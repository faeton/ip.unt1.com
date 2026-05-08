// ip.unt1.com — IP echo + VPN/proxy detection.
//
// Topology: Cloudflare (orange-cloud) → Caddy on on1 → this binary on 127.0.0.1.
// Real client IP rides CF-Connecting-IP. Country rides CF-IPCountry. ASN we
// resolve ourselves via Team Cymru DNS whois (free, public, no DB).
//
// Surface:
//   GET /             text/plain IP for curl, HTML for browsers (Accept negotiation)
//   GET /json         full JSON (ip, country, asn, asorg, vpn verdict, headers subset)
//   GET /vpn          JSON: { vpn: bool, reasons: [...], provider?: "mullvad", ... }
//   GET /trace        Cloudflare-style key=value plain text
//   GET /headers      human header dump
//   GET /all          plain-text full debug summary
//   GET /ua           User-Agent only
//   GET /reverse      reverse DNS PTR
//   GET /health       "ok"
//   GET /ip/{addr}    same as / but for an arbitrary IP (browser HTML or curl plain)
//
// Query params:
//   ?ip=<addr>        on /, /json, /vpn, /trace, /all, /reverse — look up another IP
//   ?format=yaml|hosts  on /json — alternate output formats
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

//go:embed web/index.html
var webFS embed.FS

var indexTpl = template.Must(template.ParseFS(webFS, "web/index.html"))

type config struct {
	addr           string
	trustCFHeaders bool
	disableVPN     bool
	logJSON        bool
}

type server struct {
	cfg    config
	asn    *asnResolver
	vpn    *vpnDB
	logger *slog.Logger
	// loadedAt is set when the VPN DB has its first successful refresh.
	loadedAt atomic.Pointer[time.Time]
}

func main() {
	var cfg config
	flag.StringVar(&cfg.addr, "addr", envDefault("IPUNT1_ADDR", "127.0.0.1:8080"), "listen address")
	flag.BoolVar(&cfg.trustCFHeaders, "trust-cf", envBool("IPUNT1_TRUST_CF", true), "trust CF-Connecting-IP / CF-IPCountry from upstream")
	flag.BoolVar(&cfg.disableVPN, "disable-vpn", envBool("IPUNT1_DISABLE_VPN", false), "skip fetching VPN provider lists (offline/dev)")
	flag.BoolVar(&cfg.logJSON, "log-json", envBool("IPUNT1_LOG_JSON", false), "JSON logs (default text)")
	flag.Parse()

	var handler slog.Handler
	if cfg.logJSON {
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	logger := slog.New(handler)

	srv := &server{
		cfg:    cfg,
		asn:    newASNResolver(logger),
		vpn:    newVPNDB(logger),
		logger: logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", srv.handleRoot)
	mux.HandleFunc("GET /ip/{addr}", srv.handleRoot)
	mux.HandleFunc("GET /json", srv.handleJSON)
	mux.HandleFunc("GET /vpn", srv.handleVPN)
	mux.HandleFunc("GET /trace", srv.handleTrace)
	mux.HandleFunc("GET /headers", srv.handleHeaders)
	mux.HandleFunc("GET /all", srv.handleAll)
	mux.HandleFunc("GET /ua", srv.handleUA)
	mux.HandleFunc("GET /reverse", srv.handleReverse)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})

	httpSrv := &http.Server{
		Addr:              cfg.addr,
		Handler:           withRequestLog(logger, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if !cfg.disableVPN {
		go srv.vpn.runRefreshLoop(ctx, func() {
			now := time.Now()
			srv.loadedAt.Store(&now)
		})
	}

	go func() {
		logger.Info("listening", "addr", cfg.addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

// ---------- request inspection ----------

type requestInfo struct {
	IP         netip.Addr
	IPRaw      string // exact string we resolved (may include zone for v6)
	Country    string // ISO 3166-1 alpha-2 from CF, may be empty
	UA         string
	CFRay      string
	Host       string
	Via        string // "caddy+cf" | "direct"
	RemoteAddr string // pre-trust source
}

func (s *server) inspect(r *http.Request) requestInfo {
	info := requestInfo{
		UA:         r.Header.Get("User-Agent"),
		Host:       r.Host,
		Via:        "direct",
		RemoteAddr: r.RemoteAddr,
	}

	if s.cfg.trustCFHeaders {
		if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
			info.IPRaw = v
			info.Via = "caddy+cf"
		}
		info.Country = strings.TrimSpace(r.Header.Get("CF-IPCountry"))
		info.CFRay = strings.TrimSpace(r.Header.Get("CF-Ray"))
	}
	if info.IPRaw == "" {
		// Fall back to first XFF entry, then RemoteAddr.
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			info.IPRaw = strings.TrimSpace(strings.SplitN(v, ",", 2)[0])
		}
		if info.IPRaw == "" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err == nil {
				info.IPRaw = host
			} else {
				info.IPRaw = r.RemoteAddr
			}
		}
	}

	if addr, err := netip.ParseAddr(info.IPRaw); err == nil {
		info.IP = addr
	}
	return info
}

// targetIP returns the IP to look up, which is the requester's IP unless
// overridden by the path wildcard `/ip/{addr}` or the `?ip=<addr>` query.
// The third return value flags whether the page is a third-party lookup
// (so the HTML view can hide CF-Colo/Ray which are about the requester).
func (s *server) targetIP(r *http.Request, info requestInfo) (netip.Addr, string, bool) {
	override := strings.TrimSpace(r.PathValue("addr"))
	if override == "" {
		override = strings.TrimSpace(r.URL.Query().Get("ip"))
	}
	if override == "" {
		return info.IP, info.IPRaw, false
	}
	addr, err := netip.ParseAddr(override)
	if err != nil {
		return info.IP, info.IPRaw, false
	}
	return addr, override, addr != info.IP
}

// ---------- Sec-CH-UA parsing ----------

// clientHints summarizes the Sec-CH-UA family of headers Chromium-family
// browsers send. Empty for Firefox/Safari, which don't send these.
type clientHints struct {
	Brand           string // "Google Chrome" preferred, falls back to first non-fake
	Version         string // major version, e.g. "120"
	Platform        string // "macOS" / "Windows" / "Linux" / etc. (no quotes)
	PlatformVersion string
	Mobile          bool
}

// Pretty returns "Chrome 120 on macOS 15" or "" if nothing parsed.
func (h clientHints) Pretty() string {
	if h.Brand == "" {
		return ""
	}
	short := strings.TrimPrefix(h.Brand, "Google ")
	short = strings.TrimPrefix(short, "Microsoft ")
	out := short
	if h.Version != "" {
		out += " " + h.Version
	}
	if h.Platform != "" {
		out += " on " + h.Platform
		if h.PlatformVersion != "" {
			out += " " + h.PlatformVersion
		}
	}
	if h.Mobile {
		out += " (mobile)"
	}
	return out
}

func parseClientHints(r *http.Request) clientHints {
	out := clientHints{
		Platform:        strings.Trim(r.Header.Get("Sec-CH-UA-Platform"), `"`),
		PlatformVersion: strings.Trim(r.Header.Get("Sec-CH-UA-Platform-Version"), `"`),
		Mobile:          strings.TrimSpace(r.Header.Get("Sec-CH-UA-Mobile")) == "?1",
	}
	// Trim noise: GREASE versions look like "0.0.0.0".
	if out.PlatformVersion == "0.0.0.0" {
		out.PlatformVersion = ""
	}

	// Sec-CH-UA: `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`
	// We want the most-specific brand, skipping GREASE entries and "Chromium".
	raw := r.Header.Get("Sec-CH-UA")
	if raw == "" {
		return out
	}
	type cand struct{ brand, version string }
	var cands []cand
	for _, part := range splitTopLevel(raw, ',') {
		part = strings.TrimSpace(part)
		// expect: "<brand>";v="<version>"
		segs := strings.SplitN(part, ";", 2)
		if len(segs) < 2 {
			continue
		}
		brand := strings.Trim(strings.TrimSpace(segs[0]), `"`)
		var version string
		if v := strings.TrimSpace(segs[1]); strings.HasPrefix(v, "v=") {
			version = strings.Trim(v[2:], `"`)
		}
		cands = append(cands, cand{brand, version})
	}
	pickFirst := func(want string) (string, string, bool) {
		for _, c := range cands {
			if strings.EqualFold(c.brand, want) {
				return c.brand, c.version, true
			}
		}
		return "", "", false
	}
	// Preference: Chrome / Edge / Opera / Brave / Vivaldi → then anything
	// that isn't "Chromium" or a GREASE brand (those contain `?`, `_`, or
	// are explicitly "Not...A...Brand" variants).
	for _, want := range []string{"Google Chrome", "Microsoft Edge", "Opera", "Brave", "Vivaldi", "Arc"} {
		if b, v, ok := pickFirst(want); ok {
			out.Brand, out.Version = b, v
			return out
		}
	}
	for _, c := range cands {
		l := strings.ToLower(c.brand)
		if l == "chromium" {
			continue
		}
		if strings.Contains(l, "not") && (strings.Contains(l, "brand") || strings.Contains(l, "_")) {
			continue
		}
		out.Brand, out.Version = c.brand, c.version
		return out
	}
	// All we got was Chromium — fall back to that.
	if b, v, ok := pickFirst("Chromium"); ok {
		out.Brand, out.Version = b, v
	}
	return out
}

// splitTopLevel splits on `sep` while ignoring it inside double-quoted
// substrings. Sec-CH-UA values quote the brand string, which can contain
// commas (rare) and the version with `;` separators, so we split carefully.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			depth ^= 1
		case sep:
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// ---------- handlers ----------

// dataset is what we render. Same shape across HTML/JSON/YAML/trace/all
// so output formats stay in sync.
type dataset struct {
	IP        string `json:"ip" yaml:"ip"`
	Version   string `json:"version" yaml:"version"`
	Country   string `json:"country" yaml:"country"`
	ASN       int    `json:"asn" yaml:"asn"`
	ASOrg     string `json:"asorg" yaml:"asorg"`
	Prefix    string `json:"prefix,omitempty" yaml:"prefix,omitempty"`
	RIR       string `json:"rir,omitempty" yaml:"rir,omitempty"`
	Allocated string `json:"allocated,omitempty" yaml:"allocated,omitempty"`
	Reverse   string `json:"reverse,omitempty" yaml:"reverse,omitempty"`
	UA        string `json:"ua,omitempty" yaml:"ua,omitempty"`
	UAPretty  string `json:"ua_pretty,omitempty" yaml:"ua_pretty,omitempty"`
	Via       string `json:"via,omitempty" yaml:"via,omitempty"`
	Ray       string `json:"ray,omitempty" yaml:"ray,omitempty"`
	Colo      string `json:"colo,omitempty" yaml:"colo,omitempty"`
	ColoCity    string `json:"colo_city,omitempty" yaml:"colo_city,omitempty"`
	ColoCountry string `json:"colo_country,omitempty" yaml:"colo_country,omitempty"`
	VPN       vpnVerdict `json:"vpn" yaml:"vpn"`
	DBLoaded  string `json:"db_loaded,omitempty" yaml:"db_loaded,omitempty"`
	IsLookup  bool   `json:"-" yaml:"-"`
	ReqIP     string `json:"-" yaml:"-"`
}

func (s *server) gather(r *http.Request) dataset {
	info := s.inspect(r)
	target, targetRaw, isLookup := s.targetIP(r, info)
	asn := s.asn.Lookup(r.Context(), target)
	verdict := s.vpn.Check(target, asn)

	country := info.Country
	if isLookup || country == "" {
		// CF-IPCountry is about the requester, not the target. Use RIR
		// country as a fallback for either case.
		if asn.Country != "" {
			country = asn.Country
		}
	}

	hints := parseClientHints(r)

	colo := cfColo(info.CFRay)
	coloCityName, coloCC := coloLocation(colo)

	return dataset{
		IP:        targetRaw,
		Version:   ipVersion(target),
		Country:   country,
		ASN:       asn.ASN,
		ASOrg:     asn.Org,
		Prefix:    asn.Prefix,
		RIR:       strings.ToLower(asn.RIR),
		Allocated: asn.Allocated,
		Reverse:   lookupReverse(r.Context(), target),
		UA:        info.UA,
		UAPretty:  hints.Pretty(),
		Via:       info.Via,
		Ray:         info.CFRay,
		Colo:        colo,
		ColoCity:    coloCityName,
		ColoCountry: coloCC,
		VPN:       verdict,
		DBLoaded:  s.vpnLoadedAt(),
		IsLookup:  isLookup,
		ReqIP:     info.IPRaw,
	}
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	d := s.gather(r)
	noStore(w)

	if !wantsHTML(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, d.IP)
		return
	}

	view := struct {
		dataset
		CountryFlag string
		ColoFlag    string
		Verdict     verdictView
		IPParts     []ipPart
	}{
		dataset:     d,
		CountryFlag: countryFlag(d.Country),
		ColoFlag:    countryFlag(d.ColoCountry),
		Verdict:     classifyVerdict(d.VPN),
		IPParts:     splitIPParts(d.IP),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := indexTpl.Execute(w, view); err != nil {
		s.logger.Error("template", "err", err)
	}
}

func (s *server) handleJSON(w http.ResponseWriter, r *http.Request) {
	d := s.gather(r)
	switch strings.ToLower(r.URL.Query().Get("format")) {
	case "yaml", "yml":
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		writeYAML(w, d)
	case "hosts":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		noStore(w)
		host := d.Reverse
		if host == "" {
			host = "ip.unt1.com"
		}
		fmt.Fprintf(w, "%s\t%s\n", d.IP, host)
	default:
		writeJSON(w, http.StatusOK, d)
	}
}

func (s *server) handleVPN(w http.ResponseWriter, r *http.Request) {
	d := s.gather(r)
	writeJSON(w, http.StatusOK, d.VPN)
}

func (s *server) handleTrace(w http.ResponseWriter, r *http.Request) {
	d := s.gather(r)
	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	// Cloudflare-style key=value, deterministic order.
	fmt.Fprintf(w, "fl=%s\n", d.Ray)
	fmt.Fprintf(w, "h=%s\n", r.Host)
	fmt.Fprintf(w, "ip=%s\n", d.IP)
	fmt.Fprintf(w, "ts=%.3f\n", float64(time.Now().UnixMilli())/1000.0)
	fmt.Fprintf(w, "visit_scheme=%s\n", scheme)
	fmt.Fprintf(w, "uag=%s\n", d.UA)
	fmt.Fprintf(w, "colo=%s\n", d.Colo)
	if d.ColoCity != "" {
		fmt.Fprintf(w, "colo_city=%s\n", d.ColoCity)
		fmt.Fprintf(w, "colo_country=%s\n", d.ColoCountry)
	}
	fmt.Fprintf(w, "country=%s\n", d.Country)
	fmt.Fprintf(w, "asn=AS%d\n", d.ASN)
	fmt.Fprintf(w, "asorg=%s\n", d.ASOrg)
	if d.Prefix != "" {
		fmt.Fprintf(w, "prefix=%s\n", d.Prefix)
	}
	if d.RIR != "" {
		fmt.Fprintf(w, "rir=%s\n", d.RIR)
	}
	if d.Allocated != "" {
		fmt.Fprintf(w, "allocated=%s\n", d.Allocated)
	}
	if d.Reverse != "" {
		fmt.Fprintf(w, "reverse=%s\n", d.Reverse)
	}
	fmt.Fprintf(w, "via=%s\n", d.Via)
	fmt.Fprintf(w, "vpn=%s\n", onOff(d.VPN.VPN))
	if d.VPN.Tor {
		fmt.Fprintf(w, "tor=on\n")
	}
	if d.VPN.PrivacyProxy {
		fmt.Fprintf(w, "privacy_proxy=on\n")
	}
	if d.VPN.Provider != "" {
		fmt.Fprintf(w, "provider=%s\n", d.VPN.Provider)
	}
}

func (s *server) handleHeaders(w http.ResponseWriter, r *http.Request) {
	info := s.inspect(r)
	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "%s %s %s\n", r.Method, r.URL.RequestURI(), r.Proto)
	fmt.Fprintf(w, "Host: %s\n", r.Host)
	fmt.Fprintf(w, "Remote-Addr: %s\n", info.RemoteAddr)
	keys := []string{
		"CF-Connecting-IP", "CF-IPCountry", "CF-Ray", "CF-Visitor",
		"X-Forwarded-For", "X-Forwarded-Proto", "X-Real-IP",
		"User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
		"Referer", "Origin", "DNT",
		"Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform", "Sec-CH-UA-Platform-Version",
	}
	for _, k := range keys {
		if v := r.Header.Get(k); v != "" {
			fmt.Fprintf(w, "%s: %s\n", k, v)
		}
	}
}

func (s *server) handleAll(w http.ResponseWriter, r *http.Request) {
	d := s.gather(r)
	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "ip:        %s\n", d.IP)
	fmt.Fprintf(w, "version:   %s\n", d.Version)
	fmt.Fprintf(w, "country:   %s\n", emptyDash(d.Country))
	fmt.Fprintf(w, "asn:       AS%d\n", d.ASN)
	fmt.Fprintf(w, "asorg:     %s\n", emptyDash(d.ASOrg))
	if d.Prefix != "" {
		fmt.Fprintf(w, "prefix:    %s\n", d.Prefix)
	}
	if d.RIR != "" {
		fmt.Fprintf(w, "rir:       %s\n", d.RIR)
	}
	if d.Allocated != "" {
		fmt.Fprintf(w, "allocated: %s\n", d.Allocated)
	}
	fmt.Fprintf(w, "reverse:   %s\n", emptyDash(d.Reverse))
	fmt.Fprintf(w, "ua:        %s\n", d.UA)
	if d.UAPretty != "" {
		fmt.Fprintf(w, "browser:   %s\n", d.UAPretty)
	}
	fmt.Fprintf(w, "via:       %s\n", d.Via)
	if d.Ray != "" {
		fmt.Fprintf(w, "ray:       %s\n", d.Ray)
		if d.ColoCity != "" {
			fmt.Fprintf(w, "colo:      %s (%s, %s)\n", d.Colo, d.ColoCity, d.ColoCountry)
		} else {
			fmt.Fprintf(w, "colo:      %s\n", d.Colo)
		}
	}
	fmt.Fprintf(w, "vpn:       %t\n", d.VPN.VPN)
	if d.VPN.Provider != "" {
		fmt.Fprintf(w, "provider:  %s\n", d.VPN.Provider)
	}
	if len(d.VPN.Reasons) > 0 {
		fmt.Fprintf(w, "reasons:   %s\n", strings.Join(d.VPN.Reasons, "; "))
	}
}

func (s *server) handleUA(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, r.Header.Get("User-Agent"))
}

func (s *server) handleReverse(w http.ResponseWriter, r *http.Request) {
	d := s.gather(r)
	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, emptyDash(d.Reverse))
}

// onOff returns "on" / "off" for boolean trace fields.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// writeYAML emits a tiny hand-rolled YAML for our flat-ish dataset.
// Avoids pulling in a YAML dependency for two output formats.
func writeYAML(w http.ResponseWriter, d dataset) {
	emit := func(k, v string) {
		if v == "" {
			return
		}
		// Quote if value contains characters YAML would interpret.
		if strings.ContainsAny(v, ":#@\"'\n") || strings.HasPrefix(v, " ") {
			v = `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
		}
		fmt.Fprintf(w, "%s: %s\n", k, v)
	}
	emit("ip", d.IP)
	emit("version", d.Version)
	emit("country", d.Country)
	if d.ASN != 0 {
		fmt.Fprintf(w, "asn: %d\n", d.ASN)
	}
	emit("asorg", d.ASOrg)
	emit("prefix", d.Prefix)
	emit("rir", d.RIR)
	emit("allocated", d.Allocated)
	emit("reverse", d.Reverse)
	emit("ua", d.UA)
	emit("ua_pretty", d.UAPretty)
	emit("via", d.Via)
	emit("ray", d.Ray)
	emit("colo", d.Colo)
	emit("colo_city", d.ColoCity)
	emit("colo_country", d.ColoCountry)
	fmt.Fprintf(w, "vpn:\n")
	fmt.Fprintf(w, "  vpn: %t\n", d.VPN.VPN)
	if d.VPN.Tor {
		fmt.Fprintf(w, "  tor: true\n")
	}
	if d.VPN.PrivacyProxy {
		fmt.Fprintf(w, "  privacy_proxy: true\n")
	}
	if d.VPN.Provider != "" {
		fmt.Fprintf(w, "  provider: %s\n", d.VPN.Provider)
	}
	if d.VPN.Source != "" {
		fmt.Fprintf(w, "  source: %s\n", d.VPN.Source)
	}
	if len(d.VPN.Reasons) > 0 {
		fmt.Fprintf(w, "  reasons:\n")
		for _, r := range d.VPN.Reasons {
			fmt.Fprintf(w, "    - %q\n", r)
		}
	}
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

// wantsHTML returns true when Accept includes text/html. This is the same
// browser-vs-curl rule the previous Caddy block used.
func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func ipVersion(a netip.Addr) string {
	switch {
	case !a.IsValid():
		return ""
	case a.Is4(), a.Is4In6():
		return "v4"
	default:
		return "v6"
	}
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// verdictView is the compact human-readable shape used by the HTML
// template's verdict strip. It boils the multi-flag VPN result down to
// one tone + one stamp word + a one-line "what" + a one-line source.
type verdictView struct {
	Tone  string // "good" | "warn" | "bad"
	Stamp string // "Clean" | "VPN" | "Tor" | "Private Relay" | "WARP"
	What  string
	Src   string
}

func classifyVerdict(v vpnVerdict) verdictView {
	switch {
	case v.Tor:
		return verdictView{Tone: "warn", Stamp: "Tor", What: "Tor exit relay", Src: "tor exit list"}
	case v.Provider == "cloudflare-warp":
		return verdictView{Tone: "warn", Stamp: "WARP", What: "Cloudflare WARP / 1.1.1.1", Src: "AS13335 egress"}
	case v.PrivacyProxy:
		return verdictView{Tone: "warn", Stamp: "Private Relay", What: "iCloud Private Relay egress", Src: "apple egress cidr"}
	case v.VPN:
		name := providerLabel(v.Provider)
		if name == "" {
			name = "Hosting / VPN network"
		}
		return verdictView{Tone: "bad", Stamp: "VPN", What: name, Src: sourceLabel(v.Source)}
	default:
		return verdictView{Tone: "good", Stamp: "Clean", What: "No flags raised", Src: "all sources clear"}
	}
}

func providerLabel(k string) string {
	switch k {
	case "mullvad":
		return "Mullvad"
	case "nordvpn":
		return "NordVPN"
	case "ivpn":
		return "iVPN"
	case "airvpn":
		return "AirVPN"
	case "icloud-private-relay":
		return "iCloud Private Relay"
	case "cloudflare-warp":
		return "Cloudflare WARP"
	}
	return k
}

func sourceLabel(s string) string {
	switch s {
	case "ip-list":
		return "matched published server IP"
	case "asn":
		return "matched datacenter ASN"
	case "asn+ip-list":
		return "matched server IP + datacenter ASN"
	case "cidr":
		return "matched egress CIDR"
	}
	return s
}

// ipPart is one segment of an IP address split for styled rendering:
// either a numeric octet/group ("Sep" false) or a separator ("." or ":").
type ipPart struct {
	Sep bool
	V   string
}

func splitIPParts(ip string) []ipPart {
	if ip == "" {
		return nil
	}
	sep := byte('.')
	if strings.Contains(ip, ":") {
		sep = ':'
	}
	var out []ipPart
	start := 0
	for i := 0; i < len(ip); i++ {
		if ip[i] == sep {
			out = append(out, ipPart{V: ip[start:i]})
			out = append(out, ipPart{Sep: true, V: string(sep)})
			start = i + 1
		}
	}
	out = append(out, ipPart{V: ip[start:]})
	return out
}

// cfColo extracts the airport-code suffix from a CF-Ray header
// (e.g. "9f7aa17abb769816-CDG" → "CDG"). The suffix is the IATA code
// of the Cloudflare datacenter that handled the request.
func cfColo(ray string) string {
	if i := strings.LastIndexByte(ray, '-'); i >= 0 && i+1 < len(ray) {
		code := ray[i+1:]
		if len(code) == 3 {
			return code
		}
	}
	return ""
}

// countryFlag turns ISO-3166-1 alpha-2 into a regional indicator emoji pair.
func countryFlag(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 {
		return ""
	}
	r := []rune{0x1F1E6 + rune(cc[0]-'A'), 0x1F1E6 + rune(cc[1]-'A')}
	return string(r)
}

func lookupReverse(ctx context.Context, ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func (s *server) vpnLoadedAt() string {
	t := s.loadedAt.Load()
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func withRequestLog(logger *slog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: 200}
		h.ServeHTTP(rw, r)
		logger.Info("req",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"dur_ms", time.Since(start).Milliseconds(),
			"ua", truncate(r.Header.Get("User-Agent"), 80),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
