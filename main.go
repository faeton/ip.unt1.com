// ip.unt1.com — IP echo + VPN/proxy detection.
//
// Topology: Cloudflare (orange-cloud) → Caddy on de1 → this binary on 127.0.0.1.
// Real client IP rides CF-Connecting-IP. Country rides CF-IPCountry. ASN we
// resolve ourselves via Team Cymru DNS whois (free, public, no DB).
//
// Surface:
//
//	GET /             text/plain IP for curl, HTML for browsers (Accept negotiation)
//	GET /json         full JSON (ip, country, asn, asorg, vpn verdict, headers subset)
//	GET /country      text: "ip country"; JSON when Accept asks for JSON
//	GET /vpn          JSON: { vpn: bool, reasons: [...], provider?: "mullvad", ... }
//	GET /trace        Cloudflare-style key=value plain text
//	GET /headers      human header dump
//	GET /all          plain-text full debug summary
//	GET /ua           User-Agent only
//	GET /reverse      reverse DNS PTR
//	GET /health       "ok"
//	GET /ip/{addr}    same as / but for an arbitrary IP (browser HTML or curl plain)
//
// Query params:
//
//	?ip=<addr>        on /, /json, /country, /vpn, /trace, /all, /reverse — look up another IP
//	?format=yaml|hosts  on /json — alternate output formats
//	?format=json      on /country — force JSON without Accept negotiation
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
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

//go:embed web/index.html web/index-swiss.html
var webFS embed.FS

var (
	indexTpl      = template.Must(template.ParseFS(webFS, "web/index.html"))
	indexSwissTpl = template.Must(template.ParseFS(webFS, "web/index-swiss.html"))
)

// pickStyle returns the template the user wants. Query ?style=… wins over
// cookie and is also persisted, so a shared link forces that design once.
func pickStyle(w http.ResponseWriter, r *http.Request) *template.Template {
	style := ""
	if q := r.URL.Query().Get("style"); q != "" {
		style = q
	} else if c, err := r.Cookie("style"); err == nil {
		style = c.Value
	}
	switch style {
	case "swiss":
		if r.URL.Query().Get("style") != "" {
			http.SetCookie(w, &http.Cookie{Name: "style", Value: "swiss", Path: "/", MaxAge: 60 * 60 * 24 * 365, SameSite: http.SameSiteLaxMode})
		}
		return indexSwissTpl
	case "classic":
		if r.URL.Query().Get("style") != "" {
			http.SetCookie(w, &http.Cookie{Name: "style", Value: "classic", Path: "/", MaxAge: 60 * 60 * 24 * 365, SameSite: http.SameSiteLaxMode})
		}
		return indexTpl
	}
	return indexTpl
}

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
	whois  *whoisCache
	logger *slog.Logger
	// loadedAt is set when the VPN DB has its first successful refresh.
	loadedAt atomic.Pointer[time.Time]
	// UA-string dedup for journal logging — one bucket for unidentified
	// browsers (so we can adopt nicer rendering later), one for declared
	// bots/scrapers (curiosity / abuse).
	uaUnknownSeen *uaSeenSet
	uaBotSeen     *uaSeenSet
	// lookupLimit throttles third-party /ip/{addr} and ?ip= lookups only;
	// self-lookups are unmetered.
	lookupLimit *rateLimiter
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
		cfg:           cfg,
		asn:           newASNResolver(logger),
		vpn:           newVPNDB(logger),
		whois:         newWhoisCache(),
		logger:        logger,
		uaUnknownSeen: newUASeenSet(1024, 6*time.Hour),
		uaBotSeen:     newUASeenSet(1024, 6*time.Hour),
		// ~1 lookup/sec sustained, 30 back-to-back. A person pasting
		// addresses into the lookup box never reaches this.
		lookupLimit: newRateLimiter(1, 30, 20_000),
	}

	mux := http.NewServeMux()
	// "GET /{$}" matches only the root. The bare "GET /" pattern is a
	// catch-all: it made every unknown path answer 200 with the requester's
	// address, so a typo like /8.8.8.8 looked like a successful lookup.
	mux.HandleFunc("GET /{$}", srv.handleRoot)
	mux.HandleFunc("GET /ip/{addr}", srv.handleRoot)
	mux.HandleFunc("GET /json", srv.handleJSON)
	mux.HandleFunc("GET /country", srv.handleCountry)
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
	// /health is liveness and always says ok. Readiness is separate: it is
	// false until a provider list loads, which is exactly the window in
	// which every address would otherwise be reported as clean.
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !srv.vpn.Ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("vpn detection lists not loaded\n"))
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})

	httpSrv := &http.Server{
		Addr:              cfg.addr,
		Handler:           withRequestLog(logger, mux),
		MaxHeaderBytes:    32 << 10,
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
			cancel()
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
		// X-Real-IP is set by Caddy from the connecting peer, so a client
		// cannot forge it. The left-most X-Forwarded-For entry *is*
		// client-supplied — Caddy appends the real hop rather than
		// replacing the header — so it is deliberately no longer consulted.
		//
		// Note this only closes the in-process half of the problem. If
		// de1's origin address is reachable directly, a caller can still
		// present their own CF-* headers; restricting Caddy to Cloudflare
		// ranges (or requiring authenticated origin pulls) is the other half.
		if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
			info.IPRaw = v
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

	// Canonicalise once, here, so every downstream comparison, cache key and
	// outbound query sees the same form of the address.
	if addr, err := netip.ParseAddr(info.IPRaw); err == nil {
		info.IP = canonicalIP(addr)
		info.IPRaw = info.IP.String()
	}
	return info
}

// lookupError is a bad-request condition from a caller-supplied address.
type lookupError struct {
	status int
	msg    string
}

func (e *lookupError) Error() string { return e.msg }

var errRateLimited = &lookupError{status: http.StatusTooManyRequests,
	msg: "too many third-party lookups; slow down"}

// targetIP returns the address to look up, which is the requester's own
// unless overridden by the path wildcard `/ip/{addr}` or the `?ip=<addr>`
// query. The third return value flags whether this is a third-party lookup
// (so the HTML view can hide CF-Colo/Ray, which are about the requester).
//
// A malformed or unroutable override is an error rather than a silent
// fallback: quietly answering with the caller's own address when they asked
// about a different one is the kind of thing that survives into a script and
// produces confidently wrong data.
func (s *server) targetIP(r *http.Request, info requestInfo) (netip.Addr, string, bool, error) {
	override := strings.TrimSpace(r.PathValue("addr"))
	if override == "" {
		override = strings.TrimSpace(r.URL.Query().Get("ip"))
	}
	if override == "" {
		return info.IP, info.IPRaw, false, nil
	}
	addr, err := netip.ParseAddr(override)
	if err != nil {
		return netip.Addr{}, "", false, &lookupError{
			status: http.StatusBadRequest,
			msg:    "not an IP address: " + truncate(override, 64),
		}
	}
	addr = canonicalIP(addr)
	if !isRoutable(addr) {
		return netip.Addr{}, "", false, &lookupError{
			status: http.StatusBadRequest,
			msg:    addr.String() + " is not a globally routable address",
		}
	}
	isLookup := addr != info.IP
	if isLookup && !s.lookupLimit.Allow(limiterKey(info.IP)) {
		return netip.Addr{}, "", false, errRateLimited
	}
	return addr, addr.String(), isLookup, nil
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
	IP             string     `json:"ip" yaml:"ip"`
	Version        string     `json:"version" yaml:"version"`
	Country        string     `json:"country" yaml:"country"`
	ASN            int        `json:"asn" yaml:"asn"`
	ASOrg          string     `json:"asorg" yaml:"asorg"`
	Prefix         string     `json:"prefix,omitempty" yaml:"prefix,omitempty"`
	RIR            string     `json:"rir,omitempty" yaml:"rir,omitempty"`
	Allocated      string     `json:"allocated,omitempty" yaml:"allocated,omitempty"`
	Reverse        string     `json:"reverse,omitempty" yaml:"reverse,omitempty"`
	UA             string     `json:"ua,omitempty" yaml:"ua,omitempty"`
	UAPretty       string     `json:"ua_pretty,omitempty" yaml:"ua_pretty,omitempty"`
	Browser        string     `json:"browser,omitempty" yaml:"browser,omitempty"`
	BrowserVersion string     `json:"browser_version,omitempty" yaml:"browser_version,omitempty"`
	Engine         string     `json:"engine,omitempty" yaml:"engine,omitempty"`
	OS             string     `json:"os,omitempty" yaml:"os,omitempty"`
	OSVersion      string     `json:"os_version,omitempty" yaml:"os_version,omitempty"`
	Device         string     `json:"device,omitempty" yaml:"device,omitempty"`
	UAHints        bool       `json:"ua_hints,omitempty" yaml:"ua_hints,omitempty"`
	Bot            bool       `json:"bot,omitempty" yaml:"bot,omitempty"`
	BrowserSlug    string     `json:"-" yaml:"-"`
	OSSlug         string     `json:"-" yaml:"-"`
	DeviceSlug     string     `json:"-" yaml:"-"`
	Via            string     `json:"via,omitempty" yaml:"via,omitempty"`
	Ray            string     `json:"ray,omitempty" yaml:"ray,omitempty"`
	Colo           string     `json:"colo,omitempty" yaml:"colo,omitempty"`
	ColoCity       string     `json:"colo_city,omitempty" yaml:"colo_city,omitempty"`
	ColoCountry    string     `json:"colo_country,omitempty" yaml:"colo_country,omitempty"`
	VPN            vpnVerdict `json:"vpn" yaml:"vpn"`
	DBLoaded       string     `json:"db_loaded,omitempty" yaml:"db_loaded,omitempty"`
	IsLookup       bool       `json:"-" yaml:"-"`
	ReqIP          string     `json:"-" yaml:"-"`

	// CountrySource names where Country came from: "cf" (CF-IPCountry, and
	// therefore specific to the path this request took), "rir" (the RIR
	// registration for the announced prefix), or "relay" (the VPN
	// operator's own record). The IPv4 and IPv6 answers for one client
	// routinely disagree, and without this the disagreement is invisible.
	CountrySource string `json:"country_source,omitempty" yaml:"country_source,omitempty"`

	// PoP identifies the VPN exit this address belongs to, when a provider
	// feed names one. This is what reverse DNS used to supply — and what an
	// IPv6 arrival usually can't get, because most relay v6 addresses have
	// no PTR record. PoPV4/PoPV6 are the relay's own endpoints in each
	// family, which is the closest thing to a cross-family answer a single
	// hostname can give.
	PoP         string `json:"pop,omitempty" yaml:"pop,omitempty"`
	PoPCity     string `json:"pop_city,omitempty" yaml:"pop_city,omitempty"`
	PoPCountry  string `json:"pop_country,omitempty" yaml:"pop_country,omitempty"`
	PoPHost     string `json:"pop_host,omitempty" yaml:"pop_host,omitempty"`
	PoPV4       string `json:"pop_v4,omitempty" yaml:"pop_v4,omitempty"`
	PoPV6       string `json:"pop_v6,omitempty" yaml:"pop_v6,omitempty"`
	PoPProvider string `json:"pop_provider,omitempty" yaml:"pop_provider,omitempty"`
}

// OtherFamily returns the relay endpoint in the family this request did not
// arrive on, if the feed published one. Exported because the HTML templates
// call it.
func (d dataset) OtherFamily() string {
	if d.Version == "v6" {
		return d.PoPV4
	}
	return d.PoPV6
}

func (s *server) gather(r *http.Request) (dataset, error) {
	info := s.inspect(r)
	target, targetRaw, isLookup, err := s.targetIP(r, info)
	if err != nil {
		return dataset{}, err
	}
	asn := s.asn.Lookup(r.Context(), target)
	verdict := s.vpn.Check(target, asn)
	reverse := lookupReverse(r.Context(), target)
	verdict = s.vpn.Augment(r.Context(), verdict, target, asn, reverse, s.whois)

	country := info.Country
	countrySource := "cf"
	if isLookup || country == "" {
		// CF-IPCountry describes the requester, not the target, and is a
		// property of the path this request took. Fall back to the RIR
		// registration for either case.
		country, countrySource = asn.Country, "rir"
	}
	// The operator's own record beats both: it says where the exit actually
	// is, rather than where a geo database believes the address is.
	if verdict.Relay != nil && verdict.Relay.Country != "" {
		country, countrySource = strings.ToUpper(verdict.Relay.Country), "relay"
	}
	if country == "" {
		countrySource = ""
	}

	hints := parseClientHints(r)
	ua := parseUA(info.UA, hints)
	s.recordUA(info.UA, ua, hints, info.IPRaw, asn.ASN)

	colo := cfColo(info.CFRay)
	coloCityName, coloCC := coloLocation(colo)

	d := dataset{
		IP:             targetRaw,
		Version:        ipVersion(target),
		Country:        country,
		ASN:            asn.ASN,
		ASOrg:          asn.Org,
		Prefix:         asn.Prefix,
		RIR:            strings.ToLower(asn.RIR),
		Allocated:      asn.Allocated,
		Reverse:        reverse,
		UA:             info.UA,
		UAPretty:       hints.Pretty(),
		Browser:        ua.Browser,
		BrowserVersion: ua.BrowserVersion,
		Engine:         ua.Engine,
		OS:             ua.OS,
		OSVersion:      ua.OSVersion,
		Device:         ua.Device,
		UAHints:        hints.Brand != "",
		Bot:            ua.Bot,
		BrowserSlug:    ua.BrowserSlug,
		OSSlug:         ua.OSSlug,
		DeviceSlug:     ua.DeviceSlug,
		Via:            info.Via,
		Ray:            info.CFRay,
		Colo:           colo,
		ColoCity:       coloCityName,
		ColoCountry:    coloCC,
		VPN:            verdict,
		DBLoaded:       s.vpnLoadedAt(),
		IsLookup:       isLookup,
		ReqIP:          info.IPRaw,
		CountrySource:  countrySource,
	}
	if rel := verdict.Relay; rel != nil {
		d.PoP = rel.Hostname
		d.PoPCity = rel.City
		d.PoPCountry = strings.ToUpper(rel.Country)
		d.PoPHost = rel.Host
		d.PoPV4 = rel.V4
		d.PoPV6 = rel.V6
		d.PoPProvider = rel.Provider
	}
	return d, nil
}

// data runs gather and writes a proper error response if the caller asked
// about something we won't look up.
func (s *server) data(w http.ResponseWriter, r *http.Request) (dataset, bool) {
	d, err := s.gather(r)
	if err != nil {
		var le *lookupError
		if errors.As(err, &le) {
			http.Error(w, le.msg, le.status)
			return dataset{}, false
		}
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return dataset{}, false
	}
	return d, true
}

// recordUA emits a deduped journal line whenever we see a UA we couldn't
// identify or one that self-declares as automated. Both buckets share a TTL
// dedup so the same scraper hammering us doesn't flood the log. Empty UAs
// are ignored — most of the time those are health checks or our own probes.
func (s *server) recordUA(rawUA string, ua uaInfo, hints clientHints, ip string, asn int) {
	if rawUA == "" {
		return
	}
	switch {
	case ua.Bot:
		if s.uaBotSeen.firstSeen(rawUA) {
			s.logger.Info("ua_bot", "ua", rawUA, "ip", ip, "asn", asn)
		}
	case ua.Browser == "":
		if s.uaUnknownSeen.firstSeen(rawUA) {
			s.logger.Info("ua_unknown", "ua", rawUA, "ip", ip, "asn", asn,
				"hints_brand", hints.Brand, "hints_platform", hints.Platform)
		}
	}
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	d, ok := s.data(w, r)
	if !ok {
		return
	}
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
	if err := pickStyle(w, r).Execute(w, view); err != nil {
		s.logger.Error("template", "err", err)
	}
}

func (s *server) handleJSON(w http.ResponseWriter, r *http.Request) {
	d, ok := s.data(w, r)
	if !ok {
		return
	}
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

func (s *server) handleCountry(w http.ResponseWriter, r *http.Request) {
	d, ok := s.data(w, r)
	if !ok {
		return
	}
	body := struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
	}{
		IP:      d.IP,
		Country: d.Country,
	}

	if wantsJSON(r) || strings.EqualFold(r.URL.Query().Get("format"), "json") {
		writeJSON(w, http.StatusOK, body)
		return
	}

	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "%s %s\n", d.IP, emptyDash(d.Country))
}

func (s *server) handleVPN(w http.ResponseWriter, r *http.Request) {
	d, ok := s.data(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, d.VPN)
}

func (s *server) handleTrace(w http.ResponseWriter, r *http.Request) {
	d, ok := s.data(w, r)
	if !ok {
		return
	}
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
	fmt.Fprintf(w, "version=%s\n", d.Version)
	fmt.Fprintf(w, "ts=%.3f\n", float64(time.Now().UnixMilli())/1000.0)
	fmt.Fprintf(w, "visit_scheme=%s\n", scheme)
	fmt.Fprintf(w, "uag=%s\n", d.UA)
	fmt.Fprintf(w, "colo=%s\n", d.Colo)
	if d.ColoCity != "" {
		fmt.Fprintf(w, "colo_city=%s\n", d.ColoCity)
		fmt.Fprintf(w, "colo_country=%s\n", d.ColoCountry)
	}
	fmt.Fprintf(w, "country=%s\n", d.Country)
	if d.CountrySource != "" {
		fmt.Fprintf(w, "country_source=%s\n", d.CountrySource)
	}
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
	if d.PoP != "" {
		fmt.Fprintf(w, "pop=%s\n", d.PoP)
	}
	if d.PoPCity != "" {
		fmt.Fprintf(w, "pop_city=%s\n", d.PoPCity)
	}
	if d.PoPCountry != "" {
		fmt.Fprintf(w, "pop_country=%s\n", d.PoPCountry)
	}
	if d.PoPV4 != "" {
		fmt.Fprintf(w, "pop_v4=%s\n", d.PoPV4)
	}
	if d.PoPV6 != "" {
		fmt.Fprintf(w, "pop_v6=%s\n", d.PoPV6)
	}
	fmt.Fprintf(w, "via=%s\n", d.Via)
	fmt.Fprintf(w, "vpn=%s\n", onOff(d.VPN.VPN))
	fmt.Fprintf(w, "vpn_db=%s\n", readyWord(d.VPN.Ready))
	if d.VPN.Hosting {
		fmt.Fprintf(w, "hosting=on\n")
	}
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
	d, ok := s.data(w, r)
	if !ok {
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "ip:        %s\n", d.IP)
	fmt.Fprintf(w, "version:   %s\n", d.Version)
	if d.CountrySource != "" {
		fmt.Fprintf(w, "country:   %s (%s)\n", emptyDash(d.Country), d.CountrySource)
	} else {
		fmt.Fprintf(w, "country:   %s\n", emptyDash(d.Country))
	}
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
	if d.PoP != "" || d.PoPCity != "" {
		loc := d.PoPCity
		if d.PoPCountry != "" {
			if loc != "" {
				loc += ", " + d.PoPCountry
			} else {
				loc = d.PoPCountry
			}
		}
		fmt.Fprintf(w, "pop:       %s\n", strings.TrimSpace(d.PoP+" ("+loc+")"))
		if d.PoPV4 != "" {
			fmt.Fprintf(w, "pop_v4:    %s\n", d.PoPV4)
		}
		if d.PoPV6 != "" {
			fmt.Fprintf(w, "pop_v6:    %s\n", d.PoPV6)
		}
	}
	fmt.Fprintf(w, "ua:        %s\n", d.UA)
	if d.UAPretty != "" {
		fmt.Fprintf(w, "ua_pretty: %s\n", d.UAPretty)
	}
	if d.Browser != "" {
		v := d.Browser
		if d.BrowserVersion != "" {
			v += " " + d.BrowserVersion
		}
		fmt.Fprintf(w, "browser:   %s\n", v)
	}
	if d.Engine != "" {
		fmt.Fprintf(w, "engine:    %s\n", d.Engine)
	}
	if d.OS != "" {
		v := d.OS
		if d.OSVersion != "" {
			v += " " + d.OSVersion
		}
		fmt.Fprintf(w, "os:        %s\n", v)
	}
	if d.Device != "" {
		fmt.Fprintf(w, "device:    %s\n", strings.ToLower(d.Device))
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
	if d.VPN.Hosting {
		fmt.Fprintf(w, "hosting:   true\n")
	}
	if !d.VPN.Ready {
		fmt.Fprintf(w, "vpn_db:    not loaded — verdict is not authoritative\n")
	}
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
	d, ok := s.data(w, r)
	if !ok {
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, emptyDash(d.Reverse))
}

// readyWord renders the detection-database state for trace output.
func readyWord(ready bool) string {
	if ready {
		return "loaded"
	}
	return "unavailable"
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
		// Quote anything YAML might reinterpret. A double-quoted YAML
		// scalar uses the same escapes as JSON, so strconv.Quote produces a
		// valid one — and unlike the previous hand-rolled version it also
		// handles backslashes and control characters, which arrive via
		// User-Agent and PTR strings we don't control.
		if strings.ContainsAny(v, ":#@\"'\n\\{}[]&*!|>%`,") || strings.HasPrefix(v, " ") || strings.HasSuffix(v, " ") {
			v = strconv.Quote(v)
		}
		fmt.Fprintf(w, "%s: %s\n", k, v)
	}
	emit("ip", d.IP)
	emit("version", d.Version)
	emit("country", d.Country)
	emit("country_source", d.CountrySource)
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
	emit("browser", d.Browser)
	emit("browser_version", d.BrowserVersion)
	emit("engine", d.Engine)
	emit("os", d.OS)
	emit("os_version", d.OSVersion)
	emit("device", strings.ToLower(d.Device))
	emit("via", d.Via)
	emit("ray", d.Ray)
	emit("colo", d.Colo)
	emit("colo_city", d.ColoCity)
	emit("colo_country", d.ColoCountry)
	emit("pop", d.PoP)
	emit("pop_city", d.PoPCity)
	emit("pop_country", d.PoPCountry)
	emit("pop_host", d.PoPHost)
	emit("pop_v4", d.PoPV4)
	emit("pop_v6", d.PoPV6)
	emit("pop_provider", d.PoPProvider)
	fmt.Fprintf(w, "vpn:\n")
	fmt.Fprintf(w, "  vpn: %t\n", d.VPN.VPN)
	fmt.Fprintf(w, "  ready: %t\n", d.VPN.Ready)
	if d.VPN.Hosting {
		fmt.Fprintf(w, "  hosting: true\n")
	}
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

func wantsJSON(r *http.Request) bool {
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "application/json") || strings.Contains(accept, "+json")
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
	case v.PrivacyProxy:
		return verdictView{Tone: "warn", Stamp: "Private Relay", What: "iCloud Private Relay egress", Src: "apple egress cidr"}
	case v.VPN:
		name := providerLabel(v.Provider)
		if name == "" {
			name = firstNonEmpty(v.Network, "Hosting / VPN network")
		}
		return verdictView{Tone: "bad", Stamp: "VPN", What: name, Src: sourceLabel(v.Source)}
	case v.Hosting:
		// A datacenter address, but nothing says a VPN is involved. This
		// used to render as "VPN", which buried real detections under
		// ordinary cloud and CDN traffic.
		return verdictView{Tone: "warn", Stamp: "Hosting",
			What: firstNonEmpty(v.Network, "Datacenter network"),
			Src:  sourceLabel(v.Source)}
	case !v.Ready:
		// No provider list has loaded. Saying "Clean" here would be a
		// confident pass we have no basis for.
		return verdictView{Tone: "warn", Stamp: "Unknown",
			What: "Detection lists not loaded", Src: "no sources available"}
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
	}
	return k
}

func sourceLabel(s string) string {
	switch s {
	case "ip-list":
		return "matched published server IP"
	case "ip-prefix":
		return "in published VPN provider's prefix"
	case "asn":
		return "matched VPN-rental ASN"
	case "asn-hosting":
		return "matched datacenter ASN"
	case "asn+ip-list":
		return "matched server IP + datacenter ASN"
	case "cidr":
		return "matched egress CIDR"
	case "rdns":
		return "rDNS matches VPN provider"
	case "whois":
		return "WHOIS identifies VPN provider"
	}
	if strings.Contains(s, "+") {
		return "multiple sources: " + s
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
	// Cloudflare uses "T1" for Tor and "XX" for unknown. Without this guard
	// the arithmetic below wraps into unrelated code points.
	for i := 0; i < 2; i++ {
		if cc[i] < 'A' || cc[i] > 'Z' {
			return ""
		}
	}
	if cc == "XX" {
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

// Unwrap lets http.ResponseController reach the underlying writer, so
// wrapping here doesn't silently disable flushing or hijacking later.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
