// ip.unt1.com — IP echo + VPN/proxy detection.
//
// Topology: Cloudflare (orange-cloud) → Caddy on on1 → this binary on 127.0.0.1.
// Real client IP rides CF-Connecting-IP. Country rides CF-IPCountry. ASN we
// resolve ourselves via Team Cymru DNS whois (free, public, no DB).
//
// Surface:
//   GET /         text/plain IP for curl, HTML for browsers (Accept negotiation)
//   GET /json     full JSON (ip, country, asn, asorg, vpn verdict, headers subset)
//   GET /vpn      JSON: { vpn: bool, reasons: [...], provider?: "mullvad", ... }
//   GET /headers  human header dump
//   GET /all      plain-text full debug summary
//   GET /ua       User-Agent only
//   GET /reverse  reverse DNS PTR
//   GET /health   "ok"
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
	mux.HandleFunc("GET /json", srv.handleJSON)
	mux.HandleFunc("GET /vpn", srv.handleVPN)
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

// ---------- handlers ----------

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	info := s.inspect(r)
	noStore(w)

	if !wantsHTML(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, info.IPRaw)
		return
	}

	// Browser path: render the diagnostics page.
	asn := s.asn.Lookup(r.Context(), info.IP)
	verdict := s.vpn.Check(info.IP, asn)
	revName := lookupReverse(r.Context(), info.IP)

	data := struct {
		IP        string
		IPVersion   string
		Country     string
		CountryFlag string
		ASN         int
		ASOrg       string
		Reverse     string
		UA          string
		Via         string
		CFRay       string
		Colo        string
		Verdict     vpnVerdict
		Loaded      string
	}{
		IP:          info.IPRaw,
		IPVersion:   ipVersion(info.IP),
		Country:     info.Country,
		CountryFlag: countryFlag(info.Country),
		ASN:         asn.ASN,
		ASOrg:       asn.Org,
		Reverse:     revName,
		UA:          info.UA,
		Via:         info.Via,
		CFRay:       info.CFRay,
		Colo:        cfColo(info.CFRay),
		Verdict:   verdict,
		Loaded:    s.vpnLoadedAt(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := indexTpl.Execute(w, data); err != nil {
		s.logger.Error("template", "err", err)
	}
}

func (s *server) handleJSON(w http.ResponseWriter, r *http.Request) {
	info := s.inspect(r)
	asn := s.asn.Lookup(r.Context(), info.IP)
	verdict := s.vpn.Check(info.IP, asn)

	resp := map[string]any{
		"ip":        info.IPRaw,
		"version":   ipVersion(info.IP),
		"country":   info.Country,
		"asn":       asn.ASN,
		"asorg":     asn.Org,
		"reverse":   lookupReverse(r.Context(), info.IP),
		"ua":        info.UA,
		"host":      info.Host,
		"via":       info.Via,
		"ray":       info.CFRay,
		"colo":      cfColo(info.CFRay),
		"vpn":       verdict,
		"db_loaded": s.vpnLoadedAt(),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleVPN(w http.ResponseWriter, r *http.Request) {
	info := s.inspect(r)
	asn := s.asn.Lookup(r.Context(), info.IP)
	writeJSON(w, http.StatusOK, s.vpn.Check(info.IP, asn))
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
		"Referer", "Origin", "DNT", "Sec-CH-UA", "Sec-CH-UA-Platform",
	}
	for _, k := range keys {
		if v := r.Header.Get(k); v != "" {
			fmt.Fprintf(w, "%s: %s\n", k, v)
		}
	}
}

func (s *server) handleAll(w http.ResponseWriter, r *http.Request) {
	info := s.inspect(r)
	asn := s.asn.Lookup(r.Context(), info.IP)
	verdict := s.vpn.Check(info.IP, asn)
	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "ip:        %s\n", info.IPRaw)
	fmt.Fprintf(w, "version:   %s\n", ipVersion(info.IP))
	fmt.Fprintf(w, "country:   %s\n", emptyDash(info.Country))
	fmt.Fprintf(w, "asn:       AS%d\n", asn.ASN)
	fmt.Fprintf(w, "asorg:     %s\n", emptyDash(asn.Org))
	fmt.Fprintf(w, "reverse:   %s\n", emptyDash(lookupReverse(r.Context(), info.IP)))
	fmt.Fprintf(w, "ua:        %s\n", info.UA)
	fmt.Fprintf(w, "host:      %s\n", info.Host)
	fmt.Fprintf(w, "via:       %s\n", info.Via)
	if info.CFRay != "" {
		fmt.Fprintf(w, "ray:       %s\n", info.CFRay)
	}
	fmt.Fprintf(w, "vpn:       %t\n", verdict.VPN)
	if verdict.Provider != "" {
		fmt.Fprintf(w, "provider:  %s\n", verdict.Provider)
	}
	if len(verdict.Reasons) > 0 {
		fmt.Fprintf(w, "reasons:   %s\n", strings.Join(verdict.Reasons, "; "))
	}
}

func (s *server) handleUA(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, r.Header.Get("User-Agent"))
}

func (s *server) handleReverse(w http.ResponseWriter, r *http.Request) {
	info := s.inspect(r)
	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, emptyDash(lookupReverse(r.Context(), info.IP)))
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
