package main

// VPN / proxy / Tor detection.
//
// Strategy:
//  1. Pull official server-IP lists from VPN providers that publish them:
//     Mullvad, NordVPN, iVPN, AirVPN. Stored in an in-memory hashmap.
//  2. Pull the Tor exit list from check.torproject.org.
//  3. For everything else (ExpressVPN, Surfshark, ProtonVPN, PIA, etc.) we
//     match on ASN — these providers rent capacity from a small set of
//     hosting providers (M247, Datapacket, Tzulo, Quadranet, etc.) that
//     are unmistakably non-residential.
//
// Refresh: on startup + every 6 hours. Each source is fetched independently;
// a failure on one provider does not invalidate the others.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

type vpnVerdict struct {
	VPN          bool     `json:"vpn"`
	Tor          bool     `json:"tor,omitempty"`
	PrivacyProxy bool     `json:"privacy_proxy,omitempty"` // iCloud Private Relay etc.
	Provider     string   `json:"provider,omitempty"`
	Reasons      []string `json:"reasons,omitempty"`
	Source       string   `json:"source,omitempty"` // "ip-list" | "asn" | "asn+ip-list" | "cidr"
}

type cidrEntry struct {
	prefix   netip.Prefix
	provider string // "icloud-private-relay"
}

type vpnSnapshot struct {
	// IP → provider tag ("mullvad", "nordvpn", "ivpn", "airvpn", "tor")
	ips map[netip.Addr]string
	// CIDR ranges (iCloud Private Relay etc.) — small list, linear scan.
	cidrs []cidrEntry
	// ASN → label for known datacenter/VPN-rental ASNs.
	dcASN map[int]string
}

type vpnDB struct {
	logger *slog.Logger
	snap   atomic.Pointer[vpnSnapshot]
	client *http.Client
}

func newVPNDB(logger *slog.Logger) *vpnDB {
	d := &vpnDB{
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
	}
	// Seed with an empty snapshot so Check() before first refresh is safe.
	empty := &vpnSnapshot{
		ips:   map[netip.Addr]string{},
		dcASN: datacenterASNs(),
	}
	d.snap.Store(empty)
	return d
}

func (d *vpnDB) Loaded() bool {
	snap := d.snap.Load()
	return snap != nil && (len(snap.ips) > 0 || len(snap.cidrs) > 0)
}

// Check classifies an IP. If both ip-list and ASN match, both are reported.
func (d *vpnDB) Check(ip netip.Addr, asn asnInfo) vpnVerdict {
	v := vpnVerdict{}
	if !ip.IsValid() {
		return v
	}
	snap := d.snap.Load()

	if provider, ok := snap.ips[normalizeIP(ip)]; ok {
		v.VPN = true
		v.Provider = provider
		v.Source = "ip-list"
		v.Reasons = append(v.Reasons, "matched "+provider+" published server IP")
		if provider == "tor" {
			v.Tor = true
			v.Provider = ""
			v.Reasons = []string{"matched Tor exit relay list"}
		}
	}

	for _, c := range snap.cidrs {
		if c.prefix.Contains(normalizeIP(ip)) {
			v.VPN = true
			v.PrivacyProxy = true
			v.Provider = c.provider
			if v.Source == "" {
				v.Source = "cidr"
			} else {
				v.Source = v.Source + "+cidr"
			}
			v.Reasons = append(v.Reasons, "matched "+c.provider+" egress range "+c.prefix.String())
			break
		}
	}

	if asn.ASN != 0 {
		if label, ok := snap.dcASN[asn.ASN]; ok {
			v.VPN = true
			if v.Source == "ip-list" {
				v.Source = "asn+ip-list"
			} else {
				v.Source = "asn"
			}
			v.Reasons = append(v.Reasons, "ASN AS"+itoa(asn.ASN)+" ("+label+") is a known hosting/VPN-rental network")
		}
	}

	return v
}

// runRefreshLoop loads provider lists immediately, then re-loads every 6h.
// markLoaded is invoked after each successful refresh.
func (d *vpnDB) runRefreshLoop(ctx context.Context, markLoaded func()) {
	if err := d.refresh(ctx); err != nil {
		d.logger.Warn("initial vpn refresh", "err", err)
	} else {
		markLoaded()
	}
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := d.refresh(ctx); err != nil {
				d.logger.Warn("vpn refresh", "err", err)
			} else {
				markLoaded()
			}
		}
	}
}

func (d *vpnDB) refresh(ctx context.Context) error {
	d.logger.Info("vpn refresh starting")
	start := time.Now()
	defer func() { d.logger.Info("vpn refresh done", "dur_ms", time.Since(start).Milliseconds()) }()

	type ipResult struct {
		provider string
		ips      []netip.Addr
		err      error
	}
	type cidrResult struct {
		provider string
		prefixes []netip.Prefix
		err      error
	}

	ipJobs := []func(context.Context) ([]netip.Addr, error){
		d.fetchMullvad,
		d.fetchNordVPN,
		d.fetchIVPN,
		d.fetchAirVPN,
		d.fetchTor,
	}
	ipTags := []string{"mullvad", "nordvpn", "ivpn", "airvpn", "tor"}

	cidrJobs := []func(context.Context) ([]netip.Prefix, error){
		d.fetchICloudPrivateRelay,
	}
	cidrTags := []string{"icloud-private-relay"}

	ipCh := make(chan ipResult, len(ipJobs))
	for i, job := range ipJobs {
		i, job := i, job
		go func() {
			ips, err := job(ctx)
			ipCh <- ipResult{provider: ipTags[i], ips: ips, err: err}
		}()
	}
	cidrCh := make(chan cidrResult, len(cidrJobs))
	for i, job := range cidrJobs {
		i, job := i, job
		go func() {
			pfx, err := job(ctx)
			cidrCh <- cidrResult{provider: cidrTags[i], prefixes: pfx, err: err}
		}()
	}

	combinedIPs := make(map[netip.Addr]string, 16384)
	var combinedCIDRs []cidrEntry
	var errs []error
	totalJobs := len(ipJobs) + len(cidrJobs)
	successes := 0

	for range ipJobs {
		r := <-ipCh
		if r.err != nil {
			d.logger.Warn("vpn provider fetch", "provider", r.provider, "err", r.err)
			errs = append(errs, r.err)
			continue
		}
		d.logger.Info("vpn provider loaded", "provider", r.provider, "ips", len(r.ips))
		successes++
		for _, ip := range r.ips {
			combinedIPs[normalizeIP(ip)] = r.provider
		}
	}
	for range cidrJobs {
		r := <-cidrCh
		if r.err != nil {
			d.logger.Warn("vpn cidr fetch", "provider", r.provider, "err", r.err)
			errs = append(errs, r.err)
			continue
		}
		d.logger.Info("vpn cidr loaded", "provider", r.provider, "ranges", len(r.prefixes))
		successes++
		for _, p := range r.prefixes {
			combinedCIDRs = append(combinedCIDRs, cidrEntry{prefix: p, provider: r.provider})
		}
	}

	d.snap.Store(&vpnSnapshot{
		ips:   combinedIPs,
		cidrs: combinedCIDRs,
		dcASN: datacenterASNs(),
	})

	if successes == 0 && totalJobs > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// ---------- providers ----------

func (d *vpnDB) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ip.unt1.com/1.0 (+https://ip.unt1.com)")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, errors.New("status " + resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
}

// Mullvad: https://api.mullvad.net/www/relays/all/
// JSON array; ipv4_addr_in / ipv6_addr_in per relay.
func (d *vpnDB) fetchMullvad(ctx context.Context) ([]netip.Addr, error) {
	body, err := d.get(ctx, "https://api.mullvad.net/www/relays/all/")
	if err != nil {
		return nil, err
	}
	var relays []struct {
		IPv4 string `json:"ipv4_addr_in"`
		IPv6 string `json:"ipv6_addr_in"`
	}
	if err := json.Unmarshal(body, &relays); err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(relays)*2)
	for _, r := range relays {
		if a, err := netip.ParseAddr(r.IPv4); err == nil {
			out = append(out, a)
		}
		if a, err := netip.ParseAddr(r.IPv6); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

// NordVPN: https://api.nordvpn.com/v1/servers?limit=10000
// Each server has `station` (v4) and `ipv6_station`.
func (d *vpnDB) fetchNordVPN(ctx context.Context) ([]netip.Addr, error) {
	body, err := d.get(ctx, "https://api.nordvpn.com/v1/servers?limit=10000")
	if err != nil {
		return nil, err
	}
	var servers []struct {
		Station     string `json:"station"`
		IPv6Station string `json:"ipv6_station"`
	}
	if err := json.Unmarshal(body, &servers); err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(servers)*2)
	for _, s := range servers {
		if a, err := netip.ParseAddr(s.Station); err == nil {
			out = append(out, a)
		}
		if a, err := netip.ParseAddr(s.IPv6Station); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

// iVPN: https://api.ivpn.net/v5/servers.json
// Top-level keys: wireguard / openvpn, each with [].hosts[].host (v4)
// and optional ipv6.local_ip (we want the public host only).
func (d *vpnDB) fetchIVPN(ctx context.Context) ([]netip.Addr, error) {
	body, err := d.get(ctx, "https://api.ivpn.net/v5/servers.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Wireguard []struct {
			Hosts []struct {
				Host string `json:"host"`
			} `json:"hosts"`
		} `json:"wireguard"`
		OpenVPN []struct {
			Hosts []struct {
				Host string `json:"host"`
			} `json:"hosts"`
		} `json:"openvpn"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, g := range doc.Wireguard {
		for _, h := range g.Hosts {
			if a, err := netip.ParseAddr(h.Host); err == nil {
				out = append(out, a)
			}
		}
	}
	for _, g := range doc.OpenVPN {
		for _, h := range g.Hosts {
			if a, err := netip.ParseAddr(h.Host); err == nil {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

// AirVPN: https://airvpn.org/api/status/
// servers[].ip_v4_in1, ip_v4_in2, ip_v4_in3, ip_v4_in4 (newer schema).
func (d *vpnDB) fetchAirVPN(ctx context.Context) ([]netip.Addr, error) {
	body, err := d.get(ctx, "https://airvpn.org/api/status/")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Servers []map[string]any `json:"servers"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(doc.Servers)*2)
	for _, srv := range doc.Servers {
		for k, v := range srv {
			if !strings.HasPrefix(k, "ip_v4_in") && !strings.HasPrefix(k, "ip_v6_in") {
				continue
			}
			s, ok := v.(string)
			if !ok || s == "" {
				continue
			}
			if a, err := netip.ParseAddr(s); err == nil {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

// iCloud Private Relay: Apple publishes egress ranges as CSV.
// https://mask-api.icloud.com/egress-ip-ranges.csv
// Each line: <prefix>,<country>,<region>,<city>
// e.g. "172.225.176.0/20,US,US-NY,New York"
//
// Apple's Private Relay is structurally a privacy proxy (two-hop through
// CF/Akamai/Fastly egress), so flagging traffic from these ranges is
// genuinely correct — the IP doesn't reflect the user's real location.
func (d *vpnDB) fetchICloudPrivateRelay(ctx context.Context) ([]netip.Prefix, error) {
	body, err := d.get(ctx, "https://mask-api.icloud.com/egress-ip-ranges.csv")
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, 256)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		field := strings.SplitN(line, ",", 2)[0]
		p, err := netip.ParsePrefix(field)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// Tor: https://check.torproject.org/torbulkexitlist
// Newline-separated IPv4 list of exit relays.
func (d *vpnDB) fetchTor(ctx context.Context) ([]netip.Addr, error) {
	body, err := d.get(ctx, "https://check.torproject.org/torbulkexitlist")
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, 2048)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if a, err := netip.ParseAddr(line); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

// normalizeIP collapses 4-in-6 representations so lookups match.
func normalizeIP(a netip.Addr) netip.Addr {
	if a.Is4In6() {
		return a.Unmap()
	}
	return a
}

func itoa(n int) string {
	// Tiny local helper to avoid pulling in strconv just for this.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// datacenterASNs is a curated list of hosting/VPN-rental ASNs.
// Picked to flag the providers that don't publish server lists
// (ExpressVPN, ProtonVPN, Surfshark, PIA, CyberGhost, etc.) and the
// general "this is clearly a datacenter, not a residential ISP" case.
//
// Not exhaustive — that's a never-ending battle. Aim is high precision:
// every entry here is a network where consumer traffic has a real-world
// reason to be flagged.
func datacenterASNs() map[int]string {
	return map[int]string{
		// Top VPN-rental hosters.
		9009:   "M247",                  // hosts ExpressVPN, PIA, Surfshark, many more
		60068:  "Datacamp / CDN77",      // CyberGhost, others
		200651: "Flokinet",
		20473:  "Choopa / Vultr",
		16276:  "OVH",
		24940:  "Hetzner",
		14061:  "DigitalOcean",
		63949:  "Akamai / Linode",
		396982: "Google Cloud",
		15169:  "Google",
		8075:   "Microsoft Azure",
		16509:  "Amazon AWS",
		14618:  "Amazon AWS",
		36352:  "ColoCrossing",
		29802:  "HVC / Quadranet",
		40676:  "Psychz Networks",
		29761:  "QuadraNet Enterprises",
		46606:  "Unified Layer",
		20860:  "iomart",
		51852:  "Total Server Solutions",
		8100:   "QuadraNet Enterprises",
		63473:  "HostHatch",
		395954: "ServerMania",
		54600:  "PEG.TECH",
		201942: "GreenFloid",
		200019: "AlexHost",
		206264: "Amarutu Technology",
		211252: "Delis LLC",
		// "Definitely a datacenter, not residential" tier.
		13335: "Cloudflare",
		31898: "Oracle Cloud",
		23470: "ReliableSite",
		36351: "SoftLayer / IBM Cloud",
		// Datapacket — major VPN-rental upstream (NordVPN, ExpressVPN partner).
		212238: "Datapacket / CDN77",
	}
}
