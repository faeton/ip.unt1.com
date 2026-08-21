package main

// VPN / proxy / Tor detection.
//
// Strategy:
//  1. Pull official server lists from VPN providers that publish them:
//     Mullvad, NordVPN, iVPN, AirVPN. Full relay records are retained (see
//     relay.go), not just addresses.
//  2. Pull the Tor exit list from check.torproject.org.
//  3. Pull iCloud Private Relay's published egress CIDRs.
//  4. For everything else (ExpressVPN, Surfshark, ProtonVPN, PIA, etc.) we
//     match on ASN — these providers rent capacity from a small set of
//     hosting providers (M247, Datapacket, Tzulo, Quadranet, etc.) that are
//     unmistakably non-residential.
//
// ASNs are split into two tiers. A VPN-rental host means "a VPN probably
// egresses here"; a hyperscaler means "this is a datacenter" and nothing
// more. Reporting an AWS or Cloudflare address as vpn:true drowned real VPN
// hits in noise, so those now report hosting:true with vpn:false.
//
// Refresh: on startup + every 6 hours. Each source is fetched and validated
// independently, and — importantly — a source that fails keeps its previous
// data instead of vanishing from the snapshot until the next cycle.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type vpnVerdict struct {
	VPN          bool       `json:"vpn"`
	Hosting      bool       `json:"hosting,omitempty"` // datacenter, but not identified as a VPN
	Tor          bool       `json:"tor,omitempty"`
	PrivacyProxy bool       `json:"privacy_proxy,omitempty"` // iCloud Private Relay etc.
	Provider     string     `json:"provider,omitempty"`
	Network      string     `json:"network,omitempty"` // hosting/rental operator behind the ASN
	Relay        *relayInfo `json:"relay,omitempty"`   // exact PoP, when the feed names one
	Reasons      []string   `json:"reasons,omitempty"`
	Source       string     `json:"source,omitempty"` // "ip-list" | "asn" | "asn+ip-list" | "cidr"
	// Ready is false when no provider list has loaded yet. Without it a
	// cold or offline process reports every address as clean, which reads
	// as an authoritative pass rather than "we don't know".
	Ready bool `json:"ready"`
}

type cidrEntry struct {
	prefix   netip.Prefix
	provider string // "icloud-private-relay"
}

// sourceData is one feed's last-known-good payload. Kept per source so a
// failed fetch degrades that source only, and only until it recovers.
type sourceData struct {
	relays  []relayInfo
	addrs   []netip.Addr
	cidrs   []netip.Prefix
	fetched time.Time
}

func (s sourceData) empty() bool {
	return len(s.relays) == 0 && len(s.addrs) == 0 && len(s.cidrs) == 0
}

type vpnSnapshot struct {
	// sources holds each feed's raw last-known-good data. Indexes below
	// are derived from it on every rebuild.
	sources map[string]sourceData

	// ips maps an address to its provider tag.
	ips map[netip.Addr]string
	// relays maps an address to the relay record that published it. This
	// is what lets an IPv6 arrival name its PoP and the relay's IPv4.
	relays map[netip.Addr]*relayInfo
	// ipNets maps a /24 (v4) or /64 (v6) to a provider tag, derived from
	// ips. Catches egress addresses sitting next to a published connect
	// address — common for NordVPN. Tor is deliberately excluded;
	// neighbours of a Tor exit are not themselves exits.
	ipNets map[netip.Prefix]string
	// cidrs is the sorted-range index over published egress ranges.
	cidrs *cidrIndex
	ready bool
}

// netPrefixForIP returns /24 for v4, /64 for v6 — the granularity at which
// operators typically receive contiguous allocations. The previous /48 was
// far too wide: one relay painted 2^80 neighbouring addresses as that
// provider.
func netPrefixForIP(ip netip.Addr) (netip.Prefix, bool) {
	ip = canonicalIP(ip)
	bits := 24
	if ip.Is6() {
		bits = 64
	}
	pfx, err := ip.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	return pfx.Masked(), true
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
	// Seed with an empty, explicitly not-ready snapshot so Check() before
	// the first refresh is safe and honest about knowing nothing.
	d.snap.Store(&vpnSnapshot{
		sources: map[string]sourceData{},
		ips:     map[netip.Addr]string{},
		relays:  map[netip.Addr]*relayInfo{},
		ipNets:  map[netip.Prefix]string{},
		cidrs:   &cidrIndex{},
	})
	return d
}

// Ready reports whether at least one provider feed has loaded.
func (d *vpnDB) Ready() bool {
	snap := d.snap.Load()
	return snap != nil && snap.ready
}

// Check classifies an address. If both ip-list and ASN match, both are
// reported.
func (d *vpnDB) Check(ip netip.Addr, asn asnInfo) vpnVerdict {
	snap := d.snap.Load()
	v := vpnVerdict{Ready: snap.ready}
	if !ip.IsValid() {
		return v
	}
	ip = canonicalIP(ip)

	exact := false
	if provider, ok := snap.ips[ip]; ok {
		exact = true
		v.VPN = true
		v.Provider = provider
		v.Source = "ip-list"
		v.Reasons = append(v.Reasons, "matched "+provider+" published server IP")
		if rel, ok := snap.relays[ip]; ok {
			v.Relay = rel
			v.Reasons = append(v.Reasons, "relay "+rel.Label())
		}
		if provider == "tor" {
			v.Tor = true
			v.Provider = ""
			v.Relay = nil
			v.Reasons = []string{"matched Tor exit relay list"}
		}
	} else if pfx, ok := netPrefixForIP(ip); ok {
		// No exact hit — try the /24 (or /64) neighbourhood. Many VPN
		// operators publish connect addresses while egressing from
		// adjacent ones in the same allocation.
		if provider, hit := snap.ipNets[pfx]; hit && provider != "multi" {
			v.VPN = true
			v.Provider = provider
			v.Source = "ip-prefix"
			v.Reasons = append(v.Reasons, "in published "+provider+" prefix "+pfx.String())
		}
	}

	// Published egress ranges (iCloud Private Relay). Skipped when an exact
	// server-list hit already classified the address — the lists are
	// disjoint in practice and this is the expensive probe.
	if !exact {
		if provider, ok := snap.cidrs.Lookup(ip); ok {
			v.VPN = true
			v.PrivacyProxy = true
			v.Provider = provider
			v.Source = appendSource(v.Source, "cidr")
			v.Reasons = append(v.Reasons, "matched "+provider+" published egress range")
		}
	}

	if asn.ASN != 0 {
		if tier, ok := datacenterASN(asn.ASN); ok {
			v.Network = tier.label
			if tier.rental {
				v.VPN = true
				v.Source = appendSource(v.Source, "asn")
				v.Reasons = append(v.Reasons,
					"ASN AS"+strconv.Itoa(asn.ASN)+" ("+tier.label+") is a known hosting/VPN-rental network")
			} else {
				v.Hosting = true
				v.Source = appendSource(v.Source, "asn-hosting")
				v.Reasons = append(v.Reasons,
					"ASN AS"+strconv.Itoa(asn.ASN)+" ("+tier.label+") is a datacenter network, not a residential ISP")
			}
		}
	}

	return v
}

// Augment layers rDNS and WHOIS signals onto an existing verdict. rDNS is
// free (the lookup already happened in the request path) and runs always.
//
// WHOIS is gated hard. It used to fire whenever the ASN layer flagged an
// address without naming a brand — but the ASN list includes AWS, Google
// and Cloudflare, so every unique cloud address triggered a 4s port-43
// query. That is both a latency cliff and a good way to get the host
// blocked by a RIR. It now runs only for VPN-rental ASNs, where the answer
// is actually likely to name a VPN.
func (d *vpnDB) Augment(ctx context.Context, v vpnVerdict, ip netip.Addr, asn asnInfo, rdns string, wc *whoisCache) vpnVerdict {
	if v.Tor || v.PrivacyProxy {
		return v
	}
	if label, ok := checkRDNSHostname(rdns); ok {
		v.VPN = true
		if v.Provider == "" {
			v.Provider = label
		}
		v.Source = appendSource(v.Source, "rdns")
		v.Reasons = append(v.Reasons, "rDNS "+rdns+" matches "+label)
	}
	if wc == nil || v.Provider != "" || asn.ASN == 0 {
		return v
	}
	tier, known := datacenterASN(asn.ASN)
	if !known || !tier.rental {
		return v
	}
	if label, ok := wc.Lookup(ctx, ip, asn.Prefix, asn.RIR); ok {
		v.Provider = label
		v.VPN = true
		v.Source = appendSource(v.Source, "whois")
		v.Reasons = append(v.Reasons, "WHOIS identifies "+label)
	}
	return v
}

// LookupRelay returns the relay record publishing this address, if any.
func (d *vpnDB) LookupRelay(ip netip.Addr) *relayInfo {
	snap := d.snap.Load()
	if snap == nil {
		return nil
	}
	return snap.relays[canonicalIP(ip)]
}

func appendSource(s, more string) string {
	if s == "" {
		return more
	}
	for _, p := range strings.Split(s, "+") {
		if p == more {
			return s
		}
	}
	return s + "+" + more
}

// ---------- refresh ----------

// runRefreshLoop loads provider lists immediately, then re-loads every 6h.
// markLoaded is invoked after each refresh that leaves us with usable data.
func (d *vpnDB) runRefreshLoop(ctx context.Context, markLoaded func()) {
	if err := d.refresh(ctx); err != nil {
		d.logger.Warn("initial vpn refresh", "err", err)
	}
	if d.Ready() {
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
			}
			if d.Ready() {
				markLoaded()
			}
		}
	}
}

type fetchResult struct {
	name string
	data sourceData
	err  error
}

func (d *vpnDB) refresh(ctx context.Context) error {
	d.logger.Info("vpn refresh starting")
	start := time.Now()

	relayJobs := map[string]func(context.Context) ([]relayInfo, error){
		"mullvad": d.fetchMullvad,
		"nordvpn": d.fetchNordVPN,
		"ivpn":    d.fetchIVPN,
		"airvpn":  d.fetchAirVPN,
	}
	addrJobs := map[string]func(context.Context) ([]netip.Addr, error){
		"tor": d.fetchTor,
	}
	cidrJobs := map[string]func(context.Context) ([]netip.Prefix, error){
		"icloud-private-relay": d.fetchICloudPrivateRelay,
	}

	total := len(relayJobs) + len(addrJobs) + len(cidrJobs)
	ch := make(chan fetchResult, total)
	var wg sync.WaitGroup

	for name, job := range relayJobs {
		wg.Add(1)
		go func(name string, job func(context.Context) ([]relayInfo, error)) {
			defer wg.Done()
			rs, err := job(ctx)
			ch <- fetchResult{name: name, data: sourceData{relays: rs}, err: err}
		}(name, job)
	}
	for name, job := range addrJobs {
		wg.Add(1)
		go func(name string, job func(context.Context) ([]netip.Addr, error)) {
			defer wg.Done()
			as, err := job(ctx)
			ch <- fetchResult{name: name, data: sourceData{addrs: as}, err: err}
		}(name, job)
	}
	for name, job := range cidrJobs {
		wg.Add(1)
		go func(name string, job func(context.Context) ([]netip.Prefix, error)) {
			defer wg.Done()
			ps, err := job(ctx)
			ch <- fetchResult{name: name, data: sourceData{cidrs: ps}, err: err}
		}(name, job)
	}
	wg.Wait()
	close(ch)

	prev := d.snap.Load()
	sources := make(map[string]sourceData, total)
	for k, v := range prev.sources {
		sources[k] = v
	}

	var errs []error
	fresh := 0
	for r := range ch {
		switch {
		case r.err != nil:
			d.logger.Warn("vpn source fetch failed, keeping previous data",
				"source", r.name, "err", r.err, "had_previous", !sources[r.name].empty())
			errs = append(errs, r.err)
		case r.data.empty():
			// A syntactically valid but empty payload is a feed outage, not
			// "this provider has no servers". Treat it as a failure so we
			// don't erase good data on a 200-with-[] response.
			d.logger.Warn("vpn source returned no entries, keeping previous data", "source", r.name)
			errs = append(errs, errors.New(r.name+": empty payload"))
		default:
			r.data.fetched = time.Now()
			sources[r.name] = r.data
			fresh++
			d.logger.Info("vpn source loaded", "source", r.name,
				"relays", len(r.data.relays), "addrs", len(r.data.addrs), "cidrs", len(r.data.cidrs))
		}
	}

	snap := buildSnapshot(sources)
	d.snap.Store(snap)
	d.logger.Info("vpn refresh done",
		"dur_ms", time.Since(start).Milliseconds(),
		"fresh_sources", fresh, "total_sources", total,
		"ips", len(snap.ips), "relays", len(snap.relays),
		"cidr_ranges", snap.cidrs.Len(), "ready", snap.ready)

	if fresh == 0 && total > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// buildSnapshot derives every lookup index from the per-source data.
func buildSnapshot(sources map[string]sourceData) *vpnSnapshot {
	snap := &vpnSnapshot{
		sources: sources,
		ips:     make(map[netip.Addr]string, 16384),
		relays:  make(map[netip.Addr]*relayInfo, 16384),
		ipNets:  make(map[netip.Prefix]string, 16384),
	}
	var cidrs []cidrEntry

	// Iterate in a fixed order so that an address appearing in two feeds
	// always resolves the same way across restarts. Map order would make
	// the winner depend on nothing in particular.
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		src := sources[name]
		for i := range src.relays {
			rel := &src.relays[i]
			for _, a := range rel.addrs {
				snap.ips[a] = rel.Provider
				snap.relays[a] = rel
			}
		}
		for _, p := range src.cidrs {
			cidrs = append(cidrs, cidrEntry{prefix: p, provider: name})
		}
		if !src.empty() {
			snap.ready = true
		}
	}
	// Tor last and unconditionally: an address that is a Tor exit is a Tor
	// exit even if some VPN feed also lists it, and Check() treats the two
	// very differently.
	for _, name := range names {
		for _, a := range sources[name].addrs {
			a = canonicalIP(a)
			snap.ips[a] = name
			delete(snap.relays, a)
		}
	}

	// Derive the neighbourhood map. Skip Tor. If two providers share a
	// prefix, mark "multi" so Check() ignores it rather than guessing.
	for ip, prov := range snap.ips {
		if prov == "tor" {
			continue
		}
		pfx, ok := netPrefixForIP(ip)
		if !ok {
			continue
		}
		if existing, present := snap.ipNets[pfx]; present && existing != prov {
			snap.ipNets[pfx] = "multi"
		} else if !present {
			snap.ipNets[pfx] = prov
		}
	}

	snap.cidrs = buildCIDRIndex(cidrs)
	return snap
}

// ---------- feed transport ----------

func (d *vpnDB) get(ctx context.Context, url string, limit int64) ([]byte, error) {
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
	// Read one byte past the limit so an oversized body is reported rather
	// than silently truncated into a parse error.
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("response exceeds " + strconv.FormatInt(limit, 10) + " byte limit")
	}
	return body, nil
}

// iCloud Private Relay: Apple publishes egress ranges as CSV.
// https://mask-api.icloud.com/egress-ip-ranges.csv
// Each line: <prefix>,<country>,<region>,<city>
//
// Private Relay is structurally a privacy proxy (two-hop through
// CF/Akamai/Fastly egress), so flagging traffic from these ranges is
// genuinely correct — the address doesn't reflect the user's real location.
func (d *vpnDB) fetchICloudPrivateRelay(ctx context.Context) ([]netip.Prefix, error) {
	body, err := d.get(ctx, "https://mask-api.icloud.com/egress-ip-ranges.csv", 32<<20)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, 300_000)
	for len(body) > 0 {
		var line []byte
		if i := indexByte(body, '\n'); i >= 0 {
			line, body = body[:i], body[i+1:]
		} else {
			line, body = body, nil
		}
		s := strings.TrimSpace(string(line))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if i := strings.IndexByte(s, ','); i >= 0 {
			s = s[:i]
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// Tor: https://check.torproject.org/torbulkexitlist
// Newline-separated list of exit relays.
func (d *vpnDB) fetchTor(ctx context.Context) ([]netip.Addr, error) {
	body, err := d.get(ctx, "https://check.torproject.org/torbulkexitlist", 8<<20)
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

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// ---------- datacenter ASNs ----------

// asnTier describes what an ASN match actually tells us. rental means VPN
// operators are known to egress there, so vpn:true and a WHOIS probe are
// both justified. Otherwise it is simply a datacenter: hosting:true, and no
// claim that a VPN is involved.
type asnTier struct {
	label  string
	rental bool
}

// datacenterASNs is a curated list of hosting / VPN-rental ASNs, built once.
// Not exhaustive — that's a never-ending battle. Aim is high precision.
var datacenterASNs = func() map[int]asnTier {
	rental := map[int]string{
		9009:   "M247", // hosts ExpressVPN, PIA, Surfshark, many more
		60068:  "Datacamp / CDN77",
		200651: "Flokinet",
		20473:  "Choopa / Vultr",
		16276:  "OVH",
		24940:  "Hetzner",
		14061:  "DigitalOcean",
		63949:  "Akamai / Linode",
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
		23470:  "ReliableSite",
		212238: "Datapacket / CDN77",          // major VPN-rental upstream
		51747:  "Internetbolaget / Packethub", // NordVPN, OVPN (SE)
		44477:  "Stark Industries",
		6206:   "Netrouting",   // AirVPN egress
		137409: "GSL Networks", // Packethub-assigned NordVPN ranges (AU)
	}
	// Datacenters, but not places VPNs characteristically egress. Calling
	// these vpn:true buried real detections under cloud and CDN traffic.
	hosting := map[int]string{
		396982: "Google Cloud",
		15169:  "Google",
		8075:   "Microsoft Azure",
		16509:  "Amazon AWS",
		14618:  "Amazon AWS",
		13335:  "Cloudflare",
		31898:  "Oracle Cloud",
		36351:  "SoftLayer / IBM Cloud",
	}
	out := make(map[int]asnTier, len(rental)+len(hosting))
	for asn, label := range rental {
		out[asn] = asnTier{label: label, rental: true}
	}
	for asn, label := range hosting {
		out[asn] = asnTier{label: label}
	}
	return out
}()

func datacenterASN(asn int) (asnTier, bool) {
	t, ok := datacenterASNs[asn]
	return t, ok
}
