package main

// Secondary VPN signals: rDNS hostname patterns and WHOIS netname/descr.
//
// These augment the IP-list / ASN / CIDR layers in vpn.go for the (common)
// case where an IP is a real VPN egress that no provider feed publishes,
// but identifies itself via PTR records or RIR registration text.
//
// Examples:
//   185.236.42.33 → WHOIS netname "SE-NORDVPN1" → NordVPN
//   37.19.218.145 → rDNS unn-37-19-218-145.datapacket.com → Datapacket

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"strings"
	"time"
)

// rdnsHints maps a hostname substring (lowercased) to the operator label.
// Order: most-specific brands first so a Mullvad rDNS doesn't fall through
// to a generic hosting match.
var rdnsHints = []struct {
	needle, label string
}{
	{".mullvad.net", "Mullvad"},
	{".nordvpn.com", "NordVPN"},
	{".protonvpn.net", "ProtonVPN"},
	{".surfshark.com", "Surfshark"},
	{".expressvpn.", "ExpressVPN"},
	{".privateinternetaccess.com", "Private Internet Access"},
	{".pia-vpn.", "Private Internet Access"},
	{".cyberghostvpn.com", "CyberGhost"},
	{".airvpn.org", "AirVPN"},
	{".perfect-privacy.com", "Perfect Privacy"},
	{".windscribe.com", "Windscribe"},
	{".tunnelbear.com", "TunnelBear"},
	{".hide.me", "hide.me"},
	{".torguard.", "TorGuard"},
	{".ovpn.com", "OVPN"},
	{".ipvanish.com", "IPVanish"},

	// VPN-rental hosts (no specific brand attribution possible).
	{".datapacket.com", "Datapacket (VPN-rental host)"},
	{".m247.com", "M247 (VPN-rental host)"},
	{".m247.ro", "M247 (VPN-rental host)"},
	{".cdn77.com", "CDN77 / Datacamp (VPN-rental host)"},
	{".cdn77.net", "CDN77 / Datacamp (VPN-rental host)"},
	{".datacamp.co.uk", "CDN77 / Datacamp (VPN-rental host)"},
	{".choopa.net", "Choopa / Vultr"},
	{".vultrusercontent.com", "Vultr"},
	{".internetbolaget.se", "Internetbolaget (NordVPN/OVPN host)"},
	{".packethub.", "Packethub (NordVPN host)"},
}

// whoisBrandHints scans WHOIS netname/descr/owner/remarks lines for VPN
// brand markers. Lines and needles are lowercased before comparison.
var whoisBrandHints = []struct {
	needle, label string
}{
	{"nordvpn", "NordVPN"},
	{"expressvpn", "ExpressVPN"},
	{"protonvpn", "ProtonVPN"},
	{"surfshark", "Surfshark"},
	{"cyberghost", "CyberGhost"},
	{"mullvad", "Mullvad"},
	{"private internet access", "Private Internet Access"},
	{"privateinternetaccess", "Private Internet Access"},
	{"airvpn", "AirVPN"},
	{"windscribe", "Windscribe"},
	{"perfect privacy", "Perfect Privacy"},
	{"hide.me", "hide.me"},
	{"torguard", "TorGuard"},
	{"hidemyass", "HideMyAss"},
	{"ipvanish", "IPVanish"},
	{"ovpn integritet", "OVPN"},
	{"ovpn ab", "OVPN"},
	{"packethub", "NordVPN (Packethub)"},
	{"datapacket", "Datapacket (VPN-rental host)"},
	{"m247 ltd", "M247 (VPN-rental host)"},
}

// checkRDNSHostname returns the operator label if rdns matches a known
// VPN-related substring, lowercased on entry.
func checkRDNSHostname(rdns string) (string, bool) {
	if rdns == "" {
		return "", false
	}
	r := strings.ToLower(rdns)
	for _, h := range rdnsHints {
		if strings.Contains(r, h.needle) {
			return h.label, true
		}
	}
	return "", false
}

// ---------- WHOIS ----------

type whoisCache struct {
	cache *ttlCache[string]
	// sem caps concurrent port-43 connections. RIRs rate-limit and will
	// block a host that opens many at once, and each query holds a request
	// goroutine for up to 4s.
	sem chan struct{}
}

const (
	whoisTTL         = 24 * time.Hour
	whoisErrorTTL    = 5 * time.Minute
	whoisCacheMax    = 20_000
	whoisMaxInFlight = 4
)

func newWhoisCache() *whoisCache {
	return &whoisCache{
		cache: newTTLCache[string](whoisCacheMax),
		sem:   make(chan struct{}, whoisMaxInFlight),
	}
}

// rirServer maps the Cymru-reported RIR codes to whois servers.
// "" / unknown → IANA, which will refer us to the right RIR (one extra hop).
var rirServer = map[string]string{
	"arin":    "whois.arin.net",
	"ripencc": "whois.ripe.net",
	"ripe":    "whois.ripe.net",
	"apnic":   "whois.apnic.net",
	"lacnic":  "whois.lacnic.net",
	"afrinic": "whois.afrinic.net",
}

// Lookup returns a brand label parsed from WHOIS, with a 24h cache.
//
// Keyed on the announced prefix when Cymru gave us one: WHOIS answers
// describe a network, not an address, so every address in a prefix shares
// one answer. That collapses what used to be one port-43 query per unique
// address into one per network.
//
// Negative results are cached too — clean networks shouldn't be re-queried
// on every page load — but a *failed* query gets a short TTL so a timeout
// doesn't mask a whole network for a day.
func (c *whoisCache) Lookup(ctx context.Context, ip netip.Addr, prefix, rir string) (string, bool) {
	ip = canonicalIP(ip)
	if !isRoutable(ip) {
		return "", false
	}
	rir = strings.ToLower(strings.TrimSpace(rir))
	key := prefix
	if key == "" {
		key = ip.String()
	}
	label := c.cache.Do(key+"|"+rir, func() (string, time.Duration) {
		server, ok := rirServer[rir]
		if !ok {
			server = "whois.iana.net"
		}
		select {
		case c.sem <- struct{}{}:
			defer func() { <-c.sem }()
		case <-ctx.Done():
			return "", 0
		}
		label, err := queryWhois(ctx, server, ip.String())
		if err != nil {
			return "", whoisErrorTTL
		}
		return label, whoisTTL
	})
	return label, label != ""
}

// queryWhois connects to a port-43 server, sends the address, and scans the
// response body for a known brand marker in netname/descr/owner/remarks.
// A transport failure is returned as an error so the caller can cache it
// briefly rather than as an authoritative "no brand".
func queryWhois(ctx context.Context, server, ipStr string) (string, error) {
	dctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(dctx, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	// ARIN's default output omits org details for addresses; "n + IP" gives
	// the network record. RIPE/APNIC/LACNIC/AFRINIC accept the bare address.
	query := ipStr + "\r\n"
	if strings.Contains(server, "arin") {
		query = "n + " + ipStr + "\r\n"
	}
	if _, err := conn.Write([]byte(query)); err != nil {
		return "", err
	}

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), 256*1024)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		// Restrict scanning to identity-bearing fields to avoid matching
		// boilerplate "abuse contact" templates that mention brand names.
		if !(strings.HasPrefix(line, "netname:") ||
			strings.HasPrefix(line, "descr:") ||
			strings.HasPrefix(line, "owner:") ||
			strings.HasPrefix(line, "ownerid:") ||
			strings.HasPrefix(line, "orgname:") ||
			strings.HasPrefix(line, "org-name:") ||
			strings.HasPrefix(line, "organization:") ||
			strings.HasPrefix(line, "remarks:") ||
			strings.HasPrefix(line, "customer:")) {
			continue
		}
		for _, h := range whoisBrandHints {
			if strings.Contains(line, h.needle) {
				return h.label, nil
			}
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", nil
}
