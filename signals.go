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
	"sync"
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

type whoisCacheEntry struct {
	label   string
	expires time.Time
}

type whoisCache struct {
	mu sync.RWMutex
	m  map[string]whoisCacheEntry
}

func newWhoisCache() *whoisCache {
	return &whoisCache{m: make(map[string]whoisCacheEntry, 1024)}
}

const whoisTTL = 24 * time.Hour

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
// Caches negative results too — clean residential IPs don't need to be
// re-queried on every page load.
func (c *whoisCache) Lookup(ctx context.Context, ip netip.Addr, rir string) (string, bool) {
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return "", false
	}
	key := ip.String()

	c.mu.RLock()
	if e, ok := c.m[key]; ok && time.Now().Before(e.expires) {
		c.mu.RUnlock()
		return e.label, e.label != ""
	}
	c.mu.RUnlock()

	server, ok := rirServer[strings.ToLower(strings.TrimSpace(rir))]
	if !ok {
		server = "whois.iana.net"
	}
	label := queryWhois(ctx, server, ip.String())

	c.mu.Lock()
	c.m[key] = whoisCacheEntry{label: label, expires: time.Now().Add(whoisTTL)}
	c.mu.Unlock()
	return label, label != ""
}

// queryWhois connects to a port-43 server, sends the IP, and scans the
// response body for a known brand marker in netname/descr/owner/remarks.
func queryWhois(ctx context.Context, server, ipStr string) string {
	dctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(dctx, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	// ARIN's default output omits org details for IPs; "n + IP" gives the
	// network record. RIPE/APNIC/LACNIC/AFRINIC accept the bare IP.
	query := ipStr + "\r\n"
	if strings.Contains(server, "arin") {
		query = "n + " + ipStr + "\r\n"
	}
	if _, err := conn.Write([]byte(query)); err != nil {
		return ""
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
				return h.label
			}
		}
	}
	return ""
}
