package main

// VPN relay records.
//
// The provider feeds we already download every 6h carry far more than the
// bare addresses vpn.go used to keep. Mullvad publishes a relay hostname,
// city, country, the hosting company, and — crucially — the relay's IPv4 and
// IPv6 endpoints as one record. AirVPN does the same under different keys.
//
// Retaining that record is what lets us answer the question a single
// hostname otherwise can't. A client reaching us over IPv6 has no PTR to
// identify which exit it came out of, and CF-IPCountry may disagree with the
// IPv4 path's answer. If that IPv6 address is in a relay table, we can name
// the PoP, give the operator's own city/country instead of a geo guess, and
// point at the same relay's IPv4 endpoint.
//
// Note the framing: the paired address is *the relay's* other endpoint, not
// "your other address". They coincide for most relays but that is not
// guaranteed, and the JSON field names say pop_v4 / pop_v6 accordingly.

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
)

// relayInfo is one VPN exit, as published by its operator.
type relayInfo struct {
	Provider string `json:"provider"`           // "mullvad" | "nordvpn" | "ivpn" | "airvpn"
	Hostname string `json:"hostname,omitempty"` // "se-got-wg-001" — the PoP identity
	City     string `json:"city,omitempty"`
	Country  string `json:"country,omitempty"` // ISO-3166-1 alpha-2, lowercased by the feed
	Host     string `json:"host,omitempty"`    // hosting company running the box
	V4       string `json:"pop_v4,omitempty"`  // the relay's IPv4 endpoint
	V6       string `json:"pop_v6,omitempty"`  // the relay's IPv6 endpoint

	// addrs is every address that should resolve to this record. Kept
	// separate from V4/V6 because AirVPN publishes four of each per server.
	addrs []netip.Addr
}

// Label renders the relay for humans: "se-got-wg-001 · Gothenburg, SE".
func (r *relayInfo) Label() string {
	if r == nil {
		return ""
	}
	out := r.Hostname
	loc := r.City
	if r.Country != "" {
		cc := strings.ToUpper(r.Country)
		if loc != "" {
			loc += ", " + cc
		} else {
			loc = cc
		}
	}
	if out == "" {
		return loc
	}
	if loc != "" {
		out += " · " + loc
	}
	return out
}

// addRelayAddr records an address on the relay, keeping the first of each
// family as the representative endpoint.
func (r *relayInfo) addRelayAddr(s string) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return
	}
	a = canonicalIP(a)
	r.addrs = append(r.addrs, a)
	if a.Is4() {
		if r.V4 == "" {
			r.V4 = a.String()
		}
		return
	}
	if r.V6 == "" {
		r.V6 = a.String()
	}
}

// ---------- provider feeds ----------

// Mullvad: https://api.mullvad.net/www/relays/all/
// One object per relay, with both families and full location metadata.
func (d *vpnDB) fetchMullvad(ctx context.Context) ([]relayInfo, error) {
	body, err := d.get(ctx, "https://api.mullvad.net/www/relays/all/", 32<<20)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Hostname string `json:"hostname"`
		City     string `json:"city_name"`
		Country  string `json:"country_code"`
		Provider string `json:"provider"`
		IPv4     string `json:"ipv4_addr_in"`
		IPv6     string `json:"ipv6_addr_in"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	out := make([]relayInfo, 0, len(raw))
	for _, r := range raw {
		rel := relayInfo{
			Provider: "mullvad",
			Hostname: r.Hostname,
			City:     r.City,
			Country:  r.Country,
			Host:     r.Provider,
		}
		rel.addRelayAddr(r.IPv4)
		rel.addRelayAddr(r.IPv6)
		if len(rel.addrs) > 0 {
			out = append(out, rel)
		}
	}
	return out, nil
}

// NordVPN: https://api.nordvpn.com/v1/servers?limit=10000
// ipv6_station is present but usually empty, so pairing is rare here;
// hostname and location still identify the PoP.
func (d *vpnDB) fetchNordVPN(ctx context.Context) ([]relayInfo, error) {
	body, err := d.get(ctx, "https://api.nordvpn.com/v1/servers?limit=10000", 64<<20)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Hostname    string `json:"hostname"`
		Station     string `json:"station"`
		IPv6Station string `json:"ipv6_station"`
		Locations   []struct {
			Country struct {
				Code string `json:"code"`
				City struct {
					Name string `json:"name"`
				} `json:"city"`
			} `json:"country"`
		} `json:"locations"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	out := make([]relayInfo, 0, len(raw))
	for _, s := range raw {
		rel := relayInfo{Provider: "nordvpn", Hostname: s.Hostname}
		if len(s.Locations) > 0 {
			rel.Country = strings.ToLower(s.Locations[0].Country.Code)
			rel.City = s.Locations[0].Country.City.Name
		}
		rel.addRelayAddr(s.Station)
		rel.addRelayAddr(s.IPv6Station)
		if len(rel.addrs) > 0 {
			out = append(out, rel)
		}
	}
	return out, nil
}

// iVPN: https://api.ivpn.net/v5/servers.json
// Public egress is IPv4-only; the ipv6 block in each host is the tunnel's
// internal range, not a public address, so it is deliberately ignored.
func (d *vpnDB) fetchIVPN(ctx context.Context) ([]relayInfo, error) {
	body, err := d.get(ctx, "https://api.ivpn.net/v5/servers.json", 16<<20)
	if err != nil {
		return nil, err
	}
	type group struct {
		City    string `json:"city"`
		Country string `json:"country_code"`
		ISP     string `json:"isp"`
		Hosts   []struct {
			Hostname string `json:"hostname"`
			Host     string `json:"host"`
			ISP      string `json:"isp"`
		} `json:"hosts"`
	}
	var doc struct {
		Wireguard []group `json:"wireguard"`
		OpenVPN   []group `json:"openvpn"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []relayInfo
	for _, groups := range [][]group{doc.Wireguard, doc.OpenVPN} {
		for _, g := range groups {
			for _, h := range g.Hosts {
				rel := relayInfo{
					Provider: "ivpn",
					Hostname: h.Hostname,
					City:     g.City,
					Country:  strings.ToLower(g.Country),
					Host:     firstNonEmpty(h.ISP, g.ISP),
				}
				rel.addRelayAddr(h.Host)
				if len(rel.addrs) > 0 {
					out = append(out, rel)
				}
			}
		}
	}
	return out, nil
}

// AirVPN: https://airvpn.org/api/status/
// Each named server exposes up to four IPv4 and four IPv6 entry addresses;
// all of them belong to the same PoP.
func (d *vpnDB) fetchAirVPN(ctx context.Context) ([]relayInfo, error) {
	body, err := d.get(ctx, "https://airvpn.org/api/status/", 16<<20)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Servers []struct {
			Name    string `json:"public_name"`
			Country string `json:"country_code"`
			City    string `json:"location"`
			V4In1   string `json:"ip_v4_in1"`
			V4In2   string `json:"ip_v4_in2"`
			V4In3   string `json:"ip_v4_in3"`
			V4In4   string `json:"ip_v4_in4"`
			V6In1   string `json:"ip_v6_in1"`
			V6In2   string `json:"ip_v6_in2"`
			V6In3   string `json:"ip_v6_in3"`
			V6In4   string `json:"ip_v6_in4"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]relayInfo, 0, len(doc.Servers))
	for _, s := range doc.Servers {
		rel := relayInfo{
			Provider: "airvpn",
			Hostname: s.Name,
			City:     s.City,
			Country:  strings.ToLower(s.Country),
		}
		for _, a := range []string{s.V4In1, s.V4In2, s.V4In3, s.V4In4} {
			rel.addRelayAddr(a)
		}
		for _, a := range []string{s.V6In1, s.V6In2, s.V6In3, s.V6In4} {
			rel.addRelayAddr(a)
		}
		if len(rel.addrs) > 0 {
			out = append(out, rel)
		}
	}
	return out, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
