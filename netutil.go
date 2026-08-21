package main

// Address normalization and routability checks.
//
// Two problems this file exists to solve, both flagged by review:
//
//  1. netip.Addr treats 1.2.3.4 and ::ffff:1.2.3.4 as different values, and
//     an address carrying an IPv6 zone ("fe80::1%eth0") is rejected outright
//     by Addr.Prefix and never matches Prefix.Contains. Mixing those forms
//     silently broke VPN prefix matching and split cache keys.
//  2. /ip/{addr} and ?ip= let a caller name any address at all. Loopback,
//     multicast, CGNAT and documentation space have no meaningful ASN and
//     should never reach a resolver.

import "net/netip"

// canonicalIP collapses an address to the single form used for every
// comparison, map key, and outbound query: IPv4-mapped v6 is unmapped, and
// any IPv6 zone is dropped. Call this once at the edge, then stop worrying.
func canonicalIP(a netip.Addr) netip.Addr {
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.Zone() != "" {
		a = a.WithZone("")
	}
	return a
}

// Reserved ranges that are valid addresses but have no public registration,
// so looking them up wastes a DNS round-trip and leaks internal topology.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking (RFC 2544)
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved / limited broadcast
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2002::/16"),       // 6to4
}

// isRoutable reports whether an address is worth spending a DNS query on:
// a globally routable unicast address that isn't in reserved space.
func isRoutable(a netip.Addr) bool {
	a = canonicalIP(a)
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() ||
		a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range reservedPrefixes {
		if p.Addr().Is4() == a.Is4() && p.Contains(a) {
			return false
		}
	}
	return true
}
