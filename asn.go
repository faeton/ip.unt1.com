package main

// ASN resolution via Team Cymru's public DNS whois service.
//
// IPv4 query:  <reversed-octets>.origin.asn.cymru.com  TXT
//   1.1.1.1 → 1.1.1.1.origin.asn.cymru.com
//   answer:  "13335 | 1.1.1.0/24 | US | arin | 2010-07-14"
//
// IPv6 query:  <nibble-reversed>.origin6.asn.cymru.com TXT
//   2606:4700::1111 → e.0.6.6.4.7.0.0...origin6.asn.cymru.com
//
// Org name:    AS<num>.asn.cymru.com TXT
//   answer:    "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
//
// Cymru is the canonical free source for this. We cache aggressively since
// ASN ownership shifts on the order of weeks, not seconds — but a lookup
// that *failed* is cached only briefly. Previously any DNS blip was stored
// as an authoritative "no ASN" for 12 hours.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type asnInfo struct {
	ASN       int
	Org       string
	Prefix    string // announced prefix, e.g. "1.1.1.0/24"
	RIR       string // arin / ripencc / apnic / lacnic / afrinic
	Allocated string // YYYY-MM-DD as registered
	Country   string // RIR-registered country code (may differ from CF-IPCountry)
}

const (
	asnCacheTTL = 12 * time.Hour
	// A failed lookup is retried soon; a successful one that simply had no
	// answer still gets the long TTL.
	asnErrorTTL = 60 * time.Second
	// Entry cap. /ip/{addr} lets anyone name arbitrary addresses, so an
	// unbounded map was a memory-exhaustion lever against a 512M unit.
	asnCacheMax = 50_000
	orgCacheMax = 8_192
)

// asnResult distinguishes "we asked and got nothing" from "we couldn't ask".
type asnResult struct {
	info asnInfo
	ok   bool
}

type asnResolver struct {
	logger   *slog.Logger
	resolver *net.Resolver
	cache    *ttlCache[asnResult]
	orgs     *ttlCache[string]
}

func newASNResolver(logger *slog.Logger) *asnResolver {
	return &asnResolver{
		logger:   logger,
		resolver: net.DefaultResolver,
		cache:    newTTLCache[asnResult](asnCacheMax),
		orgs:     newTTLCache[string](orgCacheMax),
	}
}

func (a *asnResolver) Lookup(ctx context.Context, ip netip.Addr) asnInfo {
	ip = canonicalIP(ip)
	if !isRoutable(ip) {
		return asnInfo{}
	}
	res := a.cache.Do(ip.String(), func() (asnResult, time.Duration) {
		r := a.resolve(ctx, ip)
		if !r.ok {
			return r, asnErrorTTL
		}
		return r, asnCacheTTL
	})
	return res.info
}

func (a *asnResolver) resolve(ctx context.Context, ip netip.Addr) asnResult {
	lookupCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	var qname string
	if ip.Is4() {
		v4 := ip.As4()
		qname = fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	} else {
		qname = nibbleReverseV6(ip) + ".origin6.asn.cymru.com"
	}

	txts, err := a.resolver.LookupTXT(lookupCtx, qname)
	if err != nil {
		// NXDOMAIN is a real answer ("this address has no origin AS");
		// anything else is our problem and shouldn't be cached for 12h.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return asnResult{ok: true}
		}
		a.logger.Debug("cymru origin lookup failed", "ip", ip, "err", err)
		return asnResult{}
	}
	if len(txts) == 0 {
		return asnResult{ok: true}
	}
	// origin response: "ASN | prefix | country | rir | allocated"
	info := parseOriginTXT(txts[0])
	if info.ASN == 0 {
		return asnResult{ok: true}
	}
	// Org lookup gets its own budget rather than whatever is left of the
	// origin query's 1.5s, and is cached per-AS — many addresses share one.
	info.Org = a.lookupOrg(ctx, info.ASN)
	return asnResult{info: info, ok: true}
}

func (a *asnResolver) lookupOrg(ctx context.Context, asn int) string {
	return a.orgs.Do(strconv.Itoa(asn), func() (string, time.Duration) {
		lookupCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
		qname := fmt.Sprintf("AS%d.asn.cymru.com", asn)
		txts, err := a.resolver.LookupTXT(lookupCtx, qname)
		if err != nil || len(txts) == 0 {
			return "", asnErrorTTL
		}
		// org response: "ASN | country | rir | allocated | ORGNAME, CC"
		parts := strings.Split(txts[0], "|")
		if len(parts) < 5 {
			return "", asnCacheTTL
		}
		return strings.TrimSpace(parts[4]), asnCacheTTL
	})
}

func parseOriginTXT(txt string) asnInfo {
	parts := strings.Split(txt, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) < 5 {
		return asnInfo{}
	}
	asnStr := strings.SplitN(parts[0], " ", 2)[0]
	asn, err := strconv.Atoi(asnStr)
	if err != nil {
		return asnInfo{}
	}
	return asnInfo{
		ASN:       asn,
		Prefix:    parts[1],
		Country:   parts[2],
		RIR:       parts[3],
		Allocated: parts[4],
	}
}

func nibbleReverseV6(ip netip.Addr) string {
	bytes := ip.As16()
	nibbles := make([]string, 0, 32)
	for i := 15; i >= 0; i-- {
		nibbles = append(nibbles, fmt.Sprintf("%x", bytes[i]&0x0f))
		nibbles = append(nibbles, fmt.Sprintf("%x", bytes[i]>>4))
	}
	return strings.Join(nibbles, ".")
}
