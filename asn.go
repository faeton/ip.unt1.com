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
// Cymru is the canonical free source for this. We cache aggressively
// since ASN ownership shifts on the order of weeks, not seconds.

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type asnInfo struct {
	ASN int
	Org string
}

type asnEntry struct {
	info    asnInfo
	expires time.Time
}

type asnResolver struct {
	logger   *slog.Logger
	resolver *net.Resolver
	mu       sync.RWMutex
	cache    map[string]asnEntry
}

func newASNResolver(logger *slog.Logger) *asnResolver {
	return &asnResolver{
		logger:   logger,
		resolver: net.DefaultResolver,
		cache:    make(map[string]asnEntry, 1024),
	}
}

const asnCacheTTL = 12 * time.Hour

func (a *asnResolver) Lookup(ctx context.Context, ip netip.Addr) asnInfo {
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return asnInfo{}
	}
	key := ip.String()

	a.mu.RLock()
	if e, ok := a.cache[key]; ok && time.Now().Before(e.expires) {
		a.mu.RUnlock()
		return e.info
	}
	a.mu.RUnlock()

	info := a.resolve(ctx, ip)

	a.mu.Lock()
	a.cache[key] = asnEntry{info: info, expires: time.Now().Add(asnCacheTTL)}
	a.mu.Unlock()
	return info
}

func (a *asnResolver) resolve(ctx context.Context, ip netip.Addr) asnInfo {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	var qname string
	if ip.Is4() || ip.Is4In6() {
		v4 := ip.As4()
		qname = fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	} else {
		qname = nibbleReverseV6(ip) + ".origin6.asn.cymru.com"
	}

	txts, err := a.resolver.LookupTXT(ctx, qname)
	if err != nil || len(txts) == 0 {
		a.logger.Debug("cymru origin lookup failed", "ip", ip, "err", err)
		return asnInfo{}
	}
	asn := parseASNField(txts[0])
	if asn == 0 {
		return asnInfo{}
	}
	org := a.lookupOrg(ctx, asn)
	return asnInfo{ASN: asn, Org: org}
}

func (a *asnResolver) lookupOrg(ctx context.Context, asn int) string {
	qname := fmt.Sprintf("AS%d.asn.cymru.com", asn)
	txts, err := a.resolver.LookupTXT(ctx, qname)
	if err != nil || len(txts) == 0 {
		return ""
	}
	parts := strings.Split(txts[0], "|")
	if len(parts) < 5 {
		return ""
	}
	return strings.TrimSpace(parts[4])
}

// parseASNField pulls the first integer out of a TXT record like
// "13335 | 1.1.1.0/24 | US | arin | ...". When an IP is announced from
// multiple ASNs, Cymru returns them space-separated in field 0; we take
// the first.
func parseASNField(txt string) int {
	first := strings.SplitN(txt, "|", 2)[0]
	first = strings.TrimSpace(first)
	first = strings.SplitN(first, " ", 2)[0]
	n, err := strconv.Atoi(first)
	if err != nil {
		return 0
	}
	return n
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
