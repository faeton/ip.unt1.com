package main

// Sorted-range CIDR index.
//
// Apple's iCloud Private Relay egress list is ~286k /27-/31 prefixes. It was
// stored as a flat []netip.Prefix and linear-scanned on every request, which
// cost multiple milliseconds of cache-hostile work per lookup.
//
// Prefixes are converted to [first,last] address ranges, sorted, and merged
// where they touch. Lookup is then a binary search for the last range
// starting at or below the target, plus one bounds check: ~18 comparisons
// instead of 286k. Merging also shrinks the list substantially, since Apple
// publishes long runs of adjacent /29s.
//
// v4 and v6 are kept in separate slices so a lookup never compares across
// families (netip.Addr orders all v4 before all v6, which would otherwise
// make every v6 query bisect the entire v4 block first).

import (
	"encoding/binary"
	"net/netip"
	"sort"
)

type ipRange struct {
	first, last netip.Addr
	provider    string
}

type cidrIndex struct {
	v4 []ipRange
	v6 []ipRange
}

// lastAddr returns the highest address inside a prefix (its broadcast
// address, for v4). netip has no built-in for this.
func lastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	a := p.Addr()
	if a.Is4() {
		b := a.As4()
		host := 32 - p.Bits()
		var mask uint32
		if host >= 32 {
			mask = ^uint32(0)
		} else {
			mask = (uint32(1) << uint(host)) - 1
		}
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], binary.BigEndian.Uint32(b[:])|mask)
		return netip.AddrFrom4(out)
	}
	b := a.As16()
	host := 128 - p.Bits()
	for i := 15; i >= 0 && host > 0; i-- {
		n := host
		if n > 8 {
			n = 8
		}
		b[i] |= byte((1 << uint(n)) - 1)
		host -= n
	}
	return netip.AddrFrom16(b)
}

// nextAddr returns addr+1, and false if addr is already the maximum for its
// family. Used to detect ranges that abut without overlapping.
func nextAddr(a netip.Addr) (netip.Addr, bool) {
	n := a.Next()
	return n, n.IsValid()
}

// buildCIDRIndex sorts and merges entries into a searchable index. Ranges
// are only merged when they carry the same provider, so attribution survives.
func buildCIDRIndex(entries []cidrEntry) *cidrIndex {
	idx := &cidrIndex{}
	for _, e := range entries {
		p := e.prefix.Masked()
		if !p.IsValid() {
			continue
		}
		r := ipRange{first: p.Addr(), last: lastAddr(p), provider: e.provider}
		if p.Addr().Is4() {
			idx.v4 = append(idx.v4, r)
		} else {
			idx.v6 = append(idx.v6, r)
		}
	}
	idx.v4 = sortMerge(idx.v4)
	idx.v6 = sortMerge(idx.v6)
	return idx
}

func sortMerge(rs []ipRange) []ipRange {
	if len(rs) < 2 {
		return rs
	}
	sort.Slice(rs, func(i, j int) bool {
		if c := rs[i].first.Compare(rs[j].first); c != 0 {
			return c < 0
		}
		// Wider range first, so a container is merged before its contents.
		return rs[i].last.Compare(rs[j].last) > 0
	})
	out := rs[:1]
	for _, r := range rs[1:] {
		prev := &out[len(out)-1]
		if prev.provider != r.provider {
			out = append(out, r)
			continue
		}
		// Merge when r starts inside prev, or immediately after it.
		limit, ok := nextAddr(prev.last)
		if r.first.Compare(prev.last) <= 0 || (ok && r.first.Compare(limit) == 0) {
			if r.last.Compare(prev.last) > 0 {
				prev.last = r.last
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// Lookup returns the provider owning this address, if any.
func (c *cidrIndex) Lookup(ip netip.Addr) (string, bool) {
	if c == nil || !ip.IsValid() {
		return "", false
	}
	ip = canonicalIP(ip)
	rs := c.v6
	if ip.Is4() {
		rs = c.v4
	}
	if len(rs) == 0 {
		return "", false
	}
	// Last range whose start is <= ip. Ranges are disjoint and sorted, so
	// if any range contains ip, it is this one.
	i := sort.Search(len(rs), func(i int) bool {
		return rs[i].first.Compare(ip) > 0
	})
	if i == 0 {
		return "", false
	}
	r := rs[i-1]
	if ip.Compare(r.last) <= 0 {
		return r.provider, true
	}
	return "", false
}

func (c *cidrIndex) Len() int {
	if c == nil {
		return 0
	}
	return len(c.v4) + len(c.v6)
}
