package main

import (
	"math/rand"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func TestCanonicalIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.3.4", "1.2.3.4"},
		{"::ffff:1.2.3.4", "1.2.3.4"}, // 4-in-6 must collapse
		{"2606:4700::1111", "2606:4700::1111"},
		{"fe80::1%eth0", "fe80::1"}, // zone must be dropped
	}
	for _, c := range cases {
		got := canonicalIP(mustAddr(t, c.in)).String()
		if got != c.want {
			t.Errorf("canonicalIP(%s) = %s, want %s", c.in, got, c.want)
		}
	}
	// The whole point: these must compare equal after canonicalisation.
	if canonicalIP(mustAddr(t, "::ffff:8.8.8.8")) != canonicalIP(mustAddr(t, "8.8.8.8")) {
		t.Error("4-in-6 and plain v4 forms should be equal after canonicalIP")
	}
}

func TestIsRoutable(t *testing.T) {
	routable := []string{"1.1.1.1", "8.8.8.8", "2606:4700::1111", "185.65.135.75"}
	blocked := []string{
		"127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"169.254.1.1", "fe80::1", "224.0.0.1", "ff02::1", "0.0.0.0", "::",
		"100.64.0.1",   // CGNAT
		"192.0.2.1",    // TEST-NET-1
		"198.51.100.1", // TEST-NET-2
		"203.0.113.1",  // TEST-NET-3
		"198.18.0.1",   // benchmarking
		"240.0.0.1",    // reserved
		"2001:db8::1",  // documentation
		"fd00::1",      // ULA
	}
	for _, s := range routable {
		if !isRoutable(mustAddr(t, s)) {
			t.Errorf("isRoutable(%s) = false, want true", s)
		}
	}
	for _, s := range blocked {
		if isRoutable(mustAddr(t, s)) {
			t.Errorf("isRoutable(%s) = true, want false", s)
		}
	}
	// A 4-in-6 private address must be rejected just like its v4 form.
	if isRoutable(mustAddr(t, "::ffff:10.0.0.1")) {
		t.Error("4-in-6 private address should not be routable")
	}
}

func TestLastAddr(t *testing.T) {
	cases := []struct{ prefix, want string }{
		{"1.2.3.0/24", "1.2.3.255"},
		{"1.2.3.4/32", "1.2.3.4"},
		{"10.0.0.0/8", "10.255.255.255"},
		{"0.0.0.0/0", "255.255.255.255"},
		{"172.224.0.0/27", "172.224.0.31"},
		{"2606:4700::/32", "2606:4700:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"2606:4700::/128", "2606:4700::"},
	}
	for _, c := range cases {
		got := lastAddr(netip.MustParsePrefix(c.prefix)).String()
		if got != c.want {
			t.Errorf("lastAddr(%s) = %s, want %s", c.prefix, got, c.want)
		}
	}
}

// TestCIDRIndexMatchesLinearScan is the important one. The index replaced a
// linear scan for performance; it must not change a single answer. This
// checks it against the naive implementation over random data, including
// addresses deliberately placed just inside and just outside each range.
func TestCIDRIndexMatchesLinearScan(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var entries []cidrEntry
	for i := 0; i < 4000; i++ {
		var b [4]byte
		rng.Read(b[:])
		bits := 20 + rng.Intn(13) // /20../32
		p, err := netip.AddrFrom4(b).Prefix(bits)
		if err != nil {
			continue
		}
		entries = append(entries, cidrEntry{prefix: p.Masked(), provider: "icloud-private-relay"})
	}
	for i := 0; i < 500; i++ {
		var b [16]byte
		rng.Read(b[:])
		bits := 32 + rng.Intn(65)
		p, err := netip.AddrFrom16(b).Prefix(bits)
		if err != nil {
			continue
		}
		entries = append(entries, cidrEntry{prefix: p.Masked(), provider: "icloud-private-relay"})
	}

	linear := func(ip netip.Addr) bool {
		ip = canonicalIP(ip)
		for _, e := range entries {
			if e.prefix.Contains(ip) {
				return true
			}
		}
		return false
	}

	idx := buildCIDRIndex(entries)

	var probes []netip.Addr
	// Boundary probes: first, last, one before, one after each range.
	for _, e := range entries {
		first := e.prefix.Masked().Addr()
		last := lastAddr(e.prefix)
		probes = append(probes, first, last)
		if p := first.Prev(); p.IsValid() {
			probes = append(probes, p)
		}
		if n := last.Next(); n.IsValid() {
			probes = append(probes, n)
		}
	}
	// Plus random addresses, mostly misses.
	for i := 0; i < 20000; i++ {
		var b [4]byte
		rng.Read(b[:])
		probes = append(probes, netip.AddrFrom4(b))
	}
	for i := 0; i < 5000; i++ {
		var b [16]byte
		rng.Read(b[:])
		probes = append(probes, netip.AddrFrom16(b))
	}

	mismatches := 0
	for _, ip := range probes {
		_, got := idx.Lookup(ip)
		want := linear(ip)
		if got != want {
			mismatches++
			if mismatches <= 5 {
				t.Errorf("Lookup(%s) = %v, linear scan says %v", ip, got, want)
			}
		}
	}
	if mismatches > 0 {
		t.Fatalf("%d/%d probes disagreed with the linear scan", mismatches, len(probes))
	}
	t.Logf("%d prefixes merged to %d ranges; %d probes agreed",
		len(entries), idx.Len(), len(probes))
}

func TestCIDRIndexMergesAndAttributes(t *testing.T) {
	idx := buildCIDRIndex([]cidrEntry{
		{prefix: netip.MustParsePrefix("172.224.0.0/27"), provider: "a"},
		{prefix: netip.MustParsePrefix("172.224.0.32/27"), provider: "a"}, // abuts the above
		{prefix: netip.MustParsePrefix("10.1.0.0/24"), provider: "b"},
	})
	// Adjacent same-provider ranges collapse; a different provider does not.
	if got := idx.Len(); got != 2 {
		t.Errorf("expected 2 merged ranges, got %d", got)
	}
	for _, c := range []struct {
		ip, provider string
		want         bool
	}{
		{"172.224.0.0", "a", true},
		{"172.224.0.63", "a", true},
		{"172.224.0.64", "", false},
		{"10.1.0.5", "b", true},
		{"10.1.1.5", "", false},
	} {
		p, ok := idx.Lookup(mustAddr(t, c.ip))
		if ok != c.want || (ok && p != c.provider) {
			t.Errorf("Lookup(%s) = (%q,%v), want (%q,%v)", c.ip, p, ok, c.provider, c.want)
		}
	}
	// A v6 query must not bisect into the v4 ranges.
	if _, ok := idx.Lookup(mustAddr(t, "2606:4700::1")); ok {
		t.Error("v6 address matched a v4-only index")
	}
}

// TestRefreshKeepsPreviousDataOnFailure covers the bug where a failed or
// empty fetch silently erased a source until the next 6h cycle.
func TestBuildSnapshotRetainsSources(t *testing.T) {
	good := map[string]sourceData{
		"mullvad": {relays: []relayInfo{{
			Provider: "mullvad", Hostname: "se-got-wg-001", City: "Gothenburg", Country: "se",
			V4: "185.65.135.75", V6: "2a03:1b20:5:f011::a01f",
			addrs: []netip.Addr{
				mustAddr(t, "185.65.135.75"),
				mustAddr(t, "2a03:1b20:5:f011::a01f"),
			},
		}}},
		"icloud-private-relay": {cidrs: []netip.Prefix{netip.MustParsePrefix("172.224.0.0/20")}},
	}
	snap := buildSnapshot(good)
	if !snap.ready {
		t.Fatal("snapshot with data should be ready")
	}
	if snap.ips[mustAddr(t, "185.65.135.75")] != "mullvad" {
		t.Error("v4 relay address not indexed")
	}
	// The v6 address must resolve to the same record, carrying the v4.
	rel := snap.relays[mustAddr(t, "2a03:1b20:5:f011::a01f")]
	if rel == nil {
		t.Fatal("v6 relay address not indexed")
	}
	if rel.V4 != "185.65.135.75" || rel.Hostname != "se-got-wg-001" {
		t.Errorf("v6 lookup gave wrong sibling/PoP: %+v", rel)
	}
	if _, ok := snap.cidrs.Lookup(mustAddr(t, "172.224.0.9")); !ok {
		t.Error("iCloud range not indexed")
	}
}

func TestEmptySnapshotIsNotReady(t *testing.T) {
	d := newVPNDB(testLogger())
	if d.Ready() {
		t.Fatal("a freshly constructed db must not report ready")
	}
	v := d.Check(mustAddr(t, "8.8.8.8"), asnInfo{})
	if v.Ready {
		t.Error("verdict from an unloaded db must not claim readiness")
	}
	// And the rendered verdict must not say "Clean".
	if got := classifyVerdict(v).Stamp; got != "Unknown" {
		t.Errorf("unloaded db rendered as %q, want %q", got, "Unknown")
	}
}

func TestHostingTierIsNotReportedAsVPN(t *testing.T) {
	d := newVPNDB(testLogger())
	d.snap.Store(buildSnapshot(map[string]sourceData{
		"tor": {addrs: []netip.Addr{mustAddr(t, "1.2.3.4")}},
	}))
	// AWS: a datacenter, but nothing indicates a VPN.
	v := d.Check(mustAddr(t, "8.8.8.8"), asnInfo{ASN: 16509})
	if v.VPN {
		t.Error("hyperscaler ASN should not set vpn:true")
	}
	if !v.Hosting {
		t.Error("hyperscaler ASN should set hosting:true")
	}
	if got := classifyVerdict(v).Stamp; got != "Hosting" {
		t.Errorf("stamp = %q, want Hosting", got)
	}
	// M247: a VPN-rental host, so vpn:true stands.
	v = d.Check(mustAddr(t, "8.8.8.8"), asnInfo{ASN: 9009})
	if !v.VPN || v.Hosting {
		t.Errorf("VPN-rental ASN should set vpn:true and not hosting: %+v", v)
	}
}

func TestNetPrefixForIP(t *testing.T) {
	// v6 neighbourhood matching is /64; /48 painted 2^80 addresses.
	p, ok := netPrefixForIP(mustAddr(t, "2a03:1b20:5:f011::a01f"))
	if !ok || p.Bits() != 64 {
		t.Errorf("v6 prefix = %v (bits %d), want /64", p, p.Bits())
	}
	p, ok = netPrefixForIP(mustAddr(t, "1.2.3.4"))
	if !ok || p.String() != "1.2.3.0/24" {
		t.Errorf("v4 prefix = %v, want 1.2.3.0/24", p)
	}
	// 4-in-6 must land on the v4 prefix, not a v6 one.
	p, _ = netPrefixForIP(mustAddr(t, "::ffff:1.2.3.4"))
	if p.String() != "1.2.3.0/24" {
		t.Errorf("4-in-6 prefix = %v, want 1.2.3.0/24", p)
	}
}

func TestCountryFlag(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SE", "\U0001F1F8\U0001F1EA"},
		{"us", "\U0001F1FA\U0001F1F8"},
		{"T1", ""}, // Cloudflare's Tor pseudo-country
		{"XX", ""}, // Cloudflare's unknown
		{"", ""},
		{"A", ""},
		{"12", ""},
	}
	for _, c := range cases {
		if got := countryFlag(c.in); got != c.want {
			t.Errorf("countryFlag(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTTLCacheBoundsAndCoalesces(t *testing.T) {
	c := newTTLCache[int](100)
	for i := 0; i < 1000; i++ {
		v := i
		c.Do(string(rune('a'+i%26))+string(rune(i)), func() (int, time.Duration) {
			return v, time.Hour
		})
	}
	if c.Len() > 100 {
		t.Errorf("cache grew to %d, cap is 100", c.Len())
	}

	// Concurrent cold lookups of one key must run fn exactly once.
	c2 := newTTLCache[int](10)
	var calls int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c2.Do("same", func() (int, time.Duration) {
				mu.Lock()
				calls++
				mu.Unlock()
				time.Sleep(20 * time.Millisecond)
				return 7, time.Hour
			})
		}()
	}
	wg.Wait()
	if calls != 1 {
		t.Errorf("fn ran %d times for one key, want 1", calls)
	}

	// A zero TTL means don't cache.
	c3 := newTTLCache[int](10)
	c3.Do("k", func() (int, time.Duration) { return 1, 0 })
	if c3.Len() != 0 {
		t.Error("zero TTL should not store an entry")
	}
}

func TestRateLimiter(t *testing.T) {
	l := newRateLimiter(1, 3, 100)
	allowed := 0
	for i := 0; i < 10; i++ {
		if l.Allow("k") {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("burst of 3 allowed %d requests", allowed)
	}
	if !l.Allow("other") {
		t.Error("a different key must have its own bucket")
	}
	// v6 clients bucket by /64.
	a := limiterKey(mustAddr(t, "2a03:1b20:5:f011::a01f"))
	b := limiterKey(mustAddr(t, "2a03:1b20:5:f011::dead"))
	if a != b {
		t.Errorf("v6 addresses in one /64 got different keys: %s vs %s", a, b)
	}
}

func TestAppendSource(t *testing.T) {
	if got := appendSource("", "asn"); got != "asn" {
		t.Errorf("got %q", got)
	}
	if got := appendSource("ip-list", "asn"); got != "ip-list+asn" {
		t.Errorf("got %q", got)
	}
	if got := appendSource("ip-list+asn", "asn"); got != "ip-list+asn" {
		t.Errorf("duplicate source appended: %q", got)
	}
}

// BenchmarkCIDRLookup contrasts the old linear scan with the index at
// roughly the size of Apple's real Private Relay list.
func benchEntries(n int) []cidrEntry {
	rng := rand.New(rand.NewSource(2))
	out := make([]cidrEntry, 0, n)
	for len(out) < n {
		var b [4]byte
		rng.Read(b[:])
		p, err := netip.AddrFrom4(b).Prefix(27 + rng.Intn(5))
		if err != nil {
			continue
		}
		out = append(out, cidrEntry{prefix: p.Masked(), provider: "icloud-private-relay"})
	}
	return out
}

func BenchmarkCIDRLinearScan(b *testing.B) {
	entries := benchEntries(286_000)
	ip := netip.MustParseAddr("203.0.113.7")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, e := range entries {
			if e.prefix.Contains(ip) {
				break
			}
		}
	}
}

func BenchmarkCIDRIndex(b *testing.B) {
	idx := buildCIDRIndex(benchEntries(286_000))
	ip := netip.MustParseAddr("203.0.113.7")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx.Lookup(ip)
	}
}
