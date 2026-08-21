package main

// Per-client rate limiting for third-party address lookups.
//
// Self-lookups are cheap and idempotent: a client asking for its own address
// hits caches warmed by its own previous request. /ip/{addr} and ?ip= are
// different — each unique address a caller names costs a Cymru TXT query, a
// PTR, and sometimes a port-43 WHOIS. Unthrottled, one client walking the
// address space turns this service into a DNS amplifier and fills the
// caches with entries nobody will ever read again.
//
// Token bucket, keyed by requester address. Deliberately generous: a human
// pasting addresses into the lookup box never notices it.

import (
	"net/netip"
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	max     int // bucket-map cap, so the limiter isn't itself a memory lever
}

func newRateLimiter(rate, burst float64, max int) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
		max:     max,
	}
}

// Allow consumes a token for key, returning false when the bucket is empty.
func (l *rateLimiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.max {
			l.evictLocked(now)
		}
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	// Refill for elapsed time, capped at burst.
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictLocked drops buckets that have sat full (i.e. idle) long enough to be
// indistinguishable from a fresh one, then arbitrary entries if still full.
func (l *rateLimiter) evictLocked(now time.Time) {
	idle := time.Duration(l.burst/l.rate*float64(time.Second)) * 2
	for k, b := range l.buckets {
		if now.Sub(b.last) > idle {
			delete(l.buckets, k)
		}
	}
	for k := range l.buckets {
		if len(l.buckets) < l.max {
			break
		}
		delete(l.buckets, k)
	}
}

// limiterKey identifies the requester for rate-limiting purposes. IPv6
// clients are bucketed by /64 rather than by address, since a single host
// routinely has many addresses in its prefix and privacy extensions rotate
// them.
func limiterKey(ip netip.Addr) string {
	ip = canonicalIP(ip)
	if !ip.IsValid() {
		return "unknown"
	}
	if ip.Is4() {
		return ip.String()
	}
	if p, err := ip.Prefix(64); err == nil {
		return p.Masked().String()
	}
	return ip.String()
}
