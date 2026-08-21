package main

// Bounded TTL cache with request coalescing.
//
// The ASN and WHOIS caches were plain maps keyed on the address string with
// no size limit and no eviction. Because /ip/{addr} and ?ip= let an
// unauthenticated caller name any address, walking the address space grew
// those maps without bound — and every cold key fired its own DNS or port-43
// query, so a burst of identical requests multiplied the outbound load.
//
// This type fixes both: a hard entry cap with eviction, and single-flight so
// concurrent lookups of the same key share one result.

import (
	"sync"
	"time"
)

type cacheEntry[V any] struct {
	val     V
	expires time.Time
}

// call is one in-flight computation that later arrivals wait on.
type call[V any] struct {
	done chan struct{}
	val  V
}

type ttlCache[V any] struct {
	mu       sync.Mutex
	m        map[string]cacheEntry[V]
	inflight map[string]*call[V]
	max      int
}

func newTTLCache[V any](max int) *ttlCache[V] {
	return &ttlCache[V]{
		m:        make(map[string]cacheEntry[V], 1024),
		inflight: make(map[string]*call[V]),
		max:      max,
	}
}

// Get returns a live cached value, if one exists.
func (c *ttlCache[V]) Get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || !time.Now().Before(e.expires) {
		var zero V
		return zero, false
	}
	return e.val, true
}

// Do returns the cached value for key, or computes it via fn. fn returns the
// value along with the TTL to cache it for — that lets the caller give a
// transient failure a short TTL and a genuine negative answer a long one, so
// one DNS blip doesn't poison an address for hours. A zero or negative TTL
// means "don't cache this at all".
//
// Only one fn runs per key at a time; concurrent callers wait for it.
func (c *ttlCache[V]) Do(key string, fn func() (V, time.Duration)) V {
	c.mu.Lock()
	if e, ok := c.m[key]; ok && time.Now().Before(e.expires) {
		c.mu.Unlock()
		return e.val
	}
	if ch, ok := c.inflight[key]; ok {
		// Someone else is already computing this. Wait for their result
		// rather than issuing a duplicate query.
		c.mu.Unlock()
		<-ch.done
		return ch.val
	}
	ch := &call[V]{done: make(chan struct{})}
	c.inflight[key] = ch
	c.mu.Unlock()

	val, ttl := fn()

	c.mu.Lock()
	ch.val = val
	if ttl > 0 {
		c.m[key] = cacheEntry[V]{val: val, expires: time.Now().Add(ttl)}
		c.evictLocked()
	}
	delete(c.inflight, key)
	c.mu.Unlock()
	close(ch.done)
	return val
}

// evictLocked keeps the map under `max`. Expired entries go first; if that
// isn't enough we drop arbitrary entries (Go randomizes map iteration, so
// this is effectively random eviction). A true LRU would need a linked list
// for no real benefit here — every entry is equally cheap to recompute.
func (c *ttlCache[V]) evictLocked() {
	if c.max <= 0 || len(c.m) <= c.max {
		return
	}
	now := time.Now()
	for k, e := range c.m {
		if !now.Before(e.expires) {
			delete(c.m, k)
		}
	}
	for k := range c.m {
		if len(c.m) <= c.max {
			break
		}
		delete(c.m, k)
	}
}

// Len reports the current entry count (test/observability helper).
func (c *ttlCache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
