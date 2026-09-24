// SPDX-License-Identifier: Apache-2.0

// Package ratelimit provides keyed token-bucket limiters with bounded memory,
// used per client network and per principal (security-standards §12).
package ratelimit

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Keyed is a set of token buckets, one per key. Memory is bounded by maxKeys.
// When full, idle buckets are swept (at most once per sweepInterval, so the
// cost is amortized); if the map is still full, one arbitrary bucket is
// dropped in O(1). A dropped key starts again with a full bucket, which errs
// toward availability.
type Keyed struct {
	mu        sync.Mutex
	limit     rate.Limit
	burst     int
	maxKeys   int
	now       func() time.Time
	buckets   map[string]*bucket
	lastSweep time.Time
}

const sweepInterval = time.Second

type bucket struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// New returns a limiter allowing perMinute events per key with the given burst.
// now may be nil (time.Now).
func New(perMinute float64, burst, maxKeys int, now func() time.Time) *Keyed {
	if now == nil {
		now = time.Now
	}
	return &Keyed{
		limit:   rate.Limit(perMinute / 60),
		burst:   burst,
		maxKeys: maxKeys,
		now:     now,
		buckets: make(map[string]*bucket),
	}
}

// Allow consumes one token for key and reports whether it was available.
func (k *Keyed) Allow(key string) bool {
	return k.take(key, true)
}

// Peek reports whether key has a token available without consuming it.
func (k *Keyed) Peek(key string) bool {
	return k.take(key, false)
}

func (k *Keyed) take(key string, consume bool) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	b, ok := k.buckets[key]
	if !ok {
		if len(k.buckets) >= k.maxKeys {
			k.makeRoom(now)
		}
		b = &bucket{lim: rate.NewLimiter(k.limit, k.burst)}
		k.buckets[key] = b
	}
	b.lastSeen = now
	if !consume {
		return b.lim.TokensAt(now) >= 1
	}
	return b.lim.AllowN(now, 1)
}

// makeRoom frees at least one slot in amortized O(1).
func (k *Keyed) makeRoom(now time.Time) {
	if now.Sub(k.lastSweep) >= sweepInterval {
		k.lastSweep = now
		// A bucket idle for its full refill time is back at full burst, so
		// dropping it changes nothing.
		idle := time.Duration(float64(k.burst)/float64(k.limit)) * time.Second
		for key, b := range k.buckets {
			if now.Sub(b.lastSeen) > idle {
				delete(k.buckets, key)
			}
		}
	}
	for key := range k.buckets {
		if len(k.buckets) < k.maxKeys {
			return
		}
		delete(k.buckets, key) // map iteration order is randomized
	}
}

// Len returns the number of tracked keys (for tests and metrics).
func (k *Keyed) Len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.buckets)
}

// NetworkKey maps a client address to its rate-limit key: the address itself
// for IPv4 and the /64 for IPv6, since a single IPv6 host typically controls a
// whole /64 and could otherwise rotate addresses to evade limits.
func NetworkKey(a netip.Addr) string {
	a = a.Unmap()
	if a.Is6() {
		p, err := a.Prefix(64)
		if err == nil {
			return p.String()
		}
	}
	return a.String()
}
