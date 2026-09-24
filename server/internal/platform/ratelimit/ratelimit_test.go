// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"net/netip"
	"strconv"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestKeyed_LimitsPerKeyAndRefills(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	k := New(60, 3, 100, c.now) // 1/s, burst 3
	for i := range 3 {
		if !k.Allow("a") {
			t.Fatalf("request %d denied within burst", i)
		}
	}
	if k.Allow("a") {
		t.Fatal("request beyond burst allowed")
	}
	if !k.Allow("b") {
		t.Fatal("other key affected")
	}
	if k.Peek("a") {
		t.Fatal("Peek reports token for exhausted key")
	}
	c.t = c.t.Add(time.Second)
	if !k.Peek("a") || !k.Allow("a") {
		t.Fatal("bucket did not refill")
	}
}

func TestKeyed_BoundedMemory(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	k := New(60, 1, 10, c.now)
	for i := range 100 {
		c.t = c.t.Add(time.Millisecond)
		k.Allow("k" + strconv.Itoa(i))
	}
	if n := k.Len(); n > 10 {
		t.Fatalf("tracked %d keys, max 10", n)
	}
	// Idle buckets are evicted first.
	c.t = c.t.Add(time.Hour)
	k.Allow("fresh")
	if n := k.Len(); n != 1 {
		t.Fatalf("idle buckets not evicted: %d", n)
	}
}

func TestKeyed_ActiveKeyNotResetByChurn(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	k := New(1, 1, 3, c.now)
	k.Allow("attacker") // exhaust
	for i := range 2 {
		c.t = c.t.Add(time.Millisecond)
		k.Allow("other" + strconv.Itoa(i))
	}
	c.t = c.t.Add(time.Millisecond)
	if k.Allow("attacker") {
		t.Fatal("exhausted key reset while still within capacity")
	}
}

func TestNetworkKey(t *testing.T) {
	same := []string{"2001:db8:1:2:aaaa::1", "2001:db8:1:2:ffff:ffff:ffff:ffff"}
	if NetworkKey(netip.MustParseAddr(same[0])) != NetworkKey(netip.MustParseAddr(same[1])) {
		t.Fatal("addresses in one IPv6 /64 must share a key")
	}
	if NetworkKey(netip.MustParseAddr("2001:db8:1:3::1")) == NetworkKey(netip.MustParseAddr(same[0])) {
		t.Fatal("different /64s must not share a key")
	}
	if NetworkKey(netip.MustParseAddr("203.0.113.5")) == NetworkKey(netip.MustParseAddr("203.0.113.6")) {
		t.Fatal("IPv4 addresses are keyed individually")
	}
	if NetworkKey(netip.MustParseAddr("::ffff:203.0.113.5")) != "203.0.113.5" {
		t.Fatal("IPv4-mapped addresses must key as IPv4")
	}
	if NetworkKey(netip.Addr{}) != "invalid IP" {
		t.Fatal("zero address")
	}
}

func TestKeyed_ChurnStaysFast(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	k := New(60, 5, 1000, c.now)
	start := time.Now()
	for i := range 200_000 {
		k.Allow("key-" + strconv.Itoa(i))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("200k unique keys took %v; eviction is not amortized O(1)", d)
	}
	if k.Len() > 1000 {
		t.Fatalf("tracked %d keys", k.Len())
	}
}
