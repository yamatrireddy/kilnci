// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/netip"
	"strings"
)

// clientIPResolver derives the client address used for rate limiting and audit.
// X-Forwarded-For is trusted only when the direct peer is a configured proxy,
// and then only up to the first untrusted hop from the right, so a client
// cannot spoof its address by sending its own header.
type clientIPResolver struct {
	trusted []netip.Prefix
}

func (c clientIPResolver) isTrusted(a netip.Addr) bool {
	for _, p := range c.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// peerTrusted reports whether the direct peer is a configured proxy.
func (c clientIPResolver) peerTrusted(r *http.Request) bool {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	return err == nil && c.isTrusted(peer.Addr().Unmap())
}

// resolve returns the best-known client IP for r.
func (c clientIPResolver) resolve(r *http.Request) netip.Addr {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	addr := peer.Addr().Unmap()
	if !c.isTrusted(addr) {
		return addr
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return addr // malformed chain: fall back to the proxy itself
		}
		h = h.Unmap()
		if !c.isTrusted(h) {
			return h
		}
		addr = h
	}
	return addr
}
