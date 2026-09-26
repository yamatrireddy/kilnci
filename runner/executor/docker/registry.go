// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Resolver looks up the addresses of a registry host. *net.Resolver
// implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// resolveTimeout bounds the registry host lookup.
const resolveTimeout = 5 * time.Second

// errRegistryBlocked marks an image whose registry the runner refuses to
// pull from.
var errRegistryBlocked = errors.New("image registry not allowed")

// blockedPrefixes are address ranges a job image must never be pulled
// from, beyond those covered by the netip predicates in isBlockedAddr.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // "this network"
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT (also Alibaba metadata 100.100.100.200)
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments (incl. Oracle metadata 192.0.0.192)
	netip.MustParsePrefix("255.255.255.255/32"),
}

// isBlockedAddr reports whether a is loopback, private (RFC 1918, ULA
// fc00::/7, which includes AWS's fd00:ec2::254), link-local (including
// 169.254.169.254), unspecified, multicast, CGNAT, or another range that
// reaches the runner host's own network rather than a public registry.
func isBlockedAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// registryHost returns the registry host[:port] of an image reference, or ""
// for Docker Hub references (whose first component names a namespace, not a
// host). It follows the Docker reference grammar: the first component is a
// host if it contains '.' or ':' or is "localhost". Docker also treats a
// first component with an upper-case letter as a host; such references
// (and IPv6 literals, userinfo) never get here because validate's
// imagePattern accepts lower-case references only
// (TestValidate_ImageRegistry keeps it that way).
func registryHost(image string) string {
	first, _, hasSlash := strings.Cut(image, "/")
	if !hasSlash {
		return ""
	}
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return first
	}
	return ""
}

// checkRegistry refuses job images hosted on loopback, private, link-local
// or metadata addresses. Docker pulls from the host's network namespace, so
// such a pull would bypass the job's egress restrictions. Operators can
// allow specific registries (exact host[:port]) with RegistryAllowlist.
//
// Hostnames are resolved and rejected if any address is blocked or the
// lookup fails. dockerd resolves the name again on its own, so a hostile
// DNS server could still answer differently (rebinding); the host egress
// policy for dockerd remains the primary control.
func (e *Executor) checkRegistry(ctx context.Context, image string) error {
	host := registryHost(image)
	if host == "" {
		return nil
	}
	if _, ok := e.allowedRegistries[strings.ToLower(host)]; ok {
		return nil
	}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.TrimSuffix(strings.TrimPrefix(name, "["), "]")
	if strings.EqualFold(name, "localhost") || strings.HasSuffix(strings.ToLower(name), ".localhost") {
		return fmt.Errorf("%w: %s is the runner host", errRegistryBlocked, host)
	}
	if a, err := netip.ParseAddr(name); err == nil {
		if isBlockedAddr(a) {
			return fmt.Errorf("%w: %s is a loopback, private, or link-local address", errRegistryBlocked, host)
		}
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	addrs, err := e.opts.Resolver.LookupNetIP(rctx, "ip", name)
	if err != nil || len(addrs) == 0 {
		// Fail closed: dockerd would resolve it itself, possibly differently.
		return fmt.Errorf("%w: cannot resolve %s", errRegistryBlocked, host)
	}
	for _, a := range addrs {
		if isBlockedAddr(a) {
			return fmt.Errorf("%w: %s resolves to a loopback, private, or link-local address", errRegistryBlocked, host)
		}
	}
	return nil
}
