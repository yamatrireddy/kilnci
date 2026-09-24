// SPDX-License-Identifier: Apache-2.0

// Package httpclient provides the only HTTP client the server may use for
// outbound requests (CLAUDE.md; security-standards §6; threat T-40).
//
// Protections:
//   - The destination is checked at connect time, on the IP actually dialed,
//     so DNS rebinding and multi-record tricks cannot bypass it.
//   - Loopback, private, link-local, CGNAT, unspecified, multicast, and other
//     special-purpose ranges are blocked unless an admin allowlists a prefix.
//     IPv4-mapped, NAT64, and 6to4 IPv6 forms are unwrapped and checked as IPv4.
//   - Cloud metadata endpoints are blocked unconditionally, even if allowlisted.
//   - Environment proxies are ignored (a proxy would hide the real destination).
//   - Redirects are limited to 3, re-checked on connect, and may not downgrade
//     from https to http.
//   - Every request has an overall timeout; TLS 1.2 is the minimum.
package httpclient

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrBlockedDestination is returned (wrapped) when a request targets a
// disallowed address.
var ErrBlockedDestination = errors.New("destination address is not allowed")

const maxRedirects = 3

// Options configures a client.
type Options struct {
	// Timeout bounds the whole request including reading the body. Default 10s.
	Timeout time.Duration
	// AllowedPrefixes are admin-approved ranges that are otherwise blocked
	// (e.g. an internal IdP). Metadata endpoints stay blocked regardless.
	AllowedPrefixes []netip.Prefix
	// UserAgent is sent on every request. Default "kiln-server".
	UserAgent string
}

// New returns a hardened *http.Client.
func New(opts Options) *http.Client {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "kiln-server"
	}
	policy := addrPolicy{allowed: opts.AllowedPrefixes}
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   policy.control,
	}
	transport := &http.Transport{
		Proxy:                 nil, // never use environment proxies
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: opts.Timeout,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Timeout:       opts.Timeout,
		Transport:     &uaTransport{next: transport, ua: opts.UserAgent},
		CheckRedirect: checkRedirect,
	}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("refusing redirect from https to a non-https URL")
	}
	if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
		return fmt.Errorf("refusing redirect to scheme %q", req.URL.Scheme)
	}
	return nil
}

type uaTransport struct {
	next http.RoundTripper
	ua   string
}

func (t *uaTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" && r.URL.Scheme != "http" {
		return nil, fmt.Errorf("unsupported scheme %q", r.URL.Scheme)
	}
	r = r.Clone(r.Context())
	r.Header.Set("User-Agent", t.ua)
	return t.next.RoundTrip(r) //nolint:wrapcheck // transport pass-through
}

// addrPolicy decides whether an IP may be dialed.
type addrPolicy struct {
	allowed []netip.Prefix
}

// control runs after DNS resolution with the literal ip:port being dialed.
func (p addrPolicy) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable address", ErrBlockedDestination)
	}
	if err := p.check(ap.Addr()); err != nil {
		return err
	}
	return nil
}

// check returns nil if addr may be dialed.
func (p addrPolicy) check(addr netip.Addr) error {
	addr = addr.WithZone("")
	candidates := []netip.Addr{addr.Unmap()}
	if v4, ok := embeddedIPv4(addr); ok {
		candidates = append(candidates, v4)
	}
	for _, a := range candidates {
		if isMetadata(a) {
			return fmt.Errorf("%w: cloud metadata endpoint", ErrBlockedDestination)
		}
	}
	for _, a := range candidates {
		if isSpecialPurpose(a) && !p.isAllowed(a) {
			return fmt.Errorf("%w: %s is in a blocked range", ErrBlockedDestination, a)
		}
	}
	return nil
}

func (p addrPolicy) isAllowed(a netip.Addr) bool {
	for _, pfx := range p.allowed {
		if pfx.Contains(a) {
			return true
		}
	}
	return false
}

var (
	metadataAddrs = []netip.Addr{
		netip.MustParseAddr("169.254.169.254"), // AWS, GCP, Azure, OpenStack, DO
		netip.MustParseAddr("169.254.170.2"),   // AWS ECS task metadata
		netip.MustParseAddr("169.254.169.123"), // AWS time sync (same link-local host)
		netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
		netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS IPv6
		netip.MustParseAddr("fd00:ec2::23"),    // AWS ECS/EKS IPv6
	}

	// Ranges from the IANA special-purpose registries that must not be reached
	// by default. netip's IsPrivate/IsLoopback/etc. cover most; the rest are here.
	extraBlocked = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
		netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT (also used by some cloud internals)
		netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
		netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
		netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
		netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
		netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
		netip.MustParsePrefix("240.0.0.0/4"),     // reserved + broadcast
		netip.MustParsePrefix("100::/64"),        // discard-only
		netip.MustParsePrefix("2001:db8::/32"),   // documentation
		netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments (incl. Teredo)
		netip.MustParsePrefix("fec0::/10"),       // deprecated site-local
		netip.MustParsePrefix("::/128"),          // unspecified
		netip.MustParsePrefix("::ffff:0:0:0/96"), // SIIT
		netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
		netip.MustParsePrefix("5f00::/16"),       // SRv6 SIDs
		netip.MustParsePrefix("3fff::/20"),       // documentation (RFC 9637)
	}

	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour = netip.MustParsePrefix("2002::/16")
)

func isMetadata(a netip.Addr) bool {
	for _, m := range metadataAddrs {
		if a == m {
			return true
		}
	}
	return false
}

func isSpecialPurpose(a netip.Addr) bool {
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range extraBlocked {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// embeddedIPv4 extracts an IPv4 address carried inside NAT64 (64:ff9b::/96)
// or 6to4 (2002::/16) IPv6 addresses, so they are checked as that IPv4.
func embeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() || a.Is4In6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case nat64.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}
