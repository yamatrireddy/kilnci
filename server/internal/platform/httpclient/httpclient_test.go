// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestAddrPolicy_Blocks is the SSRF suite from threat-model scenario S4.
func TestAddrPolicy_Blocks(t *testing.T) {
	blocked := []string{
		// loopback, all forms
		"127.0.0.1", "127.255.255.254", "::1", "::ffff:127.0.0.1", "::ffff:7f00:1",
		// unspecified / this-network
		"0.0.0.0", "0.1.2.3", "::",
		// RFC 1918 and ULA
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "fc00::1", "fd12:3456::1",
		// link-local incl. metadata
		"169.254.169.254", "169.254.170.2", "169.254.1.1", "fe80::1", "fd00:ec2::254", "fd00:ec2::23",
		// Alibaba metadata sits in CGNAT space
		"100.100.100.200", "100.64.0.1",
		// NAT64 / 6to4 wrappers around private or metadata IPv4
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::a00:1", "2002:7f00:1::", "2002:a9fe:a9fe::", "2002:c0a8:101::",
		"64:ff9b:1::1",
		// multicast, broadcast, reserved, documentation, benchmarking
		"224.0.0.1", "ff02::1", "255.255.255.255", "240.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1",
		"198.18.0.1", "2001:db8::1", "192.0.0.8", "fec0::1", "100::1", "2001::1",
	}
	p := addrPolicy{}
	for _, s := range blocked {
		if err := p.check(netip.MustParseAddr(s)); !errors.Is(err, ErrBlockedDestination) {
			t.Errorf("%s: want blocked, got %v", s, err)
		}
	}
}

func TestAddrPolicy_AllowsPublic(t *testing.T) {
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "140.82.112.3", "2606:4700:4700::1111", "2001:4860:4860::8888", "64:ff9b::808:808", "2002:808:808::"} {
		if err := (addrPolicy{}).check(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s: want allowed, got %v", s, err)
		}
	}
}

func TestAddrPolicy_AllowlistOpensPrivateButNeverMetadata(t *testing.T) {
	p := addrPolicy{allowed: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("fd00::/8"),
	}}
	if err := p.check(netip.MustParseAddr("10.1.2.3")); err != nil {
		t.Fatalf("allowlisted private address blocked: %v", err)
	}
	for _, m := range []string{"169.254.169.254", "100.100.100.200", "fd00:ec2::254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe"} {
		if err := p.check(netip.MustParseAddr(m)); !errors.Is(err, ErrBlockedDestination) {
			t.Errorf("metadata %s reachable via allowlist: %v", m, err)
		}
	}
}

func TestAddrPolicy_ControlParsesAddress(t *testing.T) {
	p := addrPolicy{}
	if err := p.control("tcp", "not-an-addr", nil); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("unparseable address: %v", err)
	}
	if err := p.control("tcp", "[fe80::1%eth0]:80", nil); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("zoned link-local: %v", err)
	}
	if err := p.control("tcp", "8.8.8.8:443", nil); err != nil {
		t.Fatalf("public address: %v", err)
	}
}

// End-to-end: the dial-time check blocks a real request to loopback, including
// via a DNS name and a redirect.
func TestClient_BlocksLoopbackEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("internal"))
	}))
	defer srv.Close()

	c := New(Options{Timeout: 2 * time.Second})
	for _, u := range []string{srv.URL, strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)} {
		resp, err := get(t, c, u)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("%s: request to loopback succeeded", u)
		}
		if !errors.Is(err, ErrBlockedDestination) {
			t.Fatalf("%s: want ErrBlockedDestination, got %v", u, err)
		}
	}
}

func TestClient_AllowlistedLoopbackWorks_AndRedirectsAreBounded(t *testing.T) {
	var hops int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "kiln-test" {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		if r.URL.Path == "/loop" {
			hops++
			http.Redirect(w, r, "/loop", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := New(Options{Timeout: 2 * time.Second, UserAgent: "kiln-test", AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	resp, err := get(t, c, srv.URL+"/ok")
	if err != nil {
		t.Fatalf("allowlisted request failed: %v", err)
	}
	_ = resp.Body.Close()

	resp, err = get(t, c, srv.URL+"/loop")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("redirect loop not stopped")
	}
	if hops > maxRedirects {
		t.Fatalf("followed %d redirects, max %d", hops, maxRedirects)
	}
}

func TestCheckRedirect_RefusesDowngradeAndOddSchemes(t *testing.T) {
	mk := func(u string) *http.Request {
		r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
		return r
	}
	if err := checkRedirect(mk("http://example.com"), []*http.Request{mk("https://example.com")}); err == nil {
		t.Fatal("https -> http downgrade allowed")
	}
	if err := checkRedirect(mk("file:///etc/passwd"), []*http.Request{mk("http://example.com")}); err == nil {
		t.Fatal("redirect to file:// allowed")
	}
	if err := checkRedirect(mk("https://example.com/b"), []*http.Request{mk("https://example.com/a")}); err != nil {
		t.Fatalf("same-scheme redirect refused: %v", err)
	}
}

func TestClient_RejectsNonHTTPSchemes(t *testing.T) {
	c := New(Options{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "ftp://example.com/x", nil)
	resp, err := c.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("ftp scheme accepted")
	}
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c.Do(req) //nolint:wrapcheck // test helper
}
