// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewSecret(t *testing.T) {
	a, ah := newSecret(PrefixAPIToken)
	b, bh := newSecret(PrefixAPIToken)
	if a == b || bytes.Equal(ah, bh) {
		t.Fatal("secrets repeat")
	}
	if !strings.HasPrefix(a, PrefixAPIToken) || !wellFormed(a, PrefixAPIToken) {
		t.Fatalf("malformed secret %q", a)
	}
	if !bytes.Equal(hashToken(a), ah) || len(ah) != 32 {
		t.Fatal("hash mismatch")
	}
	if len(randomString()) != 43 {
		t.Fatal("randomString length")
	}
}

func TestWellFormed(t *testing.T) {
	good, _ := newSecret(PrefixSession)
	tests := map[string]bool{
		good:                                    true,
		PrefixSession:                           false,
		PrefixSession + "short":                 false,
		PrefixAPIToken + good[10:]:              false,
		good + "x":                              false,
		PrefixSession + strings.Repeat("!", 43): false,
	}
	for tok, want := range tests {
		if got := wellFormed(tok, PrefixSession); got != want {
			t.Errorf("wellFormed(%q) = %v, want %v", tok, got, want)
		}
	}
}

func TestPKCE_RFC7636Vector(t *testing.T) {
	// RFC 7636 Appendix B.
	if got := pkceS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("pkceS256 = %q", got)
	}
}

func TestCSRFToken_BoundToSession(t *testing.T) {
	a, _ := newSecret(PrefixSession)
	b, _ := newSecret(PrefixSession)
	first, again := csrfToken(a), csrfToken(a)
	if first != again || first == csrfToken(b) {
		t.Fatal("CSRF token must be deterministic per session and differ across sessions")
	}
	if strings.Contains(csrfToken(a), a[len(PrefixSession):]) {
		t.Fatal("CSRF token reveals the session secret")
	}
	if !equalConstantTime("x", "x") || equalConstantTime("x", "y") || equalConstantTime("x", "") {
		t.Fatal("equalConstantTime wrong")
	}
}

func TestSafeReturnTo_PreventsOpenRedirect(t *testing.T) {
	tests := map[string]string{
		"":                             "/",
		"/":                            "/",
		"/orgs/acme?tab=projects#x":    "/orgs/acme?tab=projects#x",
		"//evil.example/":              "/",
		"/\\evil.example":              "/",
		"https://evil.example/":        "/",
		"javascript:alert(1)":          "/",
		"evil.example":                 "/",
		"/%0d%0aSet-Cookie:x":          "/%0d%0aSet-Cookie:x", // stays a same-origin path; never a header
		"/ok\r\nLocation: https://x":   "/",
		"/" + strings.Repeat("a", 600): "/",
		"/\tevil":                      "/",
	}
	for in, want := range tests {
		if got := safeReturnTo(in); got != want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidDesktopRedirect(t *testing.T) {
	tests := map[string]bool{
		"http://127.0.0.1:53682/callback":        true,
		"http://127.0.0.1:1024/callback":         true,
		"http://127.0.0.1:80/callback":           false, // privileged port
		"http://127.0.0.1:99999/callback":        false,
		"http://localhost:53682/callback":        false, // RFC 8252 prefers the literal IP
		"https://127.0.0.1:53682/callback":       false,
		"http://127.0.0.1:53682/callback/../x":   false,
		"http://127.0.0.1:53682/callback?x=1":    false,
		"http://127.0.0.1.evil.example/callback": false,
		"http://10.0.0.1:53682/callback":         false,
	}
	for in, want := range tests {
		if got := validDesktopRedirect(in); got != want {
			t.Errorf("validDesktopRedirect(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCheckClaims(t *testing.T) {
	ok := Claims{Issuer: "https://idp", Subject: "s", Email: "a@example.com", EmailVerified: true, AMR: []string{"pwd", "mfa"}}
	if err := checkClaims(ok, nil); err != nil {
		t.Fatal(err)
	}
	if err := checkClaims(ok, []string{"mfa"}); err != nil {
		t.Fatal(err)
	}
	bad := []Claims{
		{Issuer: "", Subject: "s", Email: "a@x", EmailVerified: true},
		{Issuer: "i", Subject: "", Email: "a@x", EmailVerified: true},
		{Issuer: "i", Subject: "s", Email: "a@x", EmailVerified: false},
		{Issuer: "i", Subject: "s", Email: "", EmailVerified: true},
	}
	for _, c := range bad {
		if err := checkClaims(c, nil); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	noMFA := ok
	noMFA.AMR = []string{"pwd"}
	if err := checkClaims(noMFA, []string{"mfa", "hwk"}); err == nil {
		t.Fatal("missing required amr accepted")
	}
}
