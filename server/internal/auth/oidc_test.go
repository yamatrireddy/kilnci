// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/httpclient"
)

// fakeOIDC is a minimal OIDC provider that issues RS256-signed ID tokens, so
// OIDCProvider is tested against real signature, issuer, audience, expiry,
// and nonce verification.
type fakeOIDC struct {
	t      *testing.T
	srv    *httptest.Server
	key    *rsa.PrivateKey // advertised in JWKS
	signer *rsa.PrivateKey // actually used to sign (differs in the forged-key test)

	mu        sync.Mutex
	claims    map[string]any // ID token claims to issue
	noIDToken bool
	tokenErr  bool
	lastForm  url.Values
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOIDC{t: t, key: key, signer: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lastForm = r.PostForm
		if f.tokenErr {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		resp := map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 60}
		if !f.noIDToken {
			resp["id_token"] = f.sign(f.claims)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOIDC) sign(claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: f.signer, KeyID: "k1"}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		f.t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fakeOIDC) goodClaims(nonce string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": f.srv.URL, "aud": "kiln", "sub": "user-1", "nonce": nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"email": "a@example.com", "email_verified": true, "name": "A", "amr": []string{"mfa"},
	}
}

func (f *fakeOIDC) provider() *OIDCProvider {
	return NewOIDCProvider(OIDCOptions{
		IssuerURL: f.srv.URL, ClientID: "kiln", RedirectURL: "https://kiln.test/api/v1/auth/callback",
		// The test IdP is on loopback, so it must be explicitly allow-listed,
		// exactly as an operator would for an internal IdP.
		HTTPClient: httpclient.New(httpclient.Options{AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}),
	})
}

func TestOIDCProvider_AuthCodeURLUsesPKCEAndNonce(t *testing.T) {
	f := newFakeOIDC(t)
	u, err := f.provider().AuthCodeURL(t.Context(), "the-state", "the-nonce", "the-verifier-"+strings.Repeat("x", 40), false)
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	q := pu.Query()
	if !strings.HasPrefix(u, f.srv.URL+"/authorize?") || q.Get("state") != "the-state" || q.Get("nonce") != "the-nonce" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("client_id") != "kiln" ||
		!strings.Contains(q.Get("scope"), "openid") || q.Get("prompt") != "" {
		t.Fatalf("auth URL = %s", u)
	}
	forced, _ := f.provider().AuthCodeURL(t.Context(), "s", "n", "v", true)
	if !strings.Contains(forced, "prompt=login") {
		t.Fatalf("forced login URL = %s", forced)
	}
}

func TestOIDCProvider_Exchange(t *testing.T) {
	f := newFakeOIDC(t)
	p := f.provider()
	verifier := "v-" + strings.Repeat("y", 50)

	f.claims = f.goodClaims("n1")
	c, err := p.Exchange(t.Context(), "code", verifier, "n1")
	if err != nil {
		t.Fatalf("valid exchange: %v", err)
	}
	if c.Subject != "user-1" || c.Email != "a@example.com" || !c.EmailVerified || c.Issuer != f.srv.URL || c.AMR[0] != "mfa" {
		t.Fatalf("claims = %+v", c)
	}
	if f.lastForm.Get("code_verifier") != verifier {
		t.Fatal("PKCE verifier not sent to the token endpoint")
	}

	bad := map[string]func(){
		"wrong nonce":    func() { f.claims = f.goodClaims("other") },
		"wrong audience": func() { f.claims = f.goodClaims("n1"); f.claims["aud"] = "someone-else" },
		"wrong issuer":   func() { f.claims = f.goodClaims("n1"); f.claims["iss"] = "https://evil.example" },
		"expired":        func() { f.claims = f.goodClaims("n1"); f.claims["exp"] = time.Now().Add(-time.Hour).Unix() },
		"forged signature": func() {
			k, _ := rsa.GenerateKey(rand.Reader, 2048)
			f.signer = k
			f.claims = f.goodClaims("n1")
		},
		"no id_token": func() { f.signer = f.key; f.noIDToken = true },
		"token error": func() { f.noIDToken = false; f.tokenErr = true },
	}
	order := []string{"wrong nonce", "wrong audience", "wrong issuer", "expired", "forged signature", "no id_token", "token error"}
	for _, name := range order {
		bad[name]()
		if _, err := p.Exchange(t.Context(), "code", verifier, "n1"); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want ErrUnauthenticated", name, err)
		}
	}
}

func TestOIDCProvider_DiscoveryIsSSRFProtected(t *testing.T) {
	f := newFakeOIDC(t)
	// Without the allow-list the loopback IdP is unreachable.
	p := NewOIDCProvider(OIDCOptions{IssuerURL: f.srv.URL, ClientID: "kiln", HTTPClient: httpclient.New(httpclient.Options{})})
	if _, err := p.AuthCodeURL(t.Context(), "s", "n", "v", false); err == nil || !errors.Is(err, httpclient.ErrBlockedDestination) {
		t.Fatalf("discovery to loopback not blocked: %v", err)
	}
	if _, err := p.Exchange(t.Context(), "c", "v", "n"); err == nil {
		t.Fatal("exchange without discovery succeeded")
	}
}
