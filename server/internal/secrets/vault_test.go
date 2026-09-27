// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/platform/httpclient"
)

// fakeTransit is a minimal Vault Transit with a derived key: each version's
// key is HMAC(root, version) and each context's key is HMAC(that, context).
type fakeTransit struct {
	t         *testing.T
	token     string
	namespace string

	mu      sync.Mutex
	version int
	calls   []string
	status  int // forced status, if non-zero
	body    string
	keyInfo map[string]any // served at /v1/transit/keys/kiln
}

func (f *fakeTransit) derived(version int, ctx []byte) []byte {
	m := hmac.New(sha256.New, []byte(fmt.Sprintf("root-%d", version)))
	m.Write(ctx)
	return m.Sum(nil)
}

func (f *fakeTransit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.URL.Path)
	if f.status != 0 {
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(f.body))
		return
	}
	if r.Header.Get("X-Vault-Token") == f.token && r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/kiln" {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": f.keyInfo})
		return
	}
	if r.Method != http.MethodPost || r.Header.Get("X-Vault-Token") != f.token || r.Header.Get("X-Vault-Namespace") != f.namespace {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var req transitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx, err := base64.StdEncoding.DecodeString(req.Context)
	if err != nil || len(ctx) == 0 {
		w.WriteHeader(http.StatusBadRequest) // derived keys need a context
		return
	}
	encrypt := func(pt []byte) string {
		ct, err := seal(f.derived(f.version, ctx), pt, nil)
		if err != nil {
			f.t.Fatal(err)
		}
		return fmt.Sprintf("vault:v%d:%s", f.version, base64.StdEncoding.EncodeToString(ct))
	}
	decrypt := func(s string) ([]byte, bool) {
		var v int
		var b64 string
		if _, err := fmt.Sscanf(s, "vault:v%d:%s", &v, &b64); err != nil || v < 1 || v > f.version {
			return nil, false
		}
		ct, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, false
		}
		pt, err := open(f.derived(v, ctx), ct, nil)
		return pt, err == nil
	}
	var out transitResponse
	switch r.URL.Path {
	case "/v1/transit/encrypt/kiln":
		pt, _ := base64.StdEncoding.DecodeString(req.Plaintext)
		out.Data.Ciphertext = encrypt(pt)
	case "/v1/transit/decrypt/kiln":
		pt, ok := decrypt(req.Ciphertext)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		out.Data.Plaintext = base64.StdEncoding.EncodeToString(pt)
	case "/v1/transit/rewrap/kiln":
		pt, ok := decrypt(req.Ciphertext)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		out.Data.Ciphertext = encrypt(pt)
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(out)
}

func newVaultFixture(t *testing.T) (*fakeTransit, *VaultWrapper, string) {
	t.Helper()
	f := &fakeTransit{t: t, token: "s.test-token", namespace: "team/kiln", version: 1,
		keyInfo: map[string]any{"derived": true, "exportable": false, "allow_plaintext_backup": false, "latest_version": 1}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(f.token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	addr, _ := url.Parse(srv.URL)
	client := httpclient.New(httpclient.Options{Timeout: 2 * time.Second, AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	w, err := NewVaultWrapper(VaultOptions{Client: client, Addr: addr, Mount: "transit", Key: "kiln", TokenFile: tokenFile, Namespace: f.namespace})
	if err != nil {
		t.Fatal(err)
	}
	return f, w, tokenFile
}

func TestVaultWrapper_WrapUnwrapRewrap(t *testing.T) {
	ctx := context.Background()
	f, w, _ := newVaultFixture(t)
	dek := testKey(t)
	wk, err := w.Wrap(ctx, "org1", dek)
	if err != nil {
		t.Fatal(err)
	}
	if wk.KeyID != "vault:kiln:v1" {
		t.Fatalf("key ID = %q", wk.KeyID)
	}
	got, err := w.Unwrap(ctx, "org1", wk)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	// The org is the derivation context: another org cannot unwrap it.
	if _, err := w.Unwrap(ctx, "org2", wk); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("other org: err = %v, want ErrDecrypt", err)
	}

	f.mu.Lock()
	f.version = 2
	f.mu.Unlock()
	re, err := w.Rewrap(ctx, "org1", wk)
	if err != nil {
		t.Fatal(err)
	}
	if re.KeyID != "vault:kiln:v2" {
		t.Fatalf("rewrapped key ID = %q", re.KeyID)
	}
	if got, err := w.Unwrap(ctx, "org1", re); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap after rewrap: %v", err)
	}
}

func TestVaultWrapper_RejectsMismatchedOrForeignCiphertexts(t *testing.T) {
	ctx := context.Background()
	f, w, _ := newVaultFixture(t)
	wk, _ := w.Wrap(ctx, "org1", testKey(t))
	for name, bad := range map[string]WrappedKey{
		"key ID from another key":  {KeyID: "vault:other:v1", Ciphertext: wk.Ciphertext},
		"key ID version mismatch":  {KeyID: "vault:kiln:v9", Ciphertext: wk.Ciphertext},
		"local key ID":             {KeyID: "local:abcd", Ciphertext: wk.Ciphertext},
		"not a Transit ciphertext": {KeyID: "vault:kiln:v1", Ciphertext: []byte("garbage")},
		"oversized":                {KeyID: "vault:kiln:v1", Ciphertext: []byte("vault:v1:" + strings.Repeat("A", maxVaultCiphertext))},
	} {
		before := len(f.calls)
		if _, err := w.Unwrap(ctx, "org1", bad); !errors.Is(err, ErrUnknownKey) {
			t.Errorf("%s: err = %v, want ErrUnknownKey", name, err)
		}
		if len(f.calls) != before {
			t.Errorf("%s: sent to Vault", name)
		}
	}
}

func TestVaultWrapper_ErrorsNeverCarryBodies(t *testing.T) {
	ctx := context.Background()
	f, w, _ := newVaultFixture(t)
	f.status, f.body = http.StatusInternalServerError, "permission denied for s.test-token"
	_, err := w.Wrap(ctx, "org1", testKey(t))
	if err == nil || strings.Contains(err.Error(), "test-token") || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
	f.status, f.body = http.StatusOK, "{not json"
	if _, err := w.Wrap(ctx, "org1", testKey(t)); err == nil || strings.Contains(err.Error(), "not json") {
		t.Fatalf("malformed body: err = %v", err)
	}
	f.status, f.body = http.StatusOK, `{"data":{"ciphertext":"plaintext-looking"}}`
	if _, err := w.Wrap(ctx, "org1", testKey(t)); err == nil {
		t.Fatal("unexpected ciphertext format accepted")
	}
	f.status, f.body = http.StatusOK, `{"data":{"plaintext":"c2hvcnQ="}}`
	if _, err := w.Unwrap(ctx, "org1", WrappedKey{KeyID: "vault:kiln:v1", Ciphertext: []byte("vault:v1:AAAA")}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("short plaintext: err = %v, want ErrDecrypt", err)
	}
}

func TestVaultWrapper_TokenFileIsReReadAndValidated(t *testing.T) {
	ctx := context.Background()
	f, w, tokenFile := newVaultFixture(t)
	if _, err := w.Wrap(ctx, "org1", testKey(t)); err != nil {
		t.Fatal(err)
	}
	// A renewed token is picked up without a restart.
	f.mu.Lock()
	f.token = "s.renewed"
	f.mu.Unlock()
	if err := os.WriteFile(tokenFile, []byte("s.renewed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Wrap(ctx, "org1", testKey(t)); err != nil {
		t.Fatalf("after renewal: %v", err)
	}
	if _, err := w.Wrap(ctx, "", testKey(t)); err == nil {
		t.Fatal("wrap without org accepted")
	}
	for _, content := range []string{"", "  \n", "a\x00b", "a\rb", strings.Repeat("t", maxVaultToken+1)} {
		_ = os.WriteFile(tokenFile, []byte(content), 0o600)
		if _, err := w.Wrap(ctx, "org1", testKey(t)); err == nil {
			t.Errorf("token %q accepted", content)
		}
	}
	_ = os.Remove(tokenFile)
	if _, err := w.Wrap(ctx, "org1", testKey(t)); err == nil || strings.Contains(err.Error(), tokenFile) {
		t.Fatalf("missing token file: err = %v", err)
	}
}

func TestVaultWrapper_RespectsSSRFPolicy(t *testing.T) {
	_, _, tokenFile := newVaultFixture(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	addr, _ := url.Parse(srv.URL)
	// Without an allowlist entry, a loopback Vault is refused.
	w, _ := NewVaultWrapper(VaultOptions{Client: httpclient.New(httpclient.Options{Timeout: time.Second}), Addr: addr, Mount: "transit", Key: "kiln", TokenFile: tokenFile})
	if _, err := w.Wrap(context.Background(), "org1", testKey(t)); !errors.Is(err, httpclient.ErrBlockedDestination) {
		t.Fatalf("err = %v, want ErrBlockedDestination", err)
	}
	if _, err := NewVaultWrapper(VaultOptions{Addr: addr}); err == nil {
		t.Fatal("incomplete options accepted")
	}
}

func TestNewVaultWrapper_RejectsPathCharactersAndBadAddresses(t *testing.T) {
	c := httpclient.New(httpclient.Options{})
	good, _ := url.Parse("https://vault.example:8200")
	for name, o := range map[string]VaultOptions{
		"key traversal":   {Mount: "transit", Key: "../../sys/seal"},
		"mount slash":     {Mount: "a/b", Key: "kiln"},
		"empty key":       {Mount: "transit", Key: ""},
		"namespace dots":  {Mount: "transit", Key: "kiln", Namespace: "../root"},
		"address path":    {Mount: "transit", Key: "kiln", Addr: &url.URL{Scheme: "https", Host: "v", Path: "/v1/sys"}},
		"address creds":   {Mount: "transit", Key: "kiln", Addr: &url.URL{Scheme: "https", Host: "v", User: url.UserPassword("u", "p")}},
		"address scheme":  {Mount: "transit", Key: "kiln", Addr: &url.URL{Scheme: "file", Host: "v"}},
		"address no host": {Mount: "transit", Key: "kiln", Addr: &url.URL{Scheme: "https"}},
	} {
		o.Client, o.TokenFile = c, "/t"
		if o.Addr == nil {
			o.Addr = good
		}
		if _, err := NewVaultWrapper(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVaultWrapper_CheckRequiresSafeKey(t *testing.T) {
	ctx := context.Background()
	f, w, _ := newVaultFixture(t)
	info, err := w.Check(ctx)
	if err != nil || info.LatestVersion != 1 {
		t.Fatalf("safe key: %+v, %v", info, err)
	}
	for name, change := range map[string]map[string]any{
		// A non-derived key ignores the org context, so DEKs would not be
		// bound to their org (T-62).
		"not derived":      {"derived": false},
		"exportable":       {"exportable": true},
		"plaintext backup": {"allow_plaintext_backup": true},
		"no versions":      {"latest_version": 0},
	} {
		f.mu.Lock()
		saved := f.keyInfo
		f.keyInfo = map[string]any{}
		for k, v := range saved {
			f.keyInfo[k] = v
		}
		for k, v := range change {
			f.keyInfo[k] = v
		}
		f.mu.Unlock()
		if _, err := w.Check(ctx); !errors.Is(err, ErrUnsafeVaultKey) {
			t.Errorf("%s: err = %v, want ErrUnsafeVaultKey", name, err)
		}
		f.mu.Lock()
		f.keyInfo = saved
		f.mu.Unlock()
	}
	f.mu.Lock()
	f.keyInfo["deletion_allowed"] = true
	f.mu.Unlock()
	if info, err := w.Check(ctx); err != nil || !info.DeletionAllowed {
		t.Fatalf("deletion_allowed must be reported, not fatal: %+v, %v", info, err)
	}
}

// A redirect must never carry the token or a plaintext DEK to another host.
func TestVaultWrapper_DoesNotFollowRedirects(t *testing.T) {
	var leaked sync.Map
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		leaked.Store("hit", r.Header.Get("X-Vault-Token"))
	}))
	defer other.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/v1/transit/encrypt/kiln", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	_, _, tokenFile := newVaultFixture(t)
	addr, _ := url.Parse(redirector.URL)
	client := httpclient.New(httpclient.Options{Timeout: 2 * time.Second, AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	w, err := NewVaultWrapper(VaultOptions{Client: client, Addr: addr, Mount: "transit", Key: "kiln", TokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.Wrap(context.Background(), "org1", testKey(t))
	if err == nil || !strings.Contains(err.Error(), "redirected") || strings.Contains(err.Error(), "test-token") {
		t.Fatalf("err = %v", err)
	}
	if _, hit := leaked.Load("hit"); hit {
		t.Fatal("redirect was followed")
	}
	// The caller's client keeps its own redirect policy.
	if client.CheckRedirect == nil {
		t.Fatal("NewVaultWrapper modified the shared client")
	}
}
