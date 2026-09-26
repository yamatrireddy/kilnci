// SPDX-License-Identifier: Apache-2.0

package github

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type fakeGitHub struct {
	t        *testing.T
	key      *rsa.PrivateKey
	mu       sync.Mutex
	tokenReq []map[string]any
	statuses []map[string]string
}

func (f *fakeGitHub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tok, err := jwt.ParseSigned(auth, []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			http.Error(w, "bad jwt", http.StatusUnauthorized)
			return
		}
		var claims jwt.Claims
		if err := tok.Claims(&f.key.PublicKey, &claims); err != nil || claims.Issuer != "42" ||
			time.Until(claims.Expiry.Time()) > 10*time.Minute {
			http.Error(w, "bad claims", http.StatusUnauthorized)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.tokenReq = append(f.tokenReq, body)
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_test_" + r.PathValue("id"), "expires_at": time.Now().Add(time.Hour)})
	})
	mux.HandleFunc("GET /app/installations/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != "7" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 7, "account": map[string]string{"login": "acme"}})
	})
	mux.HandleFunc("GET /repos/{owner}/{name}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token ghs_test_7" || r.PathValue("name") != "app" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 99, "full_name": "acme/app", "clone_url": "https://github.com/acme/app.git", "default_branch": "main", "private": true})
	})
	mux.HandleFunc("GET /repositories/99/contents/.kiln/pipeline.yaml", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ref") != strings.Repeat("a", 40) || r.Header.Get("Accept") != "application/vnd.github.raw" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "version: 1\n")
	})
	mux.HandleFunc("GET /repositories/99/git/ref/heads/{branch...}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("branch") != "feature/x" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": strings.Repeat("b", 40), "type": "commit"}})
	})
	mux.HandleFunc("POST /repositories/99/statuses/{sha}", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.statuses = append(f.statuses, body)
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "{}")
	})
	mux.HandleFunc("GET /repositories/500/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal detail ghs_leaked_secret", http.StatusInternalServerError)
	})
	return mux
}

func newTestClient(t *testing.T) (*Client, *fakeGitHub) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGitHub{t: t, key: key}
	srv := httptest.NewTLSServer(f.handler())
	t.Cleanup(srv.Close)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	c, err := New(Options{AppID: 42, PrivateKey: keyPEM, APIURL: srv.URL, HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func TestClient_TokensAreRepoScopedAndCached(t *testing.T) {
	c, f := newTestClient(t)
	ctx := t.Context()
	for range 3 {
		if _, _, err := c.Token(ctx, 7, 99, PermContentsRead); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := c.Token(ctx, 7, 99, PermStatusWrite); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.tokenReq) != 2 {
		t.Fatalf("token requests = %d, want 2 (cached per permission set)", len(f.tokenReq))
	}
	ids, _ := f.tokenReq[0]["repository_ids"].([]any)
	perms, _ := f.tokenReq[0]["permissions"].(map[string]any)
	if len(ids) != 1 || ids[0].(float64) != 99 || perms["contents"] != "read" || len(perms) != 2 {
		t.Fatalf("token request = %+v", f.tokenReq[0])
	}
}

func TestClient_RepositoryFileBranchStatus(t *testing.T) {
	c, f := newTestClient(t)
	ctx := t.Context()
	inst, err := c.GetInstallation(ctx, 7)
	if err != nil || inst.AccountLogin != "acme" {
		t.Fatalf("installation = %+v %v", inst, err)
	}
	if _, err := c.GetInstallation(ctx, 8); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown installation = %v", err)
	}
	repo, err := c.GetRepository(ctx, 7, "acme/app")
	if err != nil || repo.ID != 99 || !repo.Private || repo.DefaultBranch != "main" {
		t.Fatalf("repo = %+v %v", repo, err)
	}
	if _, err := c.GetRepository(ctx, 7, "acme/other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("inaccessible repo = %v", err)
	}
	if _, err := c.GetRepository(ctx, 7, "../../etc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad name = %v", err)
	}
	b, err := c.GetFile(ctx, 7, 99, ".kiln/pipeline.yaml", strings.Repeat("a", 40), 1024)
	if err != nil || string(b) != "version: 1\n" {
		t.Fatalf("file = %q %v", b, err)
	}
	if _, err := c.GetFile(ctx, 7, 99, ".kiln/pipeline.yaml", strings.Repeat("c", 40), 1024); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file = %v", err)
	}
	sha, err := c.ResolveBranch(ctx, 7, 99, "feature/x")
	if err != nil || sha != strings.Repeat("b", 40) {
		t.Fatalf("branch = %q %v", sha, err)
	}
	if err := c.CreateStatus(ctx, 7, 99, strings.Repeat("a", 40), Status{State: "success", Context: "kiln/web", Description: "Run #1 succeeded", TargetURL: "https://kiln.test/r"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.statuses) != 1 || f.statuses[0]["state"] != "success" || f.statuses[0]["context"] != "kiln/web" {
		t.Fatalf("statuses = %+v", f.statuses)
	}
}

func TestClient_ErrorsNeverEchoResponses(t *testing.T) {
	c, _ := newTestClient(t)
	_, err := c.GetFile(t.Context(), 7, 500, "x", strings.Repeat("a", 40), 10)
	if err == nil || strings.Contains(err.Error(), "ghs_") || strings.Contains(err.Error(), "internal detail") {
		t.Fatalf("error leaks response data: %v", err)
	}
}

func TestNew_Validation(t *testing.T) {
	if _, err := New(Options{AppID: 1, PrivateKey: []byte("x"), HTTP: http.DefaultClient}); err == nil {
		t.Fatal("garbage key accepted")
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := New(Options{AppID: 1, PrivateKey: p, HTTP: http.DefaultClient, APIURL: "http://github.example.com"}); err == nil {
		t.Fatal("http API URL accepted")
	}
	if _, err := New(Options{AppID: 1, PrivateKey: p, HTTP: http.DefaultClient}); err != nil {
		t.Fatalf("PKCS#8 key rejected: %v", err)
	}
	if _, err := New(Options{PrivateKey: p, HTTP: http.DefaultClient}); err == nil {
		t.Fatal("missing app ID accepted")
	}
}

func TestValidFullName(t *testing.T) {
	for _, ok := range []string{"acme/app", "a-b/c.d_e"} {
		if !ValidFullName(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"acme", "acme/app/x", "../x", "a/..", "-acme/app", "acme/"} {
		if ValidFullName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
