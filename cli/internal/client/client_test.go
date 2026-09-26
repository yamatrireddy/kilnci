// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "kiln_pat_test"

func newClient(t *testing.T, srv *httptest.Server, path string) *Client {
	t.Helper()
	u, err := url.Parse(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(u, testToken, Options{Transport: srv.Client().Transport, UserAgent: "kiln-cli/test"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLint_SendsAuthenticatedRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/prefix/api/v1/pipelines/lint" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("Authorization = %q", got)
		}
		if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("User-Agent") != "kiln-cli/test" {
			t.Errorf("headers %v", r.Header)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["pipeline"] != "version: 1\n" || len(body) != 1 {
			t.Errorf("body %v %v", body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"valid":false,"problems":[{"path":"jobs","line":2,"message":"is required"}]}`)
	}))
	defer srv.Close()
	res, err := newClient(t, srv, "/prefix").Lint(t.Context(), "version: 1\n")
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || len(res.Problems) != 1 || res.Problems[0] != (LintProblem{Path: "jobs", Line: 2, Message: "is required"}) {
		t.Fatalf("result %+v", res)
	}
}

func TestLint_Errors(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		header      map[string]string
		body        string
		wantErr     string
		wantStatus  int
	}{
		{name: "unauthenticated", status: 401, contentType: "application/problem+json",
			body:    `{"type":"about:blank","title":"Unauthenticated","status":401,"requestId":"req1"}`,
			wantErr: "401 Unauthenticated (check the token", wantStatus: 401},
		{name: "forbidden", status: 403, contentType: "application/problem+json",
			body: `{"title":"Forbidden","status":403}`, wantErr: "pipelines:lint scope", wantStatus: 403},
		{name: "validation", status: 422, contentType: "application/problem+json; charset=utf-8",
			body:    `{"title":"Validation failed","status":422,"detail":"bad body","errors":[{"field":"pipeline","message":"too long"}]}`,
			wantErr: "422 Validation failed: bad body; pipeline: too long", wantStatus: 422},
		{name: "rate limited", status: 429, contentType: "application/problem+json", header: map[string]string{"Retry-After": "60"},
			body: `{"title":"Too many requests","status":429}`, wantErr: "retry after 1m0s", wantStatus: 429},
		{name: "plain error page", status: 502, contentType: "text/html", body: "<html>bad gateway</html>",
			wantErr: "502 Bad Gateway", wantStatus: 502},
		{name: "redirect not followed", status: 302, header: map[string]string{"Location": "https://evil.example.com/"},
			wantErr: "redirects are not followed", wantStatus: 302},
		{name: "non-json success", status: 200, contentType: "text/html", body: "<html></html>", wantErr: "non-JSON"},
		{name: "malformed json", status: 200, contentType: "application/json", body: "{", wantErr: "decode response"},
		{name: "inconsistent", status: 200, contentType: "application/json", body: `{"valid":true,"problems":[{"path":"a","line":1,"message":"x"}]}`,
			wantErr: "inconsistent"},
		{name: "oversized", status: 200, contentType: "application/json", body: `{"valid":true,"problems":[],"x":"` + strings.Repeat("a", maxResponseBytes) + `"}`,
			wantErr: "exceeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.contentType != "" {
					w.Header().Set("Content-Type", tt.contentType)
				}
				for k, v := range tt.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer srv.Close()
			_, err := newClient(t, srv, "").Lint(t.Context(), "version: 1")
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), testToken) {
				t.Fatalf("error leaks the token: %v", err)
			}
			var apiErr *APIError
			if tt.wantStatus != 0 && (!errors.As(err, &apiErr) || apiErr.Status != tt.wantStatus) {
				t.Fatalf("err = %#v, want APIError %d", err, tt.wantStatus)
			}
		})
	}
}

func TestLint_RedirectDoesNotSendToken(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	if _, err := newClient(t, srv, "").Lint(t.Context(), "version: 1"); err == nil {
		t.Fatal("redirect succeeded")
	}
	if hits.Load() != 0 {
		t.Fatal("client followed the redirect")
	}
}

func TestLint_RequestIsNotHTMLEscaped(t *testing.T) {
	var size atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		size.Store(n)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"valid":true,"problems":[]}`)
	}))
	defer srv.Close()
	source := strings.Repeat("<", 256<<10)
	if _, err := newClient(t, srv, "").Lint(t.Context(), source); err != nil {
		t.Fatal(err)
	}
	if n := size.Load(); n > int64(len(source))+64 {
		t.Fatalf("request body %d bytes for a %d-byte pipeline", n, len(source))
	}
}

func TestLint_Timeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	u, _ := url.Parse(srv.URL)
	c, err := New(u, testToken, Options{Transport: srv.Client().Transport, Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lint(t.Context(), "version: 1"); err == nil {
		t.Fatal("no timeout")
	}
}

func TestLint_CanceledContext(t *testing.T) {
	u, _ := url.Parse("https://kiln.invalid")
	c, err := New(u, testToken, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.Lint(ctx, "version: 1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestNew_RequiresServerAndToken(t *testing.T) {
	u, _ := url.Parse("https://kiln.example.com")
	if _, err := New(nil, testToken, Options{}); err == nil {
		t.Fatal("nil server accepted")
	}
	if _, err := New(u, "", Options{}); err == nil {
		t.Fatal("empty token accepted")
	}
	c, err := New(u, testToken, Options{})
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig.MinVersion < 0x0303 || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("transport TLS config %+v", tr.TLSClientConfig)
	}
	if c.http.Timeout != DefaultTimeout {
		t.Fatalf("timeout %v", c.http.Timeout)
	}
}
