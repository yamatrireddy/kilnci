// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
)

// fakeAuthn returns a fixed principal or error.
type fakeAuthn struct {
	p   *authz.Principal
	err error
}

func (f fakeAuthn) Authenticate(*http.Request) (*authz.Principal, error) { return f.p, f.err }

func testDeps(t *testing.T, logBuf *bytes.Buffer) Deps {
	t.Helper()
	log := logging.Discard()
	if logBuf != nil {
		log = logging.New(logBuf, logging.Options{Level: slog.LevelDebug, Format: "json"})
	}
	return Deps{
		Log:     log,
		IDs:     ids.NewGenerator(nil),
		Options: Options{MaxBodyBytes: 1024, AllowedOrigins: []string{"tauri://localhost"}, HSTS: true},
	}
}

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) Problem {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want problem+json; body=%s", ct, rec.Body)
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if p.RequestID == "" {
		t.Error("problem has no requestId")
	}
	return p
}

// newTestHandler builds the full middleware chain around a router with extra routes.
func newTestHandler(t *testing.T, d Deps, register func(rt *Router)) http.Handler {
	t.Helper()
	s := &server{log: d.Log, checks: d.Checks, errs: errorWriter{log: d.Log}, ips: clientIPResolver{trusted: d.Options.TrustedProxies}}
	rt := newRouter(d.Authn, s.errs)
	rt.Handle(http.MethodGet, "/healthz", authz.PermissionPublic, healthz)
	rt.Handle(http.MethodGet, "/readyz", authz.PermissionPublic, s.readyz)
	if register != nil {
		register(rt)
	}
	h, err := rt.build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return chain(h, recoverer(d.Log), requestID(d.IDs, s.ips), tracing(), accessLog(d.Log, s.ips),
		securityHeaders(d.Options.HSTS), cors(d.Options.AllowedOrigins), bodyLimit(d.Options.MaxBodyBytes))
}

func do(h http.Handler, method, target string, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func ok(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"ok": "yes"})
}

func TestNewHandler_ServesHealth(t *testing.T) {
	d := testDeps(t, nil)
	d.Checks = map[string]ReadinessCheck{"db": func(context.Context) error { return nil }}
	h, rt, err := NewHandler(d)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if rec := do(h, "GET", "/healthz", "", nil); rec.Code != 200 {
		t.Fatalf("healthz = %d", rec.Code)
	}
	rec := do(h, "GET", "/readyz", "", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"db":"ok"`) {
		t.Fatalf("readyz = %d %s", rec.Code, rec.Body)
	}
	if len(rt.Routes()) != 2 {
		t.Fatalf("Routes() = %v", rt.Routes())
	}
}

func TestNewHandler_RequiresDeps(t *testing.T) {
	if _, _, err := NewHandler(Deps{}); err == nil {
		t.Fatal("want error for missing deps")
	}
	d := testDeps(t, nil)
	d.Options.MaxBodyBytes = 0
	if _, _, err := NewHandler(d); err == nil {
		t.Fatal("want error for zero body limit")
	}
}

func TestReadyz_FailingCheck_Returns503WithoutDetails(t *testing.T) {
	var logs bytes.Buffer
	d := testDeps(t, &logs)
	d.Checks = map[string]ReadinessCheck{
		"db":    func(context.Context) error { return errors.New("dial tcp 10.0.0.5:5432: secret-internal-detail") },
		"cache": func(context.Context) error { return nil },
	}
	h := newTestHandler(t, d, nil)
	rec := do(h, "GET", "/readyz", "", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret-internal-detail") {
		t.Fatal("readiness response leaks internal error")
	}
	if !strings.Contains(logs.String(), "secret-internal-detail") {
		t.Fatal("readiness failure detail should be logged server-side")
	}
}

func TestRouter_RejectsUnsafeRegistrations(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		pattern  string
		perm     authz.Action
		h        http.HandlerFunc
		wantText string
	}{
		{"no permission", "GET", "/api/v1/x", "", ok, "no permission"},
		{"unknown permission", "GET", "/api/v1/x", "things:do", ok, "unknown permission"},
		{"public on arbitrary route", "GET", "/api/v1/orgs", authz.PermissionPublic, ok, "public access"},
		{"public on wrong method", "POST", "/healthz", authz.PermissionPublic, ok, "public access"},
		{"public on bare webhook prefix", "POST", "/api/v1/webhooks/", authz.PermissionPublic, ok, "public access"},
		{"preauth on arbitrary route", "GET", "/api/v1/orgs", authz.PermissionPreAuth, ok, "pre-auth"},
		{"nil handler", "GET", "/api/v1/orgs", authz.ActionOrgsList, nil, "nil handler"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := newRouter(nil, errorWriter{log: logging.Discard()})
			rt.Handle(tt.method, tt.pattern, tt.perm, tt.h)
			_, err := rt.build()
			if err == nil || !strings.Contains(err.Error(), tt.wantText) {
				t.Fatalf("build err = %v, want %q", err, tt.wantText)
			}
		})
	}
}

func TestRouter_RejectsDuplicateRoute(t *testing.T) {
	rt := newRouter(nil, errorWriter{log: logging.Discard()})
	rt.Handle("GET", "/api/v1/orgs", authz.ActionOrgsList, ok)
	rt.Handle("GET", "/api/v1/orgs", authz.ActionOrgsList, ok)
	if _, err := rt.build(); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("want duplicate error, got %v", err)
	}
}

func TestRouter_AllowsWebhookPrefixAndPreAuthAllowlist(t *testing.T) {
	rt := newRouter(nil, errorWriter{log: logging.Discard()})
	rt.Handle("POST", "/api/v1/webhooks/github", authz.PermissionPublic, ok)
	rt.Handle("GET", "/api/v1/auth/login", authz.PermissionPreAuth, ok)
	if _, err := rt.build(); err != nil {
		t.Fatalf("build: %v", err)
	}
}

func TestRouter_DenyByDefault(t *testing.T) {
	user := &authz.Principal{Kind: authz.KindUser, UserID: "u1"}
	scoped := &authz.Principal{Kind: authz.KindAPIToken, UserID: "u1", Scopes: []authz.Action{authz.ActionProjectsRead}}
	tests := []struct {
		name       string
		authn      Authenticator
		wantStatus int
		wantType   string
	}{
		{"no authenticator configured", nil, 401, ProblemUnauthenticated},
		{"no credentials", fakeAuthn{}, 401, ProblemUnauthenticated},
		{"invalid credentials", fakeAuthn{err: fmt.Errorf("session expired: %w", domain.ErrUnauthenticated)}, 401, ProblemUnauthenticated},
		{"csrf failure", fakeAuthn{err: domain.ErrForbidden}, 403, ProblemForbidden},
		{"token scope excludes action", fakeAuthn{p: scoped}, 403, ProblemForbidden},
		{"authenticated", fakeAuthn{p: user}, 200, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := testDeps(t, nil)
			d.Authn = tt.authn
			var seen *authz.Principal
			h := newTestHandler(t, d, func(rt *Router) {
				rt.Handle("GET", "/api/v1/orgs", authz.ActionOrgsList, func(w http.ResponseWriter, r *http.Request) {
					seen, _ = authz.FromContext(r.Context())
					ok(w, r)
				})
			})
			rec := do(h, "GET", "/api/v1/orgs", "", nil)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantType != "" {
				if p := decodeProblem(t, rec); p.Type != tt.wantType {
					t.Fatalf("type = %q, want %q", p.Type, tt.wantType)
				}
				if seen != nil {
					t.Fatal("handler ran for a denied request")
				}
			} else if seen == nil {
				t.Fatal("principal not in handler context")
			}
			if tt.wantStatus == 401 && rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("401 without WWW-Authenticate")
			}
		})
	}
}

func TestRouter_UnknownPathAndMethod(t *testing.T) {
	h := newTestHandler(t, testDeps(t, nil), nil)

	rec := do(h, "GET", "/nope", "", nil)
	if rec.Code != 404 || decodeProblem(t, rec).Type != ProblemNotFound {
		t.Fatalf("unknown path = %d %s", rec.Code, rec.Body)
	}
	rec = do(h, "DELETE", "/healthz", "", nil)
	if rec.Code != 405 || decodeProblem(t, rec).Type != ProblemMethodNotAllowed {
		t.Fatalf("wrong method = %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Allow") != "GET" {
		t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
	}
}

func TestErrorWriter_MapsDomainErrors(t *testing.T) {
	tests := []struct {
		err    error
		status int
		typ    string
	}{
		{fmt.Errorf("get org: %w", domain.ErrNotFound), 404, ProblemNotFound},
		{domain.ErrConflict, 409, ProblemConflict},
		{domain.NewValidationError("slug", "bad"), 422, ProblemValidation},
		{domain.ErrForbidden, 403, ProblemForbidden},
		{domain.ErrRateLimited, 429, ProblemRateLimited},
		{domain.ErrPreconditionFailed, 412, ProblemPreconditionFailed},
		{&http.MaxBytesError{Limit: 1}, 413, ProblemPayloadTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			d := testDeps(t, nil)
			d.Authn = fakeAuthn{p: &authz.Principal{UserID: "u"}}
			h := newTestHandler(t, d, func(rt *Router) {
				rt.Handle("GET", "/api/v1/orgs", authz.ActionOrgsList, func(w http.ResponseWriter, r *http.Request) {
					errorWriter{log: d.Log}.write(w, r, tt.err)
				})
			})
			rec := do(h, "GET", "/api/v1/orgs", "", nil)
			p := decodeProblem(t, rec)
			if rec.Code != tt.status || p.Type != tt.typ || p.Status != tt.status {
				t.Fatalf("got %d %+v, want %d %s", rec.Code, p, tt.status, tt.typ)
			}
			if tt.typ == ProblemValidation && (len(p.Errors) != 1 || p.Errors[0].Field != "slug") {
				t.Fatalf("validation fields not returned: %+v", p.Errors)
			}
		})
	}
}

func TestErrorWriter_UnexpectedErrorIsGenericAndLoggedOnce(t *testing.T) {
	var logs bytes.Buffer
	d := testDeps(t, &logs)
	d.Authn = fakeAuthn{p: &authz.Principal{UserID: "u"}}
	h := newTestHandler(t, d, func(rt *Router) {
		rt.Handle("GET", "/api/v1/orgs", authz.ActionOrgsList, func(w http.ResponseWriter, r *http.Request) {
			errorWriter{log: d.Log}.write(w, r, errors.New(`pq: relation "orgs" does not exist at /srv/kiln/store.go:42`))
		})
	})
	rec := do(h, "GET", "/api/v1/orgs", "", nil)
	p := decodeProblem(t, rec)
	if rec.Code != 500 || p.Type != ProblemInternal {
		t.Fatalf("got %d %+v", rec.Code, p)
	}
	if strings.Contains(rec.Body.String(), "relation") || strings.Contains(rec.Body.String(), "store.go") {
		t.Fatal("internal details leaked to client")
	}
	if n := strings.Count(logs.String(), `"msg":"request failed"`); n != 1 {
		t.Fatalf("error logged %d times, want 1", n)
	}
	if !strings.Contains(logs.String(), `"route":"/api/v1/orgs"`) {
		t.Fatalf("log missing route: %s", logs.String())
	}
}

func TestRecoverer_PanicReturnsGeneric500(t *testing.T) {
	var logs bytes.Buffer
	d := testDeps(t, &logs)
	d.Authn = fakeAuthn{p: &authz.Principal{UserID: "u"}}
	h := newTestHandler(t, d, func(rt *Router) {
		rt.Handle("GET", "/api/v1/orgs", authz.ActionOrgsList, func(http.ResponseWriter, *http.Request) {
			panic("boom: internal state")
		})
	})
	rec := do(h, "GET", "/api/v1/orgs", "", nil)
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "boom") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(logs.String(), "boom") {
		t.Fatal("panic not logged")
	}
}

func TestRequestID(t *testing.T) {
	h := newTestHandler(t, testDeps(t, nil), nil)

	rec := do(h, "GET", "/healthz", "", nil)
	if !ids.Valid(rec.Header().Get("X-Request-Id")) {
		t.Fatalf("generated request id %q", rec.Header().Get("X-Request-Id"))
	}
	rec = do(h, "GET", "/healthz", "", map[string]string{"X-Request-Id": "edge-abc-12345"})
	if rec.Header().Get("X-Request-Id") == "edge-abc-12345" {
		t.Fatal("request id from an untrusted peer was kept")
	}
	trusted := testDeps(t, nil)
	trusted.Options.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")} // httptest RemoteAddr
	rec = do(newTestHandler(t, trusted, nil), "GET", "/healthz", "", map[string]string{"X-Request-Id": "edge-abc-12345"})
	if rec.Header().Get("X-Request-Id") != "edge-abc-12345" {
		t.Fatal("well-formed request id from a trusted proxy not kept")
	}
	for _, bad := range []string{"short", "has space in it", "inject\r\nX-Evil: 1", strings.Repeat("a", 65)} {
		rec = do(h, "GET", "/healthz", "", map[string]string{"X-Request-Id": bad})
		if rec.Header().Get("X-Request-Id") == bad {
			t.Fatalf("malformed request id %q echoed", bad)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newTestHandler(t, testDeps(t, nil), nil)
	for _, target := range []string{"/healthz", "/nope"} {
		rec := do(h, "GET", target, "", nil)
		want := map[string]string{
			"Content-Security-Policy":   apiCSP,
			"X-Content-Type-Options":    "nosniff",
			"Referrer-Policy":           "strict-origin-when-cross-origin",
			"X-Frame-Options":           "DENY",
			"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
			"Cache-Control":             "no-store",
		}
		for k, v := range want {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s %s = %q, want %q", target, k, got, v)
			}
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Error("CSP missing frame-ancestors")
		}
	}
}

func TestSecurityHeaders_NoHSTSWhenDisabled(t *testing.T) {
	d := testDeps(t, nil)
	d.Options.HSTS = false
	rec := do(newTestHandler(t, d, nil), "GET", "/healthz", "", nil)
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS sent over plain HTTP config")
	}
}

func TestCORS(t *testing.T) {
	h := newTestHandler(t, testDeps(t, nil), nil)

	rec := do(h, "GET", "/healthz", "", map[string]string{"Origin": "tauri://localhost"})
	if rec.Header().Get("Access-Control-Allow-Origin") != "tauri://localhost" {
		t.Fatal("allowed origin not echoed")
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("credentials must never be allowed cross-origin")
	}

	rec = do(h, "GET", "/healthz", "", map[string]string{"Origin": "https://evil.example"})
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("disallowed origin granted CORS")
	}

	rec = do(h, "OPTIONS", "/api/v1/orgs", "", map[string]string{"Origin": "tauri://localhost", "Access-Control-Request-Method": "POST"})
	if rec.Code != 204 || !strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("preflight = %d %v", rec.Code, rec.Header())
	}

	rec = do(h, "OPTIONS", "/api/v1/orgs", "", map[string]string{"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
	if rec.Code == 204 || rec.Header().Get("Access-Control-Allow-Methods") != "" {
		t.Fatalf("preflight from disallowed origin succeeded: %d", rec.Code)
	}
}

func TestBodyLimit(t *testing.T) {
	d := testDeps(t, nil)
	d.Authn = fakeAuthn{p: &authz.Principal{UserID: "u"}}
	var decodeErr error
	h := newTestHandler(t, d, func(rt *Router) {
		rt.Handle("POST", "/api/v1/orgs", authz.ActionOrgsCreate, func(w http.ResponseWriter, r *http.Request) {
			var v map[string]any
			if decodeErr = decodeJSON(r, &v); decodeErr != nil {
				errorWriter{log: d.Log}.write(w, r, decodeErr)
				return
			}
			ok(w, r)
		})
	})
	big := `{"name":"` + strings.Repeat("a", 2000) + `"}`

	rec := do(h, "POST", "/api/v1/orgs", big, map[string]string{"Content-Type": "application/json"})
	if rec.Code != 413 {
		t.Fatalf("declared oversize body = %d", rec.Code)
	}

	// Chunked body with no Content-Length is cut off by MaxBytesReader.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/orgs", strings.NewReader(big))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 413 {
		t.Fatalf("streamed oversize body = %d %s", rec.Code, rec.Body)
	}
}

func TestDecodeJSON(t *testing.T) {
	type in struct {
		Name string `json:"name"`
	}
	tests := []struct {
		name, ct, body string
		ok             bool
	}{
		{"valid", "application/json", `{"name":"a"}`, true},
		{"valid with charset", "application/json; charset=utf-8", `{"name":"a"}`, true},
		{"wrong content type", "text/plain", `{"name":"a"}`, false},
		{"unknown field", "application/json", `{"name":"a","admin":true}`, false},
		{"trailing data", "application/json", `{"name":"a"}{"name":"b"}`, false},
		{"malformed", "application/json", `{"name":`, false},
		{"wrong type", "application/json", `{"name":1}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(tt.body))
			r.Header.Set("Content-Type", tt.ct)
			var v in
			err := decodeJSON(r, &v)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("decode error is not a validation error: %v", err)
			}
		})
	}
}

func TestAccessLog_NeverLogsQueryString(t *testing.T) {
	var logs bytes.Buffer
	h := newTestHandler(t, testDeps(t, &logs), nil)
	do(h, "GET", "/healthz?code=fake-auth-code&state=xyz", "", nil)
	if strings.Contains(logs.String(), "fake-auth-code") {
		t.Fatalf("query string logged: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `"route":"/healthz"`) {
		t.Fatalf("route not logged: %s", logs.String())
	}
}

func TestClientIP(t *testing.T) {
	trusted := clientIPResolver{trusted: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	untrusted := clientIPResolver{}
	tests := []struct {
		name   string
		res    clientIPResolver
		remote string
		xff    string
		want   string
	}{
		{"direct client", untrusted, "203.0.113.9:5555", "", "203.0.113.9"},
		{"spoofed xff from untrusted peer ignored", untrusted, "203.0.113.9:5555", "1.2.3.4", "203.0.113.9"},
		{"trusted proxy", trusted, "10.0.0.2:80", "198.51.100.7", "198.51.100.7"},
		{"client-prepended spoof ignored", trusted, "10.0.0.2:80", "1.2.3.4, 198.51.100.7", "198.51.100.7"},
		{"proxy chain", trusted, "10.0.0.2:80", "198.51.100.7, 10.0.0.9", "198.51.100.7"},
		{"garbage xff", trusted, "10.0.0.2:80", "not-an-ip", "10.0.0.2"},
		{"all trusted", trusted, "10.0.0.2:80", "10.0.0.3", "10.0.0.3"},
		{"ipv4-mapped peer", untrusted, "[::ffff:203.0.113.9]:1", "", "203.0.113.9"},
		{"bad remote", untrusted, "garbage", "", "invalid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := tt.res.resolve(r).String(); got != tt.want {
				t.Fatalf("resolve = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSpecValidator_RejectsInvalidInputWithoutEchoingIt(t *testing.T) {
	spec, err := loadSpec()
	if err != nil {
		t.Fatal(err)
	}
	v, err := newSpecValidator(spec)
	if err != nil {
		t.Fatal(err)
	}
	d := testDeps(t, nil)
	d.Authn = fakeAuthn{p: &authz.Principal{UserID: "u"}}
	h := newTestHandler(t, d, func(rt *Router) {
		rt.validate = v.validate
		rt.Handle(http.MethodPost, "/api/v1/orgs", authz.ActionOrgsCreate, ok)
		rt.Handle(http.MethodGet, "/api/v1/orgs/{orgSlug}", authz.ActionOrgsRead, ok)
		rt.Handle(http.MethodGet, "/api/v1/orgs", authz.ActionOrgsList, ok)
		rt.Handle(http.MethodGet, "/api/v1/not-in-spec", authz.ActionOrgsList, ok)
	})
	json := map[string]string{"Content-Type": "application/json"}
	tests := []struct {
		name, method, target, body string
		hdr                        map[string]string
		want                       int
		field                      string
	}{
		{"valid create", "POST", "/api/v1/orgs", `{"slug":"acme","name":"Acme"}`, json, 200, ""},
		{"unknown field (mass assignment)", "POST", "/api/v1/orgs", `{"slug":"acme","name":"Acme","owner":"x"}`, json, 422, "body"},
		{"bad slug", "POST", "/api/v1/orgs", `{"slug":"<script>","name":"Acme"}`, json, 422, "body"},
		{"missing field", "POST", "/api/v1/orgs", `{"slug":"acme"}`, json, 422, "body"},
		{"bad path param", "GET", "/api/v1/orgs/UPPER_case", "", nil, 422, "orgSlug"},
		{"limit too large", "GET", "/api/v1/orgs?limit=1000", "", nil, 422, "limit"},
		{"bad cursor", "GET", "/api/v1/orgs?cursor=%27%20OR%201=1", "", nil, 422, "cursor"},
		{"valid list", "GET", "/api/v1/orgs?limit=10", "", nil, 200, ""},
		{"route missing from spec fails closed", "GET", "/api/v1/not-in-spec", "", nil, 500, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(h, tt.method, tt.target, tt.body, tt.hdr)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body)
			}
			if strings.Contains(rec.Body.String(), "<script>") || strings.Contains(rec.Body.String(), "OR 1=1") {
				t.Fatal("rejected input echoed in response")
			}
			if tt.field != "" {
				p := decodeProblem(t, rec)
				if len(p.Errors) == 0 || p.Errors[0].Field != tt.field {
					t.Fatalf("errors = %+v, want field %q", p.Errors, tt.field)
				}
			}
		})
	}
}
