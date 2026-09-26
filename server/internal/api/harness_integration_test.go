// SPDX-License-Identifier: Apache-2.0

//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/api"
	"github.com/yamatrireddy/kilnci/server/internal/auth"
	"github.com/yamatrireddy/kilnci/server/internal/auth/authtest"
	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/platform/pki"
	"github.com/yamatrireddy/kilnci/server/internal/scheduler"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/service/orgs"
	"github.com/yamatrireddy/kilnci/server/internal/service/runners"
	"github.com/yamatrireddy/kilnci/server/internal/service/runs"
	"github.com/yamatrireddy/kilnci/server/internal/store"
	"github.com/yamatrireddy/kilnci/server/internal/store/storetest"
)

const origin = "https://kiln.test"

// clock is a controllable time source shared by all services in an env.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	t        *testing.T
	h        http.Handler
	rt       *api.Router
	st       *store.Store
	idp      *authtest.FakeIDP
	recorder *audit.Recorder
	runs     *runs.Service
	runners  *runners.Service
	clock    *clock
	// bootstrap is the instance admin's email for this env.
	bootstrap string
	// keys maps email -> IdP identity key, so re-login is the same person.
	keys map[string]string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := storetest.New(t)
	gen := ids.NewGenerator(nil)
	clk := &clock{t: time.Now().UTC()}
	idp := authtest.NewFakeIDP()
	az := authz.NewAuthorizer(st)
	rec := audit.NewRecorder(st, gen, clk.now)
	bootstrap := storetest.Unique("root") + "@kiln.test"
	authSvc := auth.NewService(st, idp, rec, az, gen, logging.Discard(), clk.now, auth.Options{
		PublicOrigin:           origin,
		SessionIdleTimeout:     time.Hour,
		SessionAbsoluteTimeout: 12 * time.Hour,
		AccessTokenTTL:         15 * time.Minute,
		RefreshTokenTTL:        30 * 24 * time.Hour,
		BootstrapAdminEmails:   []string{bootstrap},
	})
	orgSvc := orgs.NewService(st, az, rec, gen, clk.now)
	runSvc := runs.NewService(st, az, rec, scheduler.NewProgressor(st, clk.now), gen, clk.now)
	caDir := t.TempDir() + "/ca"
	if err := pki.Init(caDir, clk.now()); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.Load(caDir)
	if err != nil {
		t.Fatal(err)
	}
	runnerSvc := runners.NewService(st, az, rec, ca, gen, clk.now)
	h, rt, err := api.NewHandler(api.Deps{
		Log: logging.Discard(), IDs: gen, Authn: authSvc, Auth: authSvc, Orgs: orgSvc, Runs: runSvc, Runners: runnerSvc,
		Options: api.Options{
			MaxBodyBytes: 1 << 20,
			HSTS:         true,
			RateLimits:   api.RateLimits{PerIP: 1e6, AuthPerIP: 1e6, AuthFailuresPerIP: 1e6, PerPrincipal: 1e6},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, h: h, rt: rt, st: st, idp: idp, recorder: rec, runs: runSvc, runners: runnerSvc, clock: clk, bootstrap: bootstrap, keys: map[string]string{}}
}

// client is one caller: anonymous, a browser session, or a bearer token.
type client struct {
	session string
	csrf    string
	bearer  string
	userID  string
}

var anonymous = &client{}

type reqOpt func(*http.Request)

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

func (e *env) do(c *client, method, target, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequestWithContext(e.t.Context(), method, target, strings.NewReader(body))
	req.RemoteAddr = "203.0.113.10:4444"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.session != "" {
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: c.session, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		if method != http.MethodGet {
			req.Header.Set("Origin", origin)
			req.Header.Set(auth.CSRFHeader, c.csrf)
		}
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func cookieFrom(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %T: %v; body=%s", v, err, rec.Body)
	}
	return v
}

// identity registers a verified identity with the fake IdP and returns its key.
func (e *env) identity(email string) string {
	if key, ok := e.keys[email]; ok {
		return key
	}
	key := storetest.Unique("id")
	e.keys[email] = key
	e.idp.Register(key, auth.Claims{Issuer: "https://idp.test", Subject: key, Email: email, EmailVerified: true, Name: "User " + key})
	return key
}

// startLogin begins a login and returns the state and login cookie.
func (e *env) startLogin(query string) (state string, loginCookie *http.Cookie) {
	e.t.Helper()
	rec := e.do(anonymous, http.MethodGet, "/api/v1/auth/login?"+query, "")
	if rec.Code != http.StatusSeeOther {
		e.t.Fatalf("login start = %d %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		e.t.Fatal(err)
	}
	c := cookieFrom(rec, auth.LoginCookieName)
	if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		e.t.Fatalf("login cookie attributes wrong: %+v", c)
	}
	return loc.Query().Get("state"), c
}

// callback completes a login with the IdP code for key.
func (e *env) callback(key, state string, loginCookie *http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()
	q := url.Values{"state": {state}, "code": {key + "." + state}}
	var opts []reqOpt
	if loginCookie != nil {
		opts = append(opts, func(r *http.Request) { r.AddCookie(loginCookie) })
	}
	return e.do(anonymous, http.MethodGet, "/api/v1/auth/callback?"+q.Encode(), "", opts...)
}

// loginWeb signs in through the real web flow and returns a session client.
func (e *env) loginWeb(email string) *client {
	e.t.Helper()
	key := e.identity(email)
	state, lc := e.startLogin("client=web&returnTo=%2Forgs")
	rec := e.callback(key, state, lc)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/orgs" {
		e.t.Fatalf("callback = %d Location=%q", rec.Code, rec.Header().Get("Location"))
	}
	sc := cookieFrom(rec, auth.SessionCookieName)
	if sc == nil || !sc.HttpOnly || !sc.Secure || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" || sc.Domain != "" {
		e.t.Fatalf("session cookie attributes wrong: %+v", sc)
	}
	c := &client{session: sc.Value}
	s := e.do(c, http.MethodGet, "/api/v1/session", "")
	if s.Code != http.StatusOK {
		e.t.Fatalf("session = %d %s", s.Code, s.Body)
	}
	body := decode[struct {
		CsrfToken string `json:"csrfToken"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
	}](e.t, s)
	c.csrf, c.userID = body.CsrfToken, body.User.ID
	return c
}

func (e *env) mustStatus(rec *httptest.ResponseRecorder, want int) {
	e.t.Helper()
	if rec.Code != want {
		e.t.Fatalf("status = %d, want %d; body=%s", rec.Code, want, rec.Body)
	}
}
