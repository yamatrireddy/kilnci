// SPDX-License-Identifier: Apache-2.0

//go:build integration

package api_test

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/auth"
	"github.com/yamatrireddy/kilnci/server/internal/store/storetest"
)

func TestWebLogin_RequiresBrowserBindingCookie(t *testing.T) {
	e := newEnv(t)
	key := e.identity(e.bootstrap)
	state, _ := e.startLogin("client=web")
	// An attacker who starts a login and sends the victim the callback URL
	// has no way to plant the victim's __Host- login cookie.
	rec := e.callback(key, state, nil)
	e.mustStatus(rec, http.StatusSeeOther)
	if rec.Header().Get("Location") != "/signin?error=failed" || cookieFrom(rec, auth.SessionCookieName) != nil {
		t.Fatalf("login without binding cookie succeeded: %v", rec.Header())
	}
	// A cookie for a different login does not help either.
	_, otherCookie := e.startLogin("client=web")
	rec = e.callback(key, state, otherCookie)
	if cookieFrom(rec, auth.SessionCookieName) != nil {
		t.Fatal("login with mismatched binding cookie succeeded")
	}
}

func TestWebLogin_StateIsSingleUseAndExpires(t *testing.T) {
	e := newEnv(t)
	key := e.identity(e.bootstrap)
	state, lc := e.startLogin("client=web")
	if rec := e.callback(key, state, lc); cookieFrom(rec, auth.SessionCookieName) == nil {
		t.Fatal("first callback failed")
	}
	if rec := e.callback(key, state, lc); cookieFrom(rec, auth.SessionCookieName) != nil {
		t.Fatal("login state replayed")
	}

	state, lc = e.startLogin("client=web")
	e.clock.advance(11 * time.Minute)
	if rec := e.callback(key, state, lc); cookieFrom(rec, auth.SessionCookieName) != nil {
		t.Fatal("expired login state accepted")
	}
}

func TestWebLogin_IdPErrorAndBadCode(t *testing.T) {
	e := newEnv(t)
	state, lc := e.startLogin("client=web")
	q := url.Values{"state": {state}, "error": {"access_denied"}}
	rec := e.do(anonymous, http.MethodGet, "/api/v1/auth/callback?"+q.Encode(), "", func(r *http.Request) { r.AddCookie(lc) })
	if rec.Header().Get("Location") != "/signin?error=failed" {
		t.Fatalf("IdP error not handled: %v", rec.Header())
	}
	state, lc = e.startLogin("client=web")
	if rec := e.callback("unknown-identity", state, lc); rec.Header().Get("Location") != "/signin?error=failed" {
		t.Fatalf("bad code: %v", rec.Header())
	}
}

func TestWebLogin_ReturnToCannotRedirectOffSite(t *testing.T) {
	e := newEnv(t)
	// The spec pattern rejects off-site targets before the service sees them;
	// safeReturnTo is the second layer (see auth.TestSafeReturnTo_*).
	for _, rt := range []string{"//evil.example/x", "https://evil.example", "/\\evil.example", "javascript:alert(1)"} {
		rec := e.do(anonymous, http.MethodGet, "/api/v1/auth/login?client=web&returnTo="+url.QueryEscape(rt), "")
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("returnTo %q: status %d, Location %q", rt, rec.Code, rec.Header().Get("Location"))
		}
	}
	key := e.identity(e.bootstrap)
	for _, rt := range []string{"/", "/orgs/acme?tab=members"} {
		state, lc := e.startLogin("client=web&returnTo=" + url.QueryEscape(rt))
		if loc := e.callback(key, state, lc).Header().Get("Location"); loc != rt {
			t.Fatalf("same-origin returnTo %q lost: %q", rt, loc)
		}
	}
}

func TestWebLogin_NotInvitedIsRejectedAndAudited(t *testing.T) {
	e := newEnv(t)
	key := e.identity(storetest.Unique("stranger") + "@kiln.test")
	state, lc := e.startLogin("client=web")
	rec := e.callback(key, state, lc)
	if rec.Header().Get("Location") != "/signin?error=not_invited" || cookieFrom(rec, auth.SessionCookieName) != nil {
		t.Fatalf("uninvited user signed in: %v", rec.Header())
	}
	if err := e.recorder.VerifyChain(t.Context(), ""); err != nil {
		t.Fatalf("instance audit chain: %v", err)
	}
}

func TestWebLogin_UnverifiedEmailRejected(t *testing.T) {
	e := newEnv(t)
	key := storetest.Unique("id")
	e.idp.Register(key, auth.Claims{Issuer: "https://idp.test", Subject: key, Email: e.bootstrap, EmailVerified: false})
	state, lc := e.startLogin("client=web")
	if rec := e.callback(key, state, lc); cookieFrom(rec, auth.SessionCookieName) != nil {
		t.Fatal("unverified email signed in")
	}
}

func TestWebLogin_StartValidatesClient(t *testing.T) {
	e := newEnv(t)
	for _, q := range []string{
		"client=mobile",
		"client=desktop", // missing PKCE params
		"client=desktop&redirectUri=http%3A%2F%2Fevil.example%2Fcallback&codeChallenge=" + strings.Repeat("a", 43) + "&state=" + strings.Repeat("s", 20),
	} {
		rec := e.do(anonymous, http.MethodGet, "/api/v1/auth/login?"+q, "")
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d", q, rec.Code)
		}
	}
}

func TestSession_CSRFAndOriginChecks(t *testing.T) {
	e := newEnv(t)
	root := e.loginWeb(e.bootstrap)
	body := fmt.Sprintf(`{"slug":%q,"name":"X"}`, storetest.Unique("c"))

	noToken := func(r *http.Request) { r.Header.Del(auth.CSRFHeader) }
	e.mustStatus(e.do(root, http.MethodPost, "/api/v1/orgs", body, noToken), http.StatusForbidden)

	wrongToken := withHeader(auth.CSRFHeader, strings.Repeat("A", 43))
	e.mustStatus(e.do(root, http.MethodPost, "/api/v1/orgs", body, wrongToken), http.StatusForbidden)

	crossSite := withHeader("Origin", "https://evil.example")
	e.mustStatus(e.do(root, http.MethodPost, "/api/v1/orgs", body, crossSite), http.StatusForbidden)

	e.mustStatus(e.do(root, http.MethodPost, "/api/v1/orgs", body), http.StatusCreated)

	// Another session's CSRF token does not work for this session.
	other := e.loginWeb(e.bootstrap)
	stolen := withHeader(auth.CSRFHeader, other.csrf)
	e.mustStatus(e.do(root, http.MethodPost, "/api/v1/orgs", fmt.Sprintf(`{"slug":%q,"name":"X"}`, storetest.Unique("c")), stolen), http.StatusForbidden)
}

func TestSession_Timeouts(t *testing.T) {
	e := newEnv(t)
	c := e.loginWeb(e.bootstrap)
	e.clock.advance(59 * time.Minute)
	e.mustStatus(e.do(c, http.MethodGet, "/api/v1/session", ""), http.StatusOK)
	e.clock.advance(61 * time.Minute) // idle for over an hour
	e.mustStatus(e.do(c, http.MethodGet, "/api/v1/session", ""), http.StatusUnauthorized)

	c = e.loginWeb(e.bootstrap)
	for range 13 { // stay active, but exceed the 12h absolute timeout
		e.clock.advance(59 * time.Minute)
		e.do(c, http.MethodGet, "/api/v1/session", "")
	}
	e.mustStatus(e.do(c, http.MethodGet, "/api/v1/session", ""), http.StatusUnauthorized)
}

func TestSession_TamperedAndForeignCredentials(t *testing.T) {
	e := newEnv(t)
	c := e.loginWeb(e.bootstrap)
	forged := &client{session: c.session[:len(c.session)-2] + "xx"}
	e.mustStatus(e.do(forged, http.MethodGet, "/api/v1/session", ""), http.StatusUnauthorized)
	for _, h := range []string{"Basic dXNlcjpwYXNz", "Bearer kiln_pat_nope", "Bearer " + strings.Repeat("x", 50), "Bearer kiln_at_" + strings.Repeat("A", 43)} {
		e.mustStatus(e.do(anonymous, http.MethodGet, "/api/v1/session", "", withHeader("Authorization", h)), http.StatusUnauthorized)
	}
}

func TestLogout_RevokesSession(t *testing.T) {
	e := newEnv(t)
	c := e.loginWeb(e.bootstrap)
	rec := e.do(c, http.MethodDelete, "/api/v1/session", "")
	e.mustStatus(rec, http.StatusNoContent)
	if sc := cookieFrom(rec, auth.SessionCookieName); sc == nil || sc.MaxAge >= 0 {
		t.Fatalf("session cookie not cleared: %+v", sc)
	}
	e.mustStatus(e.do(c, http.MethodGet, "/api/v1/session", ""), http.StatusUnauthorized)
	e.mustStatus(e.do(anonymous, http.MethodDelete, "/api/v1/session", ""), http.StatusUnauthorized)
}

func pkce() (verifier, challenge string) {
	verifier = strings.Repeat("v", 20) + storetest.Unique("verifier") + strings.Repeat("x", 10)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

type tokenPair struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int    `json:"expiresIn"`
}

func TestDesktopFlow(t *testing.T) {
	e := newEnv(t)
	key := e.identity(e.bootstrap)
	verifier, challenge := pkce()
	redirectURI := "http://127.0.0.1:53682/callback"
	appState := strings.Repeat("s", 24)
	state, lc := e.startLogin(url.Values{
		"client": {"desktop"}, "redirectUri": {redirectURI}, "codeChallenge": {challenge}, "state": {appState},
	}.Encode())
	rec := e.callback(key, state, lc)
	e.mustStatus(rec, http.StatusSeeOther)
	if cookieFrom(rec, auth.SessionCookieName) != nil {
		t.Fatal("desktop login must not create a browser session")
	}
	start := e.do(anonymous, http.MethodGet, "/api/v1/auth/login?"+url.Values{
		"client": {"desktop"}, "redirectUri": {redirectURI}, "codeChallenge": {challenge}, "state": {appState},
	}.Encode(), "")
	if !strings.Contains(start.Header().Get("Location"), "prompt=login") {
		t.Fatalf("desktop login must force IdP re-authentication: %s", start.Header().Get("Location"))
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Scheme+"://"+loc.Host+loc.Path != redirectURI || loc.Query().Get("state") != appState {
		t.Fatalf("desktop redirect = %q", rec.Header().Get("Location"))
	}
	code := loc.Query().Get("code")

	exchange := func(body string) *httpResult {
		r := e.do(anonymous, http.MethodPost, "/api/v1/auth/token", body)
		return &httpResult{r.Code, r.Body.String()}
	}
	codeBody := func(c, v, ru string) string {
		return fmt.Sprintf(`{"grantType":"authorization_code","code":%q,"codeVerifier":%q,"redirectUri":%q}`, c, v, ru)
	}

	// Wrong verifier burns the code.
	wrongV, _ := pkce()
	if r := exchange(codeBody(code, wrongV, redirectURI)); r.code != http.StatusUnauthorized {
		t.Fatalf("wrong verifier = %d %s", r.code, r.body)
	}
	if r := exchange(codeBody(code, verifier, redirectURI)); r.code != http.StatusUnauthorized {
		t.Fatalf("burned code accepted: %d", r.code)
	}

	// A fresh login, redeemed correctly.
	state, lc = e.startLogin(url.Values{"client": {"desktop"}, "redirectUri": {redirectURI}, "codeChallenge": {challenge}, "state": {appState}}.Encode())
	loc, _ = url.Parse(e.callback(key, state, lc).Header().Get("Location"))
	code = loc.Query().Get("code")
	if r := exchange(codeBody(code, verifier, "http://127.0.0.1:9999/callback")); r.code != http.StatusUnauthorized {
		t.Fatalf("mismatched redirect_uri accepted: %d", r.code)
	}
	state, lc = e.startLogin(url.Values{"client": {"desktop"}, "redirectUri": {redirectURI}, "codeChallenge": {challenge}, "state": {appState}}.Encode())
	loc, _ = url.Parse(e.callback(key, state, lc).Header().Get("Location"))
	rec = e.do(anonymous, http.MethodPost, "/api/v1/auth/token", codeBody(loc.Query().Get("code"), verifier, redirectURI))
	e.mustStatus(rec, http.StatusOK)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token response cacheable")
	}
	pair := decode[tokenPair](t, rec)
	if !strings.HasPrefix(pair.AccessToken, auth.PrefixAccessToken) || !strings.HasPrefix(pair.RefreshToken, auth.PrefixRefreshToken) || pair.ExpiresIn != 900 {
		t.Fatalf("pair = %+v", pair)
	}

	desk := &client{bearer: pair.AccessToken}
	sess := e.do(desk, http.MethodGet, "/api/v1/session", "")
	e.mustStatus(sess, http.StatusOK)
	if !strings.Contains(sess.Body.String(), `"authMethod":"bearer"`) || strings.Contains(sess.Body.String(), "csrfToken") {
		t.Fatalf("bearer session = %s", sess.Body)
	}
	// Bearer requests need no CSRF token and cannot be forged cross-site
	// (browsers never attach them automatically).
	e.mustStatus(e.do(desk, http.MethodPost, "/api/v1/orgs", fmt.Sprintf(`{"slug":%q,"name":"D"}`, storetest.Unique("d"))), http.StatusCreated)

	// Refresh rotates; the old refresh token is then dead, and reusing it
	// revokes the whole family including the new tokens.
	refreshBody := func(rt string) string { return fmt.Sprintf(`{"grantType":"refresh_token","refreshToken":%q}`, rt) }
	rec = e.do(anonymous, http.MethodPost, "/api/v1/auth/token", refreshBody(pair.RefreshToken))
	e.mustStatus(rec, http.StatusOK)
	pair2 := decode[tokenPair](t, rec)
	e.mustStatus(e.do(&client{bearer: pair2.AccessToken}, http.MethodGet, "/api/v1/session", ""), http.StatusOK)

	e.mustStatus(e.do(anonymous, http.MethodPost, "/api/v1/auth/token", refreshBody(pair.RefreshToken)), http.StatusUnauthorized)
	e.mustStatus(e.do(&client{bearer: pair2.AccessToken}, http.MethodGet, "/api/v1/session", ""), http.StatusUnauthorized)
	e.mustStatus(e.do(anonymous, http.MethodPost, "/api/v1/auth/token", refreshBody(pair2.RefreshToken)), http.StatusUnauthorized)

	// Access tokens expire.
	state, lc = e.startLogin(url.Values{"client": {"desktop"}, "redirectUri": {redirectURI}, "codeChallenge": {challenge}, "state": {appState}}.Encode())
	loc, _ = url.Parse(e.callback(key, state, lc).Header().Get("Location"))
	pair3 := decode[tokenPair](t, e.do(anonymous, http.MethodPost, "/api/v1/auth/token", codeBody(loc.Query().Get("code"), verifier, redirectURI)))
	e.clock.advance(16 * time.Minute)
	e.mustStatus(e.do(&client{bearer: pair3.AccessToken}, http.MethodGet, "/api/v1/session", ""), http.StatusUnauthorized)

	// Desktop sign-out revokes the grant.
	rec = e.do(anonymous, http.MethodPost, "/api/v1/auth/token", refreshBody(pair3.RefreshToken))
	e.mustStatus(rec, http.StatusOK)
	pair4 := decode[tokenPair](t, rec)
	e.mustStatus(e.do(&client{bearer: pair4.AccessToken}, http.MethodDelete, "/api/v1/session", ""), http.StatusNoContent)
	e.mustStatus(e.do(anonymous, http.MethodPost, "/api/v1/auth/token", refreshBody(pair4.RefreshToken)), http.StatusUnauthorized)

	if err := e.recorder.VerifyChain(t.Context(), ""); err != nil {
		t.Fatalf("instance audit chain: %v", err)
	}
}

type httpResult struct {
	code int
	body string
}

func TestAPITokens_ScopedExpiringAndRevocable(t *testing.T) {
	e := newEnv(t)
	root := e.loginWeb(e.bootstrap)
	e.mustStatus(e.do(root, http.MethodPost, "/api/v1/tokens", `{"name":"x","scopes":["orgs:create"],"expiresInDays":1}`), http.StatusUnprocessableEntity)
	e.mustStatus(e.do(root, http.MethodPost, "/api/v1/tokens", `{"name":"x","scopes":["orgs:list"],"expiresInDays":366}`), http.StatusUnprocessableEntity)
	e.mustStatus(e.do(root, http.MethodPost, "/api/v1/tokens", `{"name":"x","scopes":["orgs:list","orgs:list"],"expiresInDays":1}`), http.StatusUnprocessableEntity)

	rec := e.do(root, http.MethodPost, "/api/v1/tokens", `{"name":"ci","scopes":["orgs:list"],"expiresInDays":1}`)
	e.mustStatus(rec, http.StatusCreated)
	created := decode[struct {
		Token    string `json:"token"`
		APIToken struct {
			ID     string `json:"id"`
			Prefix string `json:"prefix"`
		} `json:"apiToken"`
	}](t, rec)
	if !strings.HasPrefix(created.Token, auth.PrefixAPIToken) || !strings.HasPrefix(created.Token, created.APIToken.Prefix) {
		t.Fatalf("token = %+v", created)
	}
	list := e.do(root, http.MethodGet, "/api/v1/tokens", "")
	if strings.Contains(list.Body.String(), created.Token) {
		t.Fatal("token secret returned by list")
	}

	tok := &client{bearer: created.Token}
	e.mustStatus(e.do(tok, http.MethodGet, "/api/v1/orgs", ""), http.StatusOK)
	e.mustStatus(e.do(tok, http.MethodGet, "/api/v1/session", ""), http.StatusForbidden) // not in scope

	e.clock.advance(25 * time.Hour)
	e.mustStatus(e.do(tok, http.MethodGet, "/api/v1/orgs", ""), http.StatusUnauthorized)
	root = e.loginWeb(e.bootstrap) // the old session idled out too

	rec = e.do(root, http.MethodPost, "/api/v1/tokens", `{"name":"ci2","scopes":["orgs:list"],"expiresInDays":1}`)
	created2 := decode[struct {
		Token    string `json:"token"`
		APIToken struct {
			ID string `json:"id"`
		} `json:"apiToken"`
	}](t, rec)
	e.mustStatus(e.do(root, http.MethodDelete, "/api/v1/tokens/"+created2.APIToken.ID, ""), http.StatusNoContent)
	e.mustStatus(e.do(&client{bearer: created2.Token}, http.MethodGet, "/api/v1/orgs", ""), http.StatusUnauthorized)
	e.mustStatus(e.do(root, http.MethodDelete, "/api/v1/tokens/"+created2.APIToken.ID, ""), http.StatusNotFound)
}

func TestMembers_OwnerRules(t *testing.T) {
	f := newFixture(t)
	e := f.env
	org := "/api/v1/orgs/" + f.org
	ownerID := f.actors[owner].userID

	// The only owner cannot demote or remove themselves.
	e.mustStatus(e.do(f.actors[owner], http.MethodPut, org+"/members/"+ownerID, `{"role":"admin"}`), http.StatusConflict)
	e.mustStatus(e.do(f.actors[owner], http.MethodDelete, org+"/members/"+ownerID, ""), http.StatusConflict)

	// Admins cannot create, promote to, demote, or remove owners.
	email := storetest.Unique("o") + "@kiln.test"
	e.mustStatus(e.do(f.actors[admin], http.MethodPost, org+"/members", fmt.Sprintf(`{"email":%q,"role":"owner"}`, email)), http.StatusForbidden)
	target := f.target()
	e.mustStatus(e.do(f.actors[admin], http.MethodPut, org+"/members/"+target, `{"role":"owner"}`), http.StatusForbidden)
	e.mustStatus(e.do(f.actors[admin], http.MethodPut, org+"/members/"+ownerID, `{"role":"viewer"}`), http.StatusForbidden)
	e.mustStatus(e.do(f.actors[admin], http.MethodDelete, org+"/members/"+ownerID, ""), http.StatusForbidden)

	// With a second owner, the first may step down.
	e.mustStatus(e.do(f.actors[owner], http.MethodPut, org+"/members/"+target, `{"role":"owner"}`), http.StatusOK)
	e.mustStatus(e.do(f.actors[owner], http.MethodPut, org+"/members/"+ownerID, `{"role":"admin"}`), http.StatusOK)

	// Adding an existing member conflicts; unknown member is 404; bad email is 422.
	e.mustStatus(e.do(f.actors[admin], http.MethodPost, org+"/members", `{"email":"not-an-email","role":"viewer"}`), http.StatusUnprocessableEntity)
	e.mustStatus(e.do(f.actors[admin], http.MethodPut, org+"/members/01ARZ3NDEKTSV4RRFFQ69G5FAV", `{"role":"viewer"}`), http.StatusNotFound)
}

func TestOrgs_ValidationAndConflicts(t *testing.T) {
	e := newEnv(t)
	root := e.loginWeb(e.bootstrap)
	slug := storetest.Unique("dup")
	e.mustStatus(e.do(root, http.MethodPost, "/api/v1/orgs", fmt.Sprintf(`{"slug":%q,"name":"A"}`, slug)), http.StatusCreated)
	e.mustStatus(e.do(root, http.MethodPost, "/api/v1/orgs", fmt.Sprintf(`{"slug":%q,"name":"A"}`, slug)), http.StatusConflict)
	e.mustStatus(e.do(root, http.MethodPost, "/api/v1/orgs", `{"slug":"ok-slug","name":"   "}`), http.StatusUnprocessableEntity)
	e.mustStatus(e.do(root, http.MethodGet, "/api/v1/orgs?cursor=bm90LWFuLWlk", ""), http.StatusUnprocessableEntity)

	// Pagination walks every org exactly once.
	for range 3 {
		e.mustStatus(e.do(root, http.MethodPost, "/api/v1/orgs", fmt.Sprintf(`{"slug":%q,"name":"P"}`, storetest.Unique("pg"))), http.StatusCreated)
	}
	seen := map[string]bool{}
	cursor := ""
	for range 10 {
		target := "/api/v1/orgs?limit=2"
		if cursor != "" {
			target += "&cursor=" + cursor
		}
		rec := e.do(root, http.MethodGet, target, "")
		e.mustStatus(rec, http.StatusOK)
		page := decode[struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
			NextCursor *string `json:"nextCursor"`
		}](t, rec)
		for _, o := range page.Items {
			if seen[o.ID] {
				t.Fatalf("org %s returned twice", o.ID)
			}
			seen[o.ID] = true
		}
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	if len(seen) != 4 {
		t.Fatalf("paged %d orgs, want 4", len(seen))
	}
}
