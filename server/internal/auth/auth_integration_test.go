// SPDX-License-Identifier: Apache-2.0

//go:build integration

package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/auth"
	"github.com/yamatrireddy/kilnci/server/internal/auth/authtest"
	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/store"
	"github.com/yamatrireddy/kilnci/server/internal/store/storetest"
)

type harness struct {
	svc *auth.Service
	idp *authtest.FakeIDP
	st  *store.Store
	now time.Time
}

func newHarness(t *testing.T, mutate func(*auth.Options)) *harness {
	t.Helper()
	st := storetest.New(t)
	gen := ids.NewGenerator(nil)
	h := &harness{idp: authtest.NewFakeIDP(), st: st, now: time.Now().UTC()}
	opts := auth.Options{
		PublicOrigin: "https://kiln.test", SessionIdleTimeout: time.Hour, SessionAbsoluteTimeout: 12 * time.Hour,
		AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: 24 * time.Hour,
	}
	if mutate != nil {
		mutate(&opts)
	}
	h.svc = auth.NewService(st, h.idp, audit.NewRecorder(st, gen, nil), authz.NewAuthorizer(st), gen, logging.Discard(),
		func() time.Time { return h.now }, opts)
	return h
}

// login runs the web flow at the service level and returns the result.
func (h *harness) login(t *testing.T, email, subject string) (auth.CompleteLoginResult, error) {
	t.Helper()
	h.idp.Register(subject, auth.Claims{Issuer: "https://idp.test", Subject: subject, Email: email, EmailVerified: true, Name: "N"})
	res, err := h.svc.StartLogin(t.Context(), auth.StartLoginRequest{Client: domain.LoginClientWeb})
	if err != nil {
		t.Fatal(err)
	}
	return h.svc.CompleteLogin(t.Context(), auth.CompleteLoginRequest{
		State: res.BrowserBind, Code: subject + "." + res.BrowserBind, BrowserBind: res.BrowserBind,
	})
}

func TestProvisioning_AutoProvisionRespectsDomains(t *testing.T) {
	h := newHarness(t, func(o *auth.Options) {
		o.AutoProvision = true
		o.AllowedEmailDomains = []string{"corp.example"}
	})
	if _, err := h.login(t, storetest.Unique("ok")+"@corp.example", storetest.Unique("s")); err != nil {
		t.Fatalf("allowed domain: %v", err)
	}
	if _, err := h.login(t, storetest.Unique("no")+"@other.example", storetest.Unique("s")); !errors.Is(err, auth.ErrNotInvited) {
		t.Fatalf("other domain: %v", err)
	}
}

func TestProvisioning_AutoProvisionAnyDomainAndNoMerge(t *testing.T) {
	h := newHarness(t, func(o *auth.Options) { o.AutoProvision = true })
	email := storetest.Unique("any") + "@anywhere.example"
	if _, err := h.login(t, email, storetest.Unique("s")); err != nil {
		t.Fatalf("auto-provision: %v", err)
	}
	// A second IdP identity asserting the same email must not take over the account.
	if _, err := h.login(t, email, storetest.Unique("s")); !errors.Is(err, auth.ErrNotInvited) {
		t.Fatalf("account merged by email: %v", err)
	}
}

func TestProvisioning_EmailChangeCollisionKeepsOldEmail(t *testing.T) {
	h := newHarness(t, func(o *auth.Options) { o.AutoProvision = true })
	a, b := storetest.Unique("a")+"@x.example", storetest.Unique("b")+"@x.example"
	subA := storetest.Unique("s")
	if _, err := h.login(t, a, subA); err != nil {
		t.Fatal(err)
	}
	if _, err := h.login(t, b, storetest.Unique("s")); err != nil {
		t.Fatal(err)
	}
	// A's IdP now claims B's email: A keeps its own email.
	if _, err := h.login(t, b, subA); err != nil {
		t.Fatalf("re-login with colliding email: %v", err)
	}
	u, err := h.st.GetUserByOIDC(t.Context(), "https://idp.test", subA)
	if err != nil || u.Email != a {
		t.Fatalf("user = %+v, %v", u, err)
	}
}

// Security review M1: an IdP asserting another account's (bootstrap) email
// must not make this account an instance admin.
func TestProvisioning_CollidingBootstrapEmailDoesNotGrantAdmin(t *testing.T) {
	adminEmail := storetest.Unique("boot") + "@x.example"
	h := newHarness(t, func(o *auth.Options) {
		o.AutoProvision = true
		o.BootstrapAdminEmails = []string{adminEmail}
	})
	if _, err := h.login(t, adminEmail, storetest.Unique("s")); err != nil {
		t.Fatal(err)
	}
	subB := storetest.Unique("s")
	if _, err := h.login(t, storetest.Unique("b")+"@x.example", subB); err != nil {
		t.Fatal(err)
	}
	if _, err := h.login(t, adminEmail, subB); err != nil {
		t.Fatalf("re-login with colliding email: %v", err)
	}
	u, err := h.st.GetUserByOIDC(t.Context(), "https://idp.test", subB)
	if err != nil || u.InstanceAdmin || u.Email == adminEmail {
		t.Fatalf("colliding email escalated: %+v, %v", u, err)
	}
}

func TestAPITokenPrincipal_CannotMintTokensOrSignOut(t *testing.T) {
	h := newHarness(t, nil)
	p := &authz.Principal{Kind: authz.KindAPIToken, Method: authz.MethodBearer, UserID: "u", Scopes: []authz.Action{authz.ActionSessionDelete}}
	ctx := authz.WithPrincipal(t.Context(), p)
	if _, _, err := h.svc.CreateAPIToken(ctx, "x", []string{"orgs:list"}, 1); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("token minted a token: %v", err)
	}
	if err := h.svc.Logout(ctx); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("token signed out: %v", err)
	}
}

func TestService_RequiresPrincipal(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	checks := map[string]error{}
	_, checks["Session"] = h.svc.Session(ctx)
	checks["Logout"] = h.svc.Logout(ctx)
	_, _, checks["CreateAPIToken"] = h.svc.CreateAPIToken(ctx, "x", []string{"orgs:list"}, 1)
	_, checks["ListAPITokens"] = h.svc.ListAPITokens(ctx)
	checks["RevokeAPIToken"] = h.svc.RevokeAPIToken(ctx, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	for name, err := range checks {
		if !errors.Is(err, domain.ErrUnauthenticated) {
			t.Errorf("%s without principal: %v", name, err)
		}
	}
}

func TestAPITokens_CapAndInvalidRevoke(t *testing.T) {
	h := newHarness(t, func(o *auth.Options) { o.AutoProvision = true })
	sub := storetest.Unique("s")
	if _, err := h.login(t, storetest.Unique("cap")+"@x.example", sub); err != nil {
		t.Fatal(err)
	}
	u, err := h.st.GetUserByOIDC(t.Context(), "https://idp.test", sub)
	if err != nil {
		t.Fatal(err)
	}
	ctx := authz.WithPrincipal(t.Context(), &authz.Principal{Kind: authz.KindUser, Method: authz.MethodSession, UserID: u.ID})
	for i := range 50 {
		if _, _, err := h.svc.CreateAPIToken(ctx, "t", []string{"orgs:list"}, 1); err != nil {
			t.Fatalf("token %d: %v", i, err)
		}
	}
	if _, _, err := h.svc.CreateAPIToken(ctx, "t", []string{"orgs:list"}, 1); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("51st token: %v", err)
	}
	if err := h.svc.RevokeAPIToken(ctx, "not-an-id"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("malformed id: %v", err)
	}
	ts, err := h.svc.ListAPITokens(ctx)
	if err != nil || len(ts) != 50 {
		t.Fatalf("list = %d, %v", len(ts), err)
	}
}

func TestCleanupExpired(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := h.svc.StartLogin(t.Context(), auth.StartLoginRequest{Client: domain.LoginClientWeb}); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(time.Hour)
	n, err := h.svc.CleanupExpired(t.Context())
	if err != nil || n < 1 {
		t.Fatalf("cleanup = %d, %v", n, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h.svc.RunJanitor(ctx, time.Hour) // returns promptly when cancelled
}

func TestStartLogin_RejectsUnknownClient(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := h.svc.StartLogin(t.Context(), auth.StartLoginRequest{Client: "cli"}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("err = %v", err)
	}
	if _, err := h.svc.ExchangeToken(t.Context(), auth.TokenRequest{GrantType: "password"}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("err = %v", err)
	}
	if _, err := h.svc.ExchangeToken(t.Context(), auth.TokenRequest{GrantType: "authorization_code", Code: "kiln_code_" + strings.Repeat("A", 43), CodeVerifier: strings.Repeat("v", 43)}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("unknown code: %v", err)
	}
}
