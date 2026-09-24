// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/api/gen"
	"github.com/yamatrireddy/kilnci/server/internal/auth"
	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
)

// AuthService is what the auth handlers need from internal/auth.
type AuthService interface {
	StartLogin(ctx context.Context, req auth.StartLoginRequest) (auth.StartLoginResult, error)
	CompleteLogin(ctx context.Context, req auth.CompleteLoginRequest) (auth.CompleteLoginResult, error)
	ExchangeToken(ctx context.Context, req auth.TokenRequest) (auth.TokenPair, error)
	Session(ctx context.Context) (auth.SessionInfo, error)
	Logout(ctx context.Context) error
	CreateAPIToken(ctx context.Context, name string, scopes []string, days int) (string, domain.APIToken, error)
	ListAPITokens(ctx context.Context) ([]domain.APIToken, error)
	RevokeAPIToken(ctx context.Context, id string) error
}

const loginCookieMaxAge = 10 * 60

func setCookie(w http.ResponseWriter, name, value string, maxAge int, expires time.Time) {
	c := &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge, Expires: expires,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)
}

func clearCookie(w http.ResponseWriter, name string) {
	setCookie(w, name, "", -1, time.Unix(0, 0))
}

func redirect(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusSeeOther)
}

func (s *server) startLogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	res, err := s.auth.StartLogin(r.Context(), auth.StartLoginRequest{
		Client:        domain.LoginClient(q.Get("client")),
		ReturnTo:      q.Get("returnTo"),
		RedirectURI:   q.Get("redirectUri"),
		CodeChallenge: q.Get("codeChallenge"),
		State:         q.Get("state"),
	})
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	setCookie(w, auth.LoginCookieName, res.BrowserBind, loginCookieMaxAge, time.Time{})
	redirect(w, res.RedirectURL)
}

// completeLogin is reached by browser navigation, so failures redirect to the
// web app's sign-in page with a coarse reason instead of returning JSON.
func (s *server) completeLogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bind := ""
	if c, err := r.Cookie(auth.LoginCookieName); err == nil {
		bind = c.Value
	}
	clearCookie(w, auth.LoginCookieName)

	res, err := s.auth.CompleteLogin(r.Context(), auth.CompleteLoginRequest{
		State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error"), BrowserBind: bind,
	})
	if err != nil {
		reason := "failed"
		switch {
		case errors.Is(err, domain.ErrForbidden):
			reason = "not_invited"
		case errors.Is(err, domain.ErrUnauthenticated):
		default:
			s.log.ErrorContext(r.Context(), "complete login", "error", err)
		}
		redirect(w, "/signin?"+url.Values{"error": {reason}}.Encode())
		return
	}
	if res.SessionToken != "" {
		setCookie(w, auth.SessionCookieName, res.SessionToken, 0, res.SessionExpiresAt)
	}
	redirect(w, res.Redirect)
}

func (s *server) exchangeToken(w http.ResponseWriter, r *http.Request) {
	var body gen.TokenRequest
	if err := decodeJSON(r, &body); err != nil {
		s.errs.write(w, r, err)
		return
	}
	pair, err := s.auth.ExchangeToken(r.Context(), auth.TokenRequest{
		GrantType: string(body.GrantType), Code: deref(body.Code), CodeVerifier: deref(body.CodeVerifier),
		RedirectURI: deref(body.RedirectUri), RefreshToken: deref(body.RefreshToken),
	})
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, gen.TokenResponse{
		AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken, TokenType: gen.TokenResponseTokenTypeBearer,
		ExpiresIn: int(pair.AccessExpiresIn.Seconds()), RefreshExpiresIn: int(pair.RefreshExpiresIn.Seconds()),
	})
}

func (s *server) getSession(w http.ResponseWriter, r *http.Request) {
	info, err := s.auth.Session(r.Context())
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	out := gen.Session{
		User:          gen.User{Id: info.User.ID, Email: info.User.Email, DisplayName: info.User.DisplayName},
		InstanceAdmin: info.User.InstanceAdmin,
		AuthMethod:    gen.SessionAuthMethod(info.Method),
	}
	if info.CSRFToken != "" {
		out.CsrfToken = &info.CSRFToken
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) deleteSession(w http.ResponseWriter, r *http.Request) {
	if err := s.auth.Logout(r.Context()); err != nil {
		s.errs.write(w, r, err)
		return
	}
	if p, ok := authz.FromContext(r.Context()); ok && p.Method == authz.MethodSession {
		clearCookie(w, auth.SessionCookieName)
	}
	w.WriteHeader(http.StatusNoContent)
}

func toGenToken(t domain.APIToken) gen.APIToken {
	scopes := make([]gen.Permission, len(t.Scopes))
	for i, s := range t.Scopes {
		scopes[i] = gen.Permission(s)
	}
	return gen.APIToken{
		Id: t.ID, Name: t.Name, Prefix: t.Prefix, Scopes: scopes,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt,
	}
}

func (s *server) listTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := s.auth.ListAPITokens(r.Context())
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	out := gen.APITokenList{Items: make([]gen.APIToken, len(ts))}
	for i, t := range ts {
		out.Items[i] = toGenToken(t)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) createToken(w http.ResponseWriter, r *http.Request) {
	var body gen.APITokenCreate
	if err := decodeJSON(r, &body); err != nil {
		s.errs.write(w, r, err)
		return
	}
	scopes := make([]string, len(body.Scopes))
	for i, sc := range body.Scopes {
		scopes[i] = string(sc)
	}
	token, meta, err := s.auth.CreateAPIToken(r.Context(), body.Name, scopes, body.ExpiresInDays)
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, gen.APITokenCreated{Token: token, ApiToken: toGenToken(meta)})
}

func (s *server) revokeToken(w http.ResponseWriter, r *http.Request) {
	if err := s.auth.RevokeAPIToken(r.Context(), r.PathValue("tokenId")); err != nil {
		s.errs.write(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
