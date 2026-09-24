// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
)

// Cookie names. The __Host- prefix makes browsers require Secure, Path=/, and
// no Domain, so the cookies cannot be set or shadowed by other subdomains.
const (
	SessionCookieName = "__Host-kiln_session"
	LoginCookieName   = "__Host-kiln_login"
	// CSRFHeader carries the synchronizer token on unsafe cookie requests.
	CSRFHeader = "X-CSRF-Token"
)

// Authenticate resolves the principal for r (implements api.Authenticator).
// It returns (nil, nil) when r carries no credentials.
func (s *Service) Authenticate(r *http.Request) (*authz.Principal, error) {
	ctx, span := tracer.Start(r.Context(), "auth.Authenticate")
	defer span.End()
	now := s.now().UTC()

	if h := r.Header.Get("Authorization"); h != "" {
		token, ok := strings.CutPrefix(h, "Bearer ")
		if !ok {
			return nil, fmt.Errorf("unsupported authorization scheme: %w", domain.ErrUnauthenticated)
		}
		switch {
		case strings.HasPrefix(token, PrefixAPIToken):
			return s.authAPIToken(ctx, token, now)
		case strings.HasPrefix(token, PrefixAccessToken):
			return s.authAccessToken(ctx, token, now)
		default:
			return nil, fmt.Errorf("unrecognized bearer token: %w", domain.ErrUnauthenticated)
		}
	}
	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		return nil, nil //nolint:nilnil // no credentials is not an error; the router denies it
	}
	return s.authSession(ctx, r, c.Value, now)
}

func (s *Service) authSession(ctx context.Context, r *http.Request, token string, now time.Time) (*authz.Principal, error) {
	if !wellFormed(token, PrefixSession) {
		return nil, fmt.Errorf("malformed session cookie: %w", domain.ErrUnauthenticated)
	}
	ws, err := s.store.GetWebSessionByHash(ctx, hashToken(token))
	if err != nil {
		return nil, unauthenticatedIfMissing("session", err)
	}
	switch {
	case ws.RevokedAt != nil:
		return nil, fmt.Errorf("session revoked: %w", domain.ErrUnauthenticated)
	case now.After(ws.ExpiresAt):
		return nil, fmt.Errorf("session expired: %w", domain.ErrUnauthenticated)
	case now.Sub(ws.LastSeenAt) > s.opts.SessionIdleTimeout:
		return nil, fmt.Errorf("session idle timeout: %w", domain.ErrUnauthenticated)
	}

	csrf := csrfToken(token)
	if !isSafeMethod(r.Method) {
		// Defense in depth on top of SameSite=Lax: a cross-site Origin is
		// rejected outright, and the synchronizer token must match.
		if o := r.Header.Get("Origin"); o != "" && o != s.opts.PublicOrigin {
			return nil, fmt.Errorf("cross-origin request with session cookie: %w", domain.ErrForbidden)
		}
		if !equalConstantTime(r.Header.Get(CSRFHeader), csrf) {
			return nil, fmt.Errorf("missing or invalid CSRF token: %w", domain.ErrForbidden)
		}
	}

	u, err := s.store.GetUser(ctx, ws.UserID)
	if err != nil {
		return nil, unauthenticatedIfMissing("session user", err)
	}
	if now.Sub(ws.LastSeenAt) > touchInterval {
		if err := s.store.TouchWebSession(ctx, ws.ID, now); err != nil {
			s.log.WarnContext(ctx, "touch session", "error", err)
		}
	}
	return &authz.Principal{
		Kind: authz.KindUser, Method: authz.MethodSession, UserID: u.ID, CredentialID: ws.ID,
		InstanceAdmin: u.InstanceAdmin, CSRFToken: csrf,
	}, nil
}

func (s *Service) authAccessToken(ctx context.Context, token string, now time.Time) (*authz.Principal, error) {
	if !wellFormed(token, PrefixAccessToken) {
		return nil, fmt.Errorf("malformed access token: %w", domain.ErrUnauthenticated)
	}
	at, err := s.store.GetAccessToken(ctx, hashToken(token))
	if err != nil {
		return nil, unauthenticatedIfMissing("access token", err)
	}
	if now.After(at.ExpiresAt) || at.GrantRevokedAt != nil || now.After(at.GrantExpiresAt) {
		return nil, fmt.Errorf("access token expired or revoked: %w", domain.ErrUnauthenticated)
	}
	u, err := s.store.GetUser(ctx, at.UserID)
	if err != nil {
		return nil, unauthenticatedIfMissing("token user", err)
	}
	return &authz.Principal{
		Kind: authz.KindUser, Method: authz.MethodBearer, UserID: u.ID, CredentialID: at.GrantID,
		InstanceAdmin: u.InstanceAdmin,
	}, nil
}

func (s *Service) authAPIToken(ctx context.Context, token string, now time.Time) (*authz.Principal, error) {
	if !wellFormed(token, PrefixAPIToken) {
		return nil, fmt.Errorf("malformed API token: %w", domain.ErrUnauthenticated)
	}
	t, err := s.store.GetAPITokenByHash(ctx, hashToken(token))
	if err != nil {
		return nil, unauthenticatedIfMissing("API token", err)
	}
	if t.RevokedAt != nil || now.After(t.ExpiresAt) {
		return nil, fmt.Errorf("API token expired or revoked: %w", domain.ErrUnauthenticated)
	}
	u, err := s.store.GetUser(ctx, t.UserID)
	if err != nil {
		return nil, unauthenticatedIfMissing("token user", err)
	}
	scopes := make([]authz.Action, 0, len(t.Scopes))
	for _, sc := range t.Scopes {
		if isTokenScope(authz.Action(sc)) {
			scopes = append(scopes, authz.Action(sc))
		}
	}
	if err := s.store.TouchAPIToken(ctx, t.ID, now); err != nil {
		s.log.WarnContext(ctx, "touch api token", "error", err)
	}
	return &authz.Principal{
		Kind: authz.KindAPIToken, Method: authz.MethodBearer, UserID: u.ID, CredentialID: t.ID,
		InstanceAdmin: u.InstanceAdmin, Scopes: scopes,
	}, nil
}

func unauthenticatedIfMissing(what string, err error) error {
	if errors.Is(err, domain.ErrNotFound) {
		return fmt.Errorf("unknown %s: %w", what, domain.ErrUnauthenticated)
	}
	return fmt.Errorf("look up %s: %w", what, err)
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}
