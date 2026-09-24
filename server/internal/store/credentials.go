// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/store/db"
)

// CreateWebSession inserts a browser session.
func (s *Store) CreateWebSession(ctx context.Context, ws domain.WebSession) error {
	return mapErr("create web session", s.q(ctx).CreateWebSession(ctx, db.CreateWebSessionParams{
		ID: ws.ID, TokenHash: ws.TokenHash, UserID: ws.UserID,
		CreatedAt: ws.CreatedAt, LastSeenAt: ws.LastSeenAt, ExpiresAt: ws.ExpiresAt,
	}))
}

// GetWebSessionByHash looks a session up by the hash of its cookie secret.
func (s *Store) GetWebSessionByHash(ctx context.Context, hash []byte) (domain.WebSession, error) {
	r, err := s.q(ctx).GetWebSessionByHash(ctx, hash)
	return domain.WebSession{
		ID: r.ID, TokenHash: r.TokenHash, UserID: r.UserID, CreatedAt: r.CreatedAt,
		LastSeenAt: r.LastSeenAt, ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt,
	}, mapErr("get web session", err)
}

// TouchWebSession records activity for idle-timeout tracking.
func (s *Store) TouchWebSession(ctx context.Context, id string, now time.Time) error {
	return mapErr("touch web session", s.q(ctx).TouchWebSession(ctx, db.TouchWebSessionParams{ID: id, LastSeenAt: now}))
}

// RevokeWebSession ends a session.
func (s *Store) RevokeWebSession(ctx context.Context, id string, now time.Time) error {
	return mapErr("revoke web session", s.q(ctx).RevokeWebSession(ctx, db.RevokeWebSessionParams{ID: id, RevokedAt: &now}))
}

// CreateLoginState stores an in-flight login.
func (s *Store) CreateLoginState(ctx context.Context, ls domain.LoginState) error {
	return mapErr("create login state", s.q(ctx).CreateLoginState(ctx, db.CreateLoginStateParams{
		StateHash: ls.StateHash, Client: string(ls.Client), Nonce: ls.Nonce, IdpCodeVerifier: ls.IDPCodeVerifier,
		ReturnTo: ls.ReturnTo, DesktopRedirectUri: ls.DesktopRedirectURI, DesktopCodeChallenge: ls.DesktopCodeChallenge,
		DesktopState: ls.DesktopState, CreatedAt: ls.CreatedAt, ExpiresAt: ls.ExpiresAt,
	}))
}

// TakeLoginState atomically deletes and returns a login state (single use).
func (s *Store) TakeLoginState(ctx context.Context, hash []byte) (domain.LoginState, error) {
	r, err := s.q(ctx).TakeLoginState(ctx, hash)
	return domain.LoginState{
		StateHash: r.StateHash, Client: domain.LoginClient(r.Client), Nonce: r.Nonce, IDPCodeVerifier: r.IdpCodeVerifier,
		ReturnTo: r.ReturnTo, DesktopRedirectURI: r.DesktopRedirectUri, DesktopCodeChallenge: r.DesktopCodeChallenge,
		DesktopState: r.DesktopState, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
	}, mapErr("take login state", err)
}

// credentialRetention keeps expired sessions, codes, and grants for a day
// so recent incidents can still be investigated.
const credentialRetention = 24 * time.Hour

// DeleteExpiredCredentials removes expired login states, tokens, sessions,
// codes, and grants.
func (s *Store) DeleteExpiredCredentials(ctx context.Context, now time.Time) (int64, error) {
	q := s.q(ctx)
	cutoff := now.Add(-credentialRetention)
	steps := []struct {
		op string
		fn func() (int64, error)
	}{
		{"login states", func() (int64, error) { return q.DeleteExpiredLoginStates(ctx, now) }},
		{"access tokens", func() (int64, error) { return q.DeleteExpiredAccessTokens(ctx, now) }},
		{"web sessions", func() (int64, error) { return q.DeleteExpiredWebSessions(ctx, cutoff) }},
		{"desktop auth codes", func() (int64, error) { return q.DeleteExpiredDesktopAuthCodes(ctx, cutoff) }},
		{"refresh tokens", func() (int64, error) { return q.DeleteExpiredRefreshTokens(ctx, cutoff) }},
		{"desktop grants", func() (int64, error) { return q.DeleteExpiredDesktopGrants(ctx, cutoff) }},
	}
	var total int64
	for _, st := range steps {
		n, err := st.fn()
		if err != nil {
			return total, mapErr("delete expired "+st.op, err)
		}
		total += n
	}
	return total, nil
}

// CreateDesktopAuthCode stores a one-time desktop login code.
func (s *Store) CreateDesktopAuthCode(ctx context.Context, c domain.DesktopAuthCode) error {
	return mapErr("create desktop auth code", s.q(ctx).CreateDesktopAuthCode(ctx, db.CreateDesktopAuthCodeParams{
		CodeHash: c.CodeHash, UserID: c.UserID, CodeChallenge: c.CodeChallenge, RedirectUri: c.RedirectURI,
		CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt,
	}))
}

// UseDesktopAuthCode marks a code used and returns it; a code can be used once.
func (s *Store) UseDesktopAuthCode(ctx context.Context, hash []byte, now time.Time) (domain.DesktopAuthCode, error) {
	r, err := s.q(ctx).UseDesktopAuthCode(ctx, db.UseDesktopAuthCodeParams{CodeHash: hash, Now: &now})
	return domain.DesktopAuthCode{
		CodeHash: r.CodeHash, UserID: r.UserID, CodeChallenge: r.CodeChallenge, RedirectURI: r.RedirectUri,
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, UsedAt: r.UsedAt,
	}, mapErr("use desktop auth code", err)
}

// CreateDesktopGrant starts a desktop token family.
func (s *Store) CreateDesktopGrant(ctx context.Context, g domain.DesktopGrant) error {
	return mapErr("create desktop grant", s.q(ctx).CreateDesktopGrant(ctx, db.CreateDesktopGrantParams{
		ID: g.ID, UserID: g.UserID, CreatedAt: g.CreatedAt, ExpiresAt: g.ExpiresAt,
	}))
}

// GetDesktopGrant returns a grant.
func (s *Store) GetDesktopGrant(ctx context.Context, id string) (domain.DesktopGrant, error) {
	r, err := s.q(ctx).GetDesktopGrant(ctx, id)
	return domain.DesktopGrant{ID: r.ID, UserID: r.UserID, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt},
		mapErr("get desktop grant", err)
}

// RevokeDesktopGrant revokes a grant and so every token in its family.
func (s *Store) RevokeDesktopGrant(ctx context.Context, id string, now time.Time) error {
	return mapErr("revoke desktop grant", s.q(ctx).RevokeDesktopGrant(ctx, db.RevokeDesktopGrantParams{ID: id, RevokedAt: &now}))
}

// CreateRefreshToken stores a refresh token hash.
func (s *Store) CreateRefreshToken(ctx context.Context, t domain.RefreshToken) error {
	return mapErr("create refresh token", s.q(ctx).CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		TokenHash: t.TokenHash, GrantID: t.GrantID, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
	}))
}

// GetRefreshTokenForUpdate locks and returns a refresh token (inside InTx).
func (s *Store) GetRefreshTokenForUpdate(ctx context.Context, hash []byte) (domain.RefreshToken, error) {
	r, err := s.q(ctx).GetRefreshTokenForUpdate(ctx, hash)
	return domain.RefreshToken{TokenHash: r.TokenHash, GrantID: r.GrantID, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, UsedAt: r.UsedAt},
		mapErr("get refresh token", err)
}

// MarkRefreshTokenUsed records that a refresh token was rotated.
func (s *Store) MarkRefreshTokenUsed(ctx context.Context, hash []byte, now time.Time) error {
	return mapErr("mark refresh token used", s.q(ctx).MarkRefreshTokenUsed(ctx, db.MarkRefreshTokenUsedParams{TokenHash: hash, UsedAt: &now}))
}

// CreateAccessToken stores an access token hash.
func (s *Store) CreateAccessToken(ctx context.Context, t domain.AccessToken, now time.Time) error {
	return mapErr("create access token", s.q(ctx).CreateAccessToken(ctx, db.CreateAccessTokenParams{
		TokenHash: t.TokenHash, GrantID: t.GrantID, CreatedAt: now, ExpiresAt: t.ExpiresAt,
	}))
}

// GetAccessToken returns an access token with its grant's state.
func (s *Store) GetAccessToken(ctx context.Context, hash []byte) (domain.AccessToken, error) {
	r, err := s.q(ctx).GetAccessToken(ctx, hash)
	return domain.AccessToken{
		TokenHash: r.TokenHash, GrantID: r.GrantID, UserID: r.UserID, ExpiresAt: r.ExpiresAt,
		GrantRevokedAt: r.GrantRevokedAt, GrantExpiresAt: r.GrantExpiresAt,
	}, mapErr("get access token", err)
}

func toAPIToken(id, userID, name, prefix string, scopes []string, created, expires time.Time, lastUsed, revoked *time.Time) domain.APIToken {
	return domain.APIToken{
		ID: id, UserID: userID, Name: name, Prefix: prefix, Scopes: scopes,
		CreatedAt: created, ExpiresAt: expires, LastUsedAt: lastUsed, RevokedAt: revoked,
	}
}

// CreateAPIToken stores a personal API token (hash only).
func (s *Store) CreateAPIToken(ctx context.Context, t domain.APIToken, hash []byte) (domain.APIToken, error) {
	r, err := s.q(ctx).CreateAPIToken(ctx, db.CreateAPITokenParams{
		ID: t.ID, UserID: t.UserID, Name: t.Name, Prefix: t.Prefix, TokenHash: hash,
		Scopes: t.Scopes, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
	})
	return toAPIToken(r.ID, r.UserID, r.Name, r.Prefix, r.Scopes, r.CreatedAt, r.ExpiresAt, r.LastUsedAt, r.RevokedAt),
		mapErr("create api token", err)
}

// GetAPITokenByHash looks a token up by its hash.
func (s *Store) GetAPITokenByHash(ctx context.Context, hash []byte) (domain.APIToken, error) {
	r, err := s.q(ctx).GetAPITokenByHash(ctx, hash)
	return toAPIToken(r.ID, r.UserID, r.Name, r.Prefix, r.Scopes, r.CreatedAt, r.ExpiresAt, r.LastUsedAt, r.RevokedAt),
		mapErr("get api token", err)
}

// ListAPITokens lists a user's unrevoked tokens.
func (s *Store) ListAPITokens(ctx context.Context, userID string) ([]domain.APIToken, error) {
	rows, err := s.q(ctx).ListAPITokens(ctx, userID)
	if err != nil {
		return nil, mapErr("list api tokens", err)
	}
	out := make([]domain.APIToken, len(rows))
	for i, r := range rows {
		out[i] = toAPIToken(r.ID, r.UserID, r.Name, r.Prefix, r.Scopes, r.CreatedAt, r.ExpiresAt, r.LastUsedAt, r.RevokedAt)
	}
	return out, nil
}

// CountActiveAPITokens counts a user's usable tokens (for the per-user cap).
func (s *Store) CountActiveAPITokens(ctx context.Context, userID string, now time.Time) (int64, error) {
	n, err := s.q(ctx).CountActiveAPITokens(ctx, db.CountActiveAPITokensParams{UserID: userID, ExpiresAt: now})
	return n, mapErr("count api tokens", err)
}

// RevokeAPIToken revokes a user's own token; domain.ErrNotFound otherwise.
func (s *Store) RevokeAPIToken(ctx context.Context, id, userID string, now time.Time) error {
	n, err := s.q(ctx).RevokeAPIToken(ctx, db.RevokeAPITokenParams{ID: id, UserID: userID, Now: &now})
	if err == nil && n == 0 {
		return mapErr("revoke api token", errNoRows)
	}
	return mapErr("revoke api token", err)
}

// TouchAPIToken records token use (coalesced to once a minute).
func (s *Store) TouchAPIToken(ctx context.Context, id string, now time.Time) error {
	return mapErr("touch api token", s.q(ctx).TouchAPIToken(ctx, db.TouchAPITokenParams{ID: id, Now: &now}))
}
