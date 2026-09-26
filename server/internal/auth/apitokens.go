// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
)

// tokenScopes are the actions a personal API token may be granted. Phase 0
// allows read-only actions only (ADR-0003 §4).
var tokenScopes = []authz.Action{
	authz.ActionSessionRead,
	authz.ActionOrgsList,
	authz.ActionOrgsRead,
	authz.ActionMembersList,
	authz.ActionProjectsList,
	authz.ActionProjectsRead,
	authz.ActionAuditRead,
	authz.ActionRunsList,
	authz.ActionRunsRead,
	authz.ActionLogsRead,
	authz.ActionPipelinesLint, // side-effect free; backs `kiln lint`
}

func isTokenScope(a authz.Action) bool { return slices.Contains(tokenScopes, a) }

const maxTokenDays = 365

// CreateAPIToken creates a personal API token for the caller and returns the
// secret (shown once) and its metadata. Only session or desktop principals may
// create tokens; a token cannot mint another token.
func (s *Service) CreateAPIToken(ctx context.Context, name string, scopes []string, days int) (string, domain.APIToken, error) {
	ctx, span := tracer.Start(ctx, "auth.CreateAPIToken")
	defer span.End()
	p, ok := authz.FromContext(ctx)
	if !ok {
		return "", domain.APIToken{}, domain.ErrUnauthenticated
	}
	if p.Kind != authz.KindUser {
		return "", domain.APIToken{}, fmt.Errorf("API tokens cannot create API tokens: %w", domain.ErrForbidden)
	}
	if err := s.az.Check(ctx, p, authz.ActionTokensCreate, authz.Resource{OwnerUserID: p.UserID}); err != nil {
		return "", domain.APIToken{}, fmt.Errorf("authorize: %w", err)
	}

	ve := &domain.ValidationError{}
	name, err := domain.NormalizeName("name", name)
	if err != nil {
		ve.Add("name", "must be 1-100 characters without control characters")
	}
	if len(scopes) == 0 || len(scopes) > len(tokenScopes) {
		ve.Add("scopes", "must list at least one permission")
	}
	seen := map[string]bool{}
	for _, sc := range scopes {
		if !isTokenScope(authz.Action(sc)) || seen[sc] {
			ve.Add("scopes", "contains an unknown, disallowed, or duplicate permission")
			break
		}
		seen[sc] = true
	}
	if days < 1 || days > maxTokenDays {
		ve.Add("expiresInDays", "must be between 1 and 365")
	}
	if err := ve.OrNil(); err != nil {
		return "", domain.APIToken{}, err
	}

	now := s.now().UTC()
	token, hash := newSecret(PrefixAPIToken)
	var created domain.APIToken
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		n, err := s.store.CountActiveAPITokens(ctx, p.UserID, now)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if n >= maxAPITokens {
			return fmt.Errorf("at most %d active API tokens: %w", maxAPITokens, domain.ErrConflict)
		}
		created, err = s.store.CreateAPIToken(ctx, domain.APIToken{
			ID: s.ids.New(), UserID: p.UserID, Name: name, Prefix: token[:len(PrefixAPIToken)+4],
			Scopes: scopes, CreatedAt: now, ExpiresAt: now.AddDate(0, 0, days),
		}, hash)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		return s.audit.Record(ctx, audit.Entry{
			Action: string(authz.ActionTokensCreate), TargetType: "api_token", TargetID: created.ID,
			Details: map[string]string{"scopes": strings.Join(scopes, ","), "expiresInDays": fmt.Sprint(days)},
		})
	})
	if err != nil {
		return "", domain.APIToken{}, fmt.Errorf("create api token: %w", err)
	}
	return token, created, nil
}

// ListAPITokens lists the caller's active tokens (metadata only).
func (s *Service) ListAPITokens(ctx context.Context) ([]domain.APIToken, error) {
	p, ok := authz.FromContext(ctx)
	if !ok {
		return nil, domain.ErrUnauthenticated
	}
	if err := s.az.Check(ctx, p, authz.ActionTokensList, authz.Resource{OwnerUserID: p.UserID}); err != nil {
		return nil, fmt.Errorf("authorize: %w", err)
	}
	ts, err := s.store.ListAPITokens(ctx, p.UserID)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	return ts, nil
}

// RevokeAPIToken revokes one of the caller's tokens. Another user's token is
// reported as not found.
func (s *Service) RevokeAPIToken(ctx context.Context, id string) error {
	p, ok := authz.FromContext(ctx)
	if !ok {
		return domain.ErrUnauthenticated
	}
	if err := s.az.Check(ctx, p, authz.ActionTokensDelete, authz.Resource{OwnerUserID: p.UserID}); err != nil {
		return fmt.Errorf("authorize: %w", err)
	}
	if !ids.Valid(id) {
		return domain.ErrNotFound
	}
	err := s.store.InTx(ctx, func(ctx context.Context) error {
		if err := s.store.RevokeAPIToken(ctx, id, p.UserID, s.now().UTC()); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		return s.audit.Record(ctx, audit.Entry{Action: string(authz.ActionTokensDelete), TargetType: "api_token", TargetID: id})
	})
	if err != nil {
		return fmt.Errorf("revoke api token: %w", err)
	}
	return nil
}
