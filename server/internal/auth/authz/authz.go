// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
)

// Resource identifies what an action targets. OrgID must be set for every
// org-scoped action; OwnerUserID must be set for self-only actions that target
// a specific user's credential.
type Resource struct {
	OrgID       string
	OwnerUserID string
}

// MembershipReader looks up a user's role in an org. It returns
// domain.ErrNotFound when the user is not a member.
type MembershipReader interface {
	GetMembershipRole(ctx context.Context, orgID, userID string) (domain.Role, error)
}

// Authorizer makes authorization decisions. It is the single implementation of
// the policy table in action.go.
type Authorizer struct {
	members MembershipReader
}

// NewAuthorizer returns an Authorizer backed by members.
func NewAuthorizer(members MembershipReader) *Authorizer {
	return &Authorizer{members: members}
}

// Check returns nil if p may perform a on res. Otherwise it returns
// domain.ErrUnauthenticated (no principal), domain.ErrNotFound (the principal
// is not a member of the resource's org, so its existence is not disclosed),
// or domain.ErrForbidden (known resource, insufficient permission).
func (az *Authorizer) Check(ctx context.Context, p *Principal, a Action, res Resource) error {
	if p == nil || p.UserID == "" {
		return domain.ErrUnauthenticated
	}
	r, ok := policy[a]
	if !ok {
		return fmt.Errorf("undeclared action %q: %w", a, domain.ErrForbidden)
	}
	// Only users (directly or via their API tokens) act on tenant resources in
	// Phase 0. Runners get their own narrowly scoped actions in Phase 1.
	if p.Kind != KindUser && p.Kind != KindAPIToken {
		return domain.ErrForbidden
	}
	if !p.AllowsAction(a) {
		return domain.ErrForbidden
	}

	switch {
	case r.instanceAdmin:
		if !p.InstanceAdmin || p.Kind != KindUser {
			return domain.ErrForbidden
		}
		return nil
	case r.selfOnly:
		if res.OwnerUserID != "" && res.OwnerUserID != p.UserID {
			return domain.ErrNotFound
		}
		return nil
	}

	if res.OrgID == "" {
		return fmt.Errorf("action %q requires an org-scoped resource: %w", a, domain.ErrForbidden)
	}
	role, err := az.members.GetMembershipRole(ctx, res.OrgID, p.UserID)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("authorize %s: %w", a, err)
	}
	if !role.AtLeast(r.minRole) {
		return domain.ErrForbidden
	}
	return nil
}

// RoleAllows reports whether role satisfies the minimum role for a. It does no
// lookups and exists for callers that already hold the caller's role (e.g. to
// hide UI affordances); enforcement must still go through Check.
func RoleAllows(role domain.Role, a Action) bool {
	r, ok := policy[a]
	if !ok || r.selfOnly || r.instanceAdmin {
		return false
	}
	return role.AtLeast(r.minRole)
}
