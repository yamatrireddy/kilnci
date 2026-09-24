// SPDX-License-Identifier: Apache-2.0

// Package authz is Kiln's authorization policy engine.
//
// Authorization is deny-by-default and resource-scoped: services call
// Authorizer.Check with the principal, the action, and the specific resource
// (which always names its org). Role alone is never enough, and a principal
// with no membership in the resource's org gets domain.ErrNotFound so that
// resource existence is not disclosed across tenants.
package authz

import (
	"context"
	"slices"
)

// Kind is the type of authenticated actor.
type Kind string

// Principal kinds.
const (
	KindUser     Kind = "user"
	KindAPIToken Kind = "api_token"
	KindRunner   Kind = "runner"
	KindSystem   Kind = "system"
)

// Method records how the principal authenticated, which decides CSRF rules.
type Method string

// Authentication methods.
const (
	// MethodSession is a browser session cookie; unsafe requests need a CSRF token.
	MethodSession Method = "session"
	// MethodBearer is an Authorization: Bearer credential (desktop or API token).
	MethodBearer Method = "bearer"
)

// Principal is the authenticated actor for a request.
type Principal struct {
	Kind   Kind
	Method Method
	// UserID is the acting user (for API tokens, the token's owner).
	UserID string
	// CredentialID identifies the session or token used, for audit and revocation.
	CredentialID string
	// InstanceAdmin may perform instance-level actions such as creating orgs.
	InstanceAdmin bool
	// Scopes restricts an API token to a subset of actions. Nil means the
	// principal is limited only by its role (sessions and desktop tokens).
	Scopes []Action
	// CSRFToken is set for browser-session principals only, so the session
	// endpoint can hand it to the web app. Never log it.
	CSRFToken string
}

// AllowsAction reports whether the principal's credential scopes permit a.
// Role-based checks still apply on top of this.
func (p *Principal) AllowsAction(a Action) bool {
	if p == nil {
		return false
	}
	if p.Scopes == nil {
		return true
	}
	return slices.Contains(p.Scopes, a)
}

type ctxKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the principal in ctx, if any.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok && p != nil
}
