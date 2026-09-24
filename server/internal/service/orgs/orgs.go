// SPDX-License-Identifier: Apache-2.0

// Package orgs implements tenancy use cases: orgs, memberships, projects, and
// reading the org audit log.
//
// Every method authorizes against the specific org via authz.Authorizer.Check.
// Orgs are always resolved through the caller's membership, so a non-member
// gets domain.ErrNotFound whether or not the org exists (cross-org access is
// indistinguishable from a missing resource).
package orgs

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
)

var tracer = otel.Tracer("github.com/yamatrireddy/kilnci/server/internal/service/orgs")

// Store is the persistence this service needs.
type Store interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
	CreateOrg(ctx context.Context, o domain.Org) (domain.Org, error)
	GetOrgForMember(ctx context.Context, slug, userID string) (domain.OrgWithRole, error)
	ListOrgsForMember(ctx context.Context, userID, afterID string, limit int32) ([]domain.OrgWithRole, error)
	AddMembership(ctx context.Context, m domain.Membership, now time.Time) error
	UpdateMembershipRole(ctx context.Context, m domain.Membership) error
	DeleteMembership(ctx context.Context, orgID, userID string) error
	LockOwners(ctx context.Context, orgID string) ([]string, error)
	GetMembershipRole(ctx context.Context, orgID, userID string) (domain.Role, error)
	GetMember(ctx context.Context, orgID, userID string) (domain.Member, error)
	ListMembers(ctx context.Context, orgID, afterUserID string, limit int32) ([]domain.Member, error)
	GetUserByEmail(ctx context.Context, email string) (domain.User, error)
	CreatePendingUser(ctx context.Context, id, email, displayName string, now time.Time) (domain.User, error)
	CreateProject(ctx context.Context, p domain.Project) (domain.Project, error)
	GetProject(ctx context.Context, orgID, slug string) (domain.Project, error)
	ListProjects(ctx context.Context, orgID, afterID string, limit int32) ([]domain.Project, error)
	ListAuditEvents(ctx context.Context, orgID, beforeID string, limit int32) ([]domain.AuditEvent, error)
}

// Authorizer decides whether a principal may act on a resource.
type Authorizer interface {
	Check(ctx context.Context, p *authz.Principal, a authz.Action, res authz.Resource) error
}

// Auditor records privileged actions.
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) error
}

// Service implements the tenancy use cases.
type Service struct {
	store Store
	az    Authorizer
	audit Auditor
	ids   *ids.Generator
	now   func() time.Time
}

// NewService returns a Service. now may be nil (time.Now).
func NewService(s Store, az Authorizer, a Auditor, gen *ids.Generator, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: s, az: az, audit: a, ids: gen, now: now}
}

// Page is one page of results.
type Page[T any] struct {
	Items      []T
	NextCursor string
}

// PageRequest selects a page. Cursor is opaque; Limit is clamped to 1..100.
type PageRequest struct {
	Cursor string
	Limit  int
}

const (
	defaultLimit = 50
	maxLimit     = 100
)

func (pr PageRequest) parse() (after string, limit int32, err error) {
	limit = defaultLimit
	if pr.Limit > 0 {
		limit = int32(min(pr.Limit, maxLimit)) //nolint:gosec // bounded above
	}
	if pr.Cursor == "" {
		return "", limit, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(pr.Cursor)
	if err != nil || !ids.Valid(string(b)) {
		return "", 0, domain.NewValidationError("cursor", "is not a valid cursor")
	}
	return string(b), limit, nil
}

func encodeCursor(id string) string { return base64.RawURLEncoding.EncodeToString([]byte(id)) }

// page trims a limit+1 result to limit and computes the next cursor.
func page[T any](items []T, limit int32, idOf func(T) string) Page[T] {
	if len(items) <= int(limit) {
		return Page[T]{Items: items}
	}
	items = items[:limit]
	return Page[T]{Items: items, NextCursor: encodeCursor(idOf(items[len(items)-1]))}
}

func principal(ctx context.Context) (*authz.Principal, error) {
	p, ok := authz.FromContext(ctx)
	if !ok {
		return nil, domain.ErrUnauthenticated
	}
	return p, nil
}

// resolve finds orgSlug through the caller's membership and authorizes a.
func (s *Service) resolve(ctx context.Context, p *authz.Principal, orgSlug string, a authz.Action) (domain.OrgWithRole, error) {
	if domain.ValidateSlug("orgSlug", orgSlug) != nil {
		return domain.OrgWithRole{}, domain.ErrNotFound
	}
	org, err := s.store.GetOrgForMember(ctx, orgSlug, p.UserID)
	if err != nil {
		return domain.OrgWithRole{}, fmt.Errorf("resolve org: %w", err)
	}
	if err := s.az.Check(ctx, p, a, authz.Resource{OrgID: org.ID}); err != nil {
		return domain.OrgWithRole{}, fmt.Errorf("authorize %s: %w", a, err)
	}
	return org, nil
}

// ListOrgs returns the orgs the caller belongs to.
func (s *Service) ListOrgs(ctx context.Context, pr PageRequest) (Page[domain.OrgWithRole], error) {
	ctx, span := tracer.Start(ctx, "orgs.ListOrgs")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return Page[domain.OrgWithRole]{}, err
	}
	if err := s.az.Check(ctx, p, authz.ActionOrgsList, authz.Resource{OwnerUserID: p.UserID}); err != nil {
		return Page[domain.OrgWithRole]{}, fmt.Errorf("authorize: %w", err)
	}
	after, limit, err := pr.parse()
	if err != nil {
		return Page[domain.OrgWithRole]{}, err
	}
	orgs, err := s.store.ListOrgsForMember(ctx, p.UserID, after, limit+1)
	if err != nil {
		return Page[domain.OrgWithRole]{}, fmt.Errorf("list orgs: %w", err)
	}
	return page(orgs, limit, func(o domain.OrgWithRole) string { return o.ID }), nil
}

// CreateOrg creates an org owned by the caller (instance admins only).
func (s *Service) CreateOrg(ctx context.Context, slug, name string) (domain.OrgWithRole, error) {
	ctx, span := tracer.Start(ctx, "orgs.CreateOrg")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return domain.OrgWithRole{}, err
	}
	if err := s.az.Check(ctx, p, authz.ActionOrgsCreate, authz.Resource{}); err != nil {
		return domain.OrgWithRole{}, fmt.Errorf("authorize: %w", err)
	}
	ve := &domain.ValidationError{}
	if err := domain.ValidateSlug("slug", slug); err != nil {
		ve.Add("slug", "must be 1-40 lowercase letters, digits, or single hyphens")
	}
	name, nameErr := domain.NormalizeName("name", name)
	if nameErr != nil {
		ve.Add("name", "must be 1-100 characters without control characters")
	}
	if err := ve.OrNil(); err != nil {
		return domain.OrgWithRole{}, err
	}

	org := domain.Org{ID: s.ids.New(), Slug: slug, Name: name, CreatedAt: s.now().UTC()}
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		created, err := s.store.CreateOrg(ctx, org)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		org = created
		if err := s.store.AddMembership(ctx, domain.Membership{OrgID: org.ID, UserID: p.UserID, Role: domain.RoleOwner}, s.now()); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		return s.audit.Record(logging.WithOrgID(ctx, org.ID), audit.Entry{
			OrgID: org.ID, Action: string(authz.ActionOrgsCreate), TargetType: "org", TargetID: org.ID,
			Details: map[string]string{"slug": org.Slug},
		})
	})
	if err != nil {
		return domain.OrgWithRole{}, fmt.Errorf("create org: %w", err)
	}
	return domain.OrgWithRole{Org: org, Role: domain.RoleOwner}, nil
}

// GetOrg returns an org the caller belongs to.
func (s *Service) GetOrg(ctx context.Context, orgSlug string) (domain.OrgWithRole, error) {
	ctx, span := tracer.Start(ctx, "orgs.GetOrg")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return domain.OrgWithRole{}, err
	}
	return s.resolve(ctx, p, orgSlug, authz.ActionOrgsRead)
}

// ListMembers lists an org's members.
func (s *Service) ListMembers(ctx context.Context, orgSlug string, pr PageRequest) (Page[domain.Member], error) {
	ctx, span := tracer.Start(ctx, "orgs.ListMembers")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return Page[domain.Member]{}, err
	}
	org, err := s.resolve(ctx, p, orgSlug, authz.ActionMembersList)
	if err != nil {
		return Page[domain.Member]{}, err
	}
	after, limit, err := pr.parse()
	if err != nil {
		return Page[domain.Member]{}, err
	}
	ms, err := s.store.ListMembers(ctx, org.ID, after, limit+1)
	if err != nil {
		return Page[domain.Member]{}, fmt.Errorf("list members: %w", err)
	}
	return page(ms, limit, func(m domain.Member) string { return m.UserID }), nil
}

// normalizeEmail validates an email address supplied by an admin.
func normalizeEmail(raw string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(raw))
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Address != e || addr.Name != "" || len(e) > 254 || strings.ContainsAny(e, "\r\n\t<>") {
		return "", domain.NewValidationError("email", "must be a plain email address")
	}
	return e, nil
}

// manage resolves the org for a membership mutation. A member who lacks the
// permission gets an audited denial.
func (s *Service) manage(ctx context.Context, p *authz.Principal, orgSlug, target string) (domain.OrgWithRole, error) {
	org, err := s.resolve(ctx, p, orgSlug, authz.ActionMembersManage)
	if errors.Is(err, domain.ErrForbidden) {
		if org2, lookupErr := s.store.GetOrgForMember(ctx, orgSlug, p.UserID); lookupErr == nil {
			s.recordDenied(ctx, org2.ID, target)
		}
	}
	return org, err
}

func (s *Service) recordDenied(ctx context.Context, orgID, target string) {
	// Best effort: a failure to record a denial must not change the response.
	_ = s.audit.Record(logging.WithOrgID(ctx, orgID), audit.Entry{
		OrgID: orgID, Action: string(authz.ActionMembersManage), TargetType: "membership",
		TargetID: target, Result: domain.AuditDenied,
	})
}

// callerRole re-reads the caller's role inside the owner-locked transaction,
// so a concurrent demotion of the caller cannot be outraced (TOCTOU).
func (s *Service) callerRole(ctx context.Context, orgID, userID string) (domain.Role, error) {
	role, err := s.store.GetMembershipRole(ctx, orgID, userID)
	if err != nil {
		return "", fmt.Errorf("re-read caller role: %w", err)
	}
	if !role.AtLeast(domain.RoleAdmin) {
		return "", fmt.Errorf("caller lost the admin role: %w", domain.ErrForbidden)
	}
	return role, nil
}

// AddMember adds a user (by email) to an org. Users who have never signed in
// are created as pending invites, claimed at their first sign-in.
func (s *Service) AddMember(ctx context.Context, orgSlug, email string, role domain.Role) (domain.Member, error) {
	ctx, span := tracer.Start(ctx, "orgs.AddMember")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return domain.Member{}, err
	}
	org, err := s.manage(ctx, p, orgSlug, "")
	if err != nil {
		return domain.Member{}, err
	}
	email, err = normalizeEmail(email)
	if err != nil {
		return domain.Member{}, err
	}
	if !role.Valid() {
		return domain.Member{}, domain.NewValidationError("role", "is not a valid role")
	}
	var member domain.Member
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		// Lock owner rows like the other membership changes, then re-check the
		// caller's role inside the transaction (TOCTOU, security review L).
		if _, err := s.store.LockOwners(ctx, org.ID); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		callerRole, err := s.callerRole(ctx, org.ID, p.UserID)
		if err != nil {
			return err
		}
		if role == domain.RoleOwner && callerRole != domain.RoleOwner {
			return fmt.Errorf("only owners may grant owner: %w", domain.ErrForbidden)
		}
		u, err := s.store.GetUserByEmail(ctx, email)
		if errors.Is(err, domain.ErrNotFound) {
			local, _, _ := strings.Cut(email, "@")
			u, err = s.store.CreatePendingUser(ctx, s.ids.New(), email, local, s.now().UTC())
		}
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if err := s.store.AddMembership(ctx, domain.Membership{OrgID: org.ID, UserID: u.ID, Role: role}, s.now()); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		member = domain.Member{UserID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Role: role}
		return s.audit.Record(logging.WithOrgID(ctx, org.ID), audit.Entry{
			OrgID: org.ID, Action: "members:add", TargetType: "membership", TargetID: u.ID,
			Details: map[string]string{"role": string(role)},
		})
	})
	if errors.Is(err, domain.ErrForbidden) {
		s.recordDenied(ctx, org.ID, "")
	}
	if err != nil {
		return domain.Member{}, fmt.Errorf("add member: %w", err)
	}
	return member, nil
}

// UpdateMember changes a member's role. Only owners may grant or revoke the
// owner role, and the last owner cannot be demoted.
func (s *Service) UpdateMember(ctx context.Context, orgSlug, userID string, role domain.Role) (domain.Member, error) {
	ctx, span := tracer.Start(ctx, "orgs.UpdateMember")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return domain.Member{}, err
	}
	org, err := s.manage(ctx, p, orgSlug, userID)
	if err != nil {
		return domain.Member{}, err
	}
	if !ids.Valid(userID) {
		return domain.Member{}, domain.ErrNotFound
	}
	if !role.Valid() {
		return domain.Member{}, domain.NewValidationError("role", "is not a valid role")
	}

	var member domain.Member
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		owners, err := s.store.LockOwners(ctx, org.ID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		callerRole, err := s.callerRole(ctx, org.ID, p.UserID)
		if err != nil {
			return err
		}
		current, err := s.store.GetMember(ctx, org.ID, userID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if (current.Role == domain.RoleOwner || role == domain.RoleOwner) && callerRole != domain.RoleOwner {
			return fmt.Errorf("only owners may grant or revoke owner: %w", domain.ErrForbidden)
		}
		if current.Role == domain.RoleOwner && role != domain.RoleOwner && len(owners) <= 1 {
			return fmt.Errorf("cannot demote the last owner: %w", domain.ErrConflict)
		}
		if err := s.store.UpdateMembershipRole(ctx, domain.Membership{OrgID: org.ID, UserID: userID, Role: role}); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		member = current
		member.Role = role
		return s.audit.Record(logging.WithOrgID(ctx, org.ID), audit.Entry{
			OrgID: org.ID, Action: "members:update", TargetType: "membership", TargetID: userID,
			Details: map[string]string{"from": string(current.Role), "to": string(role)},
		})
	})
	if errors.Is(err, domain.ErrForbidden) {
		s.recordDenied(ctx, org.ID, userID)
	}
	if err != nil {
		return domain.Member{}, fmt.Errorf("update member: %w", err)
	}
	return member, nil
}

// RemoveMember removes a member. Only owners may remove an owner, and the last
// owner cannot be removed.
func (s *Service) RemoveMember(ctx context.Context, orgSlug, userID string) error {
	ctx, span := tracer.Start(ctx, "orgs.RemoveMember")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return err
	}
	org, err := s.manage(ctx, p, orgSlug, userID)
	if err != nil {
		return err
	}
	if !ids.Valid(userID) {
		return domain.ErrNotFound
	}
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		owners, err := s.store.LockOwners(ctx, org.ID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		callerRole, err := s.callerRole(ctx, org.ID, p.UserID)
		if err != nil {
			return err
		}
		current, err := s.store.GetMember(ctx, org.ID, userID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if current.Role == domain.RoleOwner {
			if callerRole != domain.RoleOwner {
				return fmt.Errorf("only owners may remove an owner: %w", domain.ErrForbidden)
			}
			if len(owners) <= 1 {
				return fmt.Errorf("cannot remove the last owner: %w", domain.ErrConflict)
			}
		}
		if err := s.store.DeleteMembership(ctx, org.ID, userID); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		return s.audit.Record(logging.WithOrgID(ctx, org.ID), audit.Entry{
			OrgID: org.ID, Action: "members:remove", TargetType: "membership", TargetID: userID,
			Details: map[string]string{"role": string(current.Role)},
		})
	})
	if errors.Is(err, domain.ErrForbidden) {
		s.recordDenied(ctx, org.ID, userID)
	}
	if err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	return nil
}

// ListProjects lists an org's projects.
func (s *Service) ListProjects(ctx context.Context, orgSlug string, pr PageRequest) (Page[domain.Project], error) {
	ctx, span := tracer.Start(ctx, "orgs.ListProjects")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return Page[domain.Project]{}, err
	}
	org, err := s.resolve(ctx, p, orgSlug, authz.ActionProjectsList)
	if err != nil {
		return Page[domain.Project]{}, err
	}
	after, limit, err := pr.parse()
	if err != nil {
		return Page[domain.Project]{}, err
	}
	ps, err := s.store.ListProjects(ctx, org.ID, after, limit+1)
	if err != nil {
		return Page[domain.Project]{}, fmt.Errorf("list projects: %w", err)
	}
	return page(ps, limit, func(p domain.Project) string { return p.ID }), nil
}

// CreateProject creates a project in an org (org admins).
func (s *Service) CreateProject(ctx context.Context, orgSlug, slug, name string) (domain.Project, error) {
	ctx, span := tracer.Start(ctx, "orgs.CreateProject")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return domain.Project{}, err
	}
	org, err := s.resolve(ctx, p, orgSlug, authz.ActionProjectsCreate)
	if err != nil {
		return domain.Project{}, err
	}
	ve := &domain.ValidationError{}
	if err := domain.ValidateSlug("slug", slug); err != nil {
		ve.Add("slug", "must be 1-40 lowercase letters, digits, or single hyphens")
	}
	name, nameErr := domain.NormalizeName("name", name)
	if nameErr != nil {
		ve.Add("name", "must be 1-100 characters without control characters")
	}
	if err := ve.OrNil(); err != nil {
		return domain.Project{}, err
	}
	proj, err := s.store.CreateProject(ctx, domain.Project{ID: s.ids.New(), OrgID: org.ID, Slug: slug, Name: name, CreatedAt: s.now().UTC()})
	if err != nil {
		return domain.Project{}, fmt.Errorf("create project: %w", err)
	}
	return proj, nil
}

// GetProject returns a project in an org.
func (s *Service) GetProject(ctx context.Context, orgSlug, projectSlug string) (domain.Project, error) {
	ctx, span := tracer.Start(ctx, "orgs.GetProject")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return domain.Project{}, err
	}
	org, err := s.resolve(ctx, p, orgSlug, authz.ActionProjectsRead)
	if err != nil {
		return domain.Project{}, err
	}
	if domain.ValidateSlug("projectSlug", projectSlug) != nil {
		return domain.Project{}, domain.ErrNotFound
	}
	proj, err := s.store.GetProject(ctx, org.ID, projectSlug)
	if err != nil {
		return domain.Project{}, fmt.Errorf("get project: %w", err)
	}
	return proj, nil
}

// ListAuditEvents lists an org's audit events, newest first (org admins).
func (s *Service) ListAuditEvents(ctx context.Context, orgSlug string, pr PageRequest) (Page[domain.AuditEvent], error) {
	ctx, span := tracer.Start(ctx, "orgs.ListAuditEvents")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return Page[domain.AuditEvent]{}, err
	}
	org, err := s.resolve(ctx, p, orgSlug, authz.ActionAuditRead)
	if err != nil {
		return Page[domain.AuditEvent]{}, err
	}
	before, limit, err := pr.parse()
	if err != nil {
		return Page[domain.AuditEvent]{}, err
	}
	evs, err := s.store.ListAuditEvents(ctx, org.ID, before, limit+1)
	if err != nil {
		return Page[domain.AuditEvent]{}, fmt.Errorf("list audit events: %w", err)
	}
	return page(evs, limit, func(e domain.AuditEvent) string { return e.ID }), nil
}
