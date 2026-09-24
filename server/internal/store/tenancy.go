// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/store/db"
)

// errNoRows marks :execrows updates that matched nothing.
var errNoRows = pgx.ErrNoRows

func toUser(u db.User) domain.User {
	return domain.User{
		ID: u.ID, Issuer: deref(u.OidcIssuer), Subject: deref(u.OidcSubject), Email: u.Email,
		DisplayName: u.DisplayName, InstanceAdmin: u.InstanceAdmin, CreatedAt: u.CreatedAt,
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// GetUserByOIDC finds a user by IdP identity.
func (s *Store) GetUserByOIDC(ctx context.Context, issuer, subject string) (domain.User, error) {
	u, err := s.q(ctx).GetUserByOIDC(ctx, db.GetUserByOIDCParams{OidcIssuer: &issuer, OidcSubject: &subject})
	return toUser(u), mapErr("get user by oidc", err)
}

// GetUser finds a user by ID.
func (s *Store) GetUser(ctx context.Context, id string) (domain.User, error) {
	u, err := s.q(ctx).GetUser(ctx, id)
	return toUser(u), mapErr("get user", err)
}

// GetUserByEmail finds a user by email, case-insensitively.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	u, err := s.q(ctx).GetUserByEmail(ctx, email)
	return toUser(u), mapErr("get user by email", err)
}

// CreateUser inserts a user.
func (s *Store) CreateUser(ctx context.Context, u domain.User) (domain.User, error) {
	row, err := s.q(ctx).CreateUser(ctx, db.CreateUserParams{
		ID: u.ID, OidcIssuer: &u.Issuer, OidcSubject: &u.Subject, Email: u.Email,
		DisplayName: u.DisplayName, InstanceAdmin: u.InstanceAdmin, CreatedAt: u.CreatedAt,
	})
	return toUser(row), mapErr("create user", err)
}

// CreatePendingUser creates an invited account with no IdP identity yet;
// domain.ErrConflict if the email is taken.
func (s *Store) CreatePendingUser(ctx context.Context, id, email, displayName string, now time.Time) (domain.User, error) {
	row, err := s.q(ctx).CreatePendingUser(ctx, db.CreatePendingUserParams{ID: id, Email: email, DisplayName: displayName, CreatedAt: now})
	return toUser(row), mapErr("create pending user", err)
}

// ClaimPendingUser binds an IdP identity to the unclaimed account invited with
// email; domain.ErrNotFound if there is none.
func (s *Store) ClaimPendingUser(ctx context.Context, email, issuer, subject, displayName string, grantAdmin bool) (domain.User, error) {
	row, err := s.q(ctx).ClaimPendingUser(ctx, db.ClaimPendingUserParams{
		Issuer: &issuer, Subject: &subject, DisplayName: displayName, GrantInstanceAdmin: grantAdmin, Email: email,
	})
	return toUser(row), mapErr("claim pending user", err)
}

// UpdateUserProfile refreshes profile fields from the IdP. grantAdmin can set
// but never clear the instance-admin flag.
func (s *Store) UpdateUserProfile(ctx context.Context, id, email, displayName string, grantAdmin bool) (domain.User, error) {
	row, err := s.q(ctx).UpdateUserProfile(ctx, db.UpdateUserProfileParams{
		ID: id, Email: email, DisplayName: displayName, GrantInstanceAdmin: grantAdmin,
	})
	return toUser(row), mapErr("update user profile", err)
}

// CreateOrg inserts an org.
func (s *Store) CreateOrg(ctx context.Context, o domain.Org) (domain.Org, error) {
	row, err := s.q(ctx).CreateOrg(ctx, db.CreateOrgParams{ID: o.ID, Slug: o.Slug, Name: o.Name, CreatedAt: o.CreatedAt})
	return domain.Org{ID: row.ID, Slug: row.Slug, Name: row.Name, CreatedAt: row.CreatedAt}, mapErr("create org", err)
}

// GetOrgForMember returns the org with the given slug only if userID is a
// member; otherwise domain.ErrNotFound (existence is not disclosed).
func (s *Store) GetOrgForMember(ctx context.Context, slug, userID string) (domain.OrgWithRole, error) {
	r, err := s.q(ctx).GetOrgForMember(ctx, db.GetOrgForMemberParams{Slug: slug, UserID: userID})
	return domain.OrgWithRole{
		Org:  domain.Org{ID: r.ID, Slug: r.Slug, Name: r.Name, CreatedAt: r.CreatedAt},
		Role: domain.Role(r.Role),
	}, mapErr("get org for member", err)
}

// ListOrgsForMember lists the orgs userID belongs to, ordered by ID after afterID.
func (s *Store) ListOrgsForMember(ctx context.Context, userID, afterID string, limit int32) ([]domain.OrgWithRole, error) {
	rows, err := s.q(ctx).ListOrgsForMember(ctx, db.ListOrgsForMemberParams{UserID: userID, AfterID: afterID, MaxRows: limit})
	if err != nil {
		return nil, mapErr("list orgs for member", err)
	}
	out := make([]domain.OrgWithRole, len(rows))
	for i, r := range rows {
		out[i] = domain.OrgWithRole{
			Org:  domain.Org{ID: r.ID, Slug: r.Slug, Name: r.Name, CreatedAt: r.CreatedAt},
			Role: domain.Role(r.Role),
		}
	}
	return out, nil
}

// GetMembershipRole returns userID's role in orgID, or domain.ErrNotFound.
func (s *Store) GetMembershipRole(ctx context.Context, orgID, userID string) (domain.Role, error) {
	r, err := s.q(ctx).GetMembershipRole(ctx, db.GetMembershipRoleParams{OrgID: orgID, UserID: userID})
	return domain.Role(r), mapErr("get membership role", err)
}

// AddMembership adds userID to orgID; domain.ErrConflict if already a member.
func (s *Store) AddMembership(ctx context.Context, m domain.Membership, now time.Time) error {
	err := s.q(ctx).AddMembership(ctx, db.AddMembershipParams{OrgID: m.OrgID, UserID: m.UserID, Role: string(m.Role), CreatedAt: now})
	return mapErr("add membership", err)
}

// UpdateMembershipRole changes a member's role; domain.ErrNotFound if not a member.
func (s *Store) UpdateMembershipRole(ctx context.Context, m domain.Membership) error {
	n, err := s.q(ctx).UpdateMembershipRole(ctx, db.UpdateMembershipRoleParams{OrgID: m.OrgID, UserID: m.UserID, Role: string(m.Role)})
	if err == nil && n == 0 {
		return mapErr("update membership role", errNoRows)
	}
	return mapErr("update membership role", err)
}

// DeleteMembership removes a member; domain.ErrNotFound if not a member.
func (s *Store) DeleteMembership(ctx context.Context, orgID, userID string) error {
	n, err := s.q(ctx).DeleteMembership(ctx, db.DeleteMembershipParams{OrgID: orgID, UserID: userID})
	if err == nil && n == 0 {
		return mapErr("delete membership", errNoRows)
	}
	return mapErr("delete membership", err)
}

// LockOwners locks and returns the org's owner user IDs for the current
// transaction. It must be called inside InTx.
func (s *Store) LockOwners(ctx context.Context, orgID string) ([]string, error) {
	ids, err := s.q(ctx).LockOwners(ctx, orgID)
	return ids, mapErr("lock owners", err)
}

// GetMember returns one member of orgID.
func (s *Store) GetMember(ctx context.Context, orgID, userID string) (domain.Member, error) {
	r, err := s.q(ctx).GetMember(ctx, db.GetMemberParams{OrgID: orgID, UserID: userID})
	return domain.Member{UserID: r.UserID, Email: r.Email, DisplayName: r.DisplayName, Role: domain.Role(r.Role)}, mapErr("get member", err)
}

// ListMembers lists orgID's members ordered by user ID after afterUserID.
func (s *Store) ListMembers(ctx context.Context, orgID, afterUserID string, limit int32) ([]domain.Member, error) {
	rows, err := s.q(ctx).ListMembers(ctx, db.ListMembersParams{OrgID: orgID, AfterUserID: afterUserID, MaxRows: limit})
	if err != nil {
		return nil, mapErr("list members", err)
	}
	out := make([]domain.Member, len(rows))
	for i, r := range rows {
		out[i] = domain.Member{UserID: r.UserID, Email: r.Email, DisplayName: r.DisplayName, Role: domain.Role(r.Role)}
	}
	return out, nil
}

func toProject(p db.Project) domain.Project {
	return domain.Project{ID: p.ID, OrgID: p.OrgID, Slug: p.Slug, Name: p.Name, CreatedAt: p.CreatedAt}
}

// CreateProject inserts a project; domain.ErrConflict on a duplicate slug.
func (s *Store) CreateProject(ctx context.Context, p domain.Project) (domain.Project, error) {
	row, err := s.q(ctx).CreateProject(ctx, db.CreateProjectParams{ID: p.ID, OrgID: p.OrgID, Slug: p.Slug, Name: p.Name, CreatedAt: p.CreatedAt})
	return toProject(row), mapErr("create project", err)
}

// GetProject returns the project with slug in orgID.
func (s *Store) GetProject(ctx context.Context, orgID, slug string) (domain.Project, error) {
	row, err := s.q(ctx).GetProject(ctx, db.GetProjectParams{OrgID: orgID, Slug: slug})
	return toProject(row), mapErr("get project", err)
}

// ListProjects lists orgID's projects ordered by ID after afterID.
func (s *Store) ListProjects(ctx context.Context, orgID, afterID string, limit int32) ([]domain.Project, error) {
	rows, err := s.q(ctx).ListProjects(ctx, db.ListProjectsParams{OrgID: orgID, AfterID: afterID, MaxRows: limit})
	if err != nil {
		return nil, mapErr("list projects", err)
	}
	out := make([]domain.Project, len(rows))
	for i, r := range rows {
		out[i] = toProject(r)
	}
	return out, nil
}
