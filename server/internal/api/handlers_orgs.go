// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/yamatrireddy/kilnci/server/internal/api/gen"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/service/orgs"
)

// OrgService is what the tenancy handlers need from internal/service/orgs.
type OrgService interface {
	ListOrgs(ctx context.Context, pr orgs.PageRequest) (orgs.Page[domain.OrgWithRole], error)
	CreateOrg(ctx context.Context, slug, name string) (domain.OrgWithRole, error)
	GetOrg(ctx context.Context, orgSlug string) (domain.OrgWithRole, error)
	ListMembers(ctx context.Context, orgSlug string, pr orgs.PageRequest) (orgs.Page[domain.Member], error)
	AddMember(ctx context.Context, orgSlug, email string, role domain.Role) (domain.Member, error)
	UpdateMember(ctx context.Context, orgSlug, userID string, role domain.Role) (domain.Member, error)
	RemoveMember(ctx context.Context, orgSlug, userID string) error
	ListProjects(ctx context.Context, orgSlug string, pr orgs.PageRequest) (orgs.Page[domain.Project], error)
	CreateProject(ctx context.Context, orgSlug, slug, name string) (domain.Project, error)
	GetProject(ctx context.Context, orgSlug, projectSlug string) (domain.Project, error)
	ListAuditEvents(ctx context.Context, orgSlug string, pr orgs.PageRequest) (orgs.Page[domain.AuditEvent], error)
}

// pageRequest reads cursor/limit (already validated against the spec).
func pageRequest(r *http.Request) orgs.PageRequest {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	return orgs.PageRequest{Cursor: q.Get("cursor"), Limit: limit}
}

func nextCursor(c string) *string {
	if c == "" {
		return nil
	}
	return &c
}

func toGenOrg(o domain.OrgWithRole) gen.Org {
	return gen.Org{Id: o.ID, Slug: o.Slug, Name: o.Name, Role: gen.Role(o.Role), CreatedAt: o.CreatedAt}
}

func toGenMember(m domain.Member) gen.Member {
	return gen.Member{UserId: m.UserID, Email: m.Email, DisplayName: m.DisplayName, Role: gen.Role(m.Role)}
}

func toGenProject(p domain.Project) gen.Project {
	return gen.Project{Id: p.ID, Slug: p.Slug, Name: p.Name, CreatedAt: p.CreatedAt}
}

func (s *server) listOrgs(w http.ResponseWriter, r *http.Request) {
	pg, err := s.orgs.ListOrgs(r.Context(), pageRequest(r))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	out := gen.OrgList{Items: make([]gen.Org, len(pg.Items)), NextCursor: nextCursor(pg.NextCursor)}
	for i, o := range pg.Items {
		out.Items[i] = toGenOrg(o)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) createOrg(w http.ResponseWriter, r *http.Request) {
	var body gen.OrgCreate
	if err := decodeJSON(r, &body); err != nil {
		s.errs.write(w, r, err)
		return
	}
	o, err := s.orgs.CreateOrg(r.Context(), body.Slug, body.Name)
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/orgs/"+o.Slug)
	writeJSON(w, http.StatusCreated, toGenOrg(o))
}

func (s *server) getOrg(w http.ResponseWriter, r *http.Request) {
	o, err := s.orgs.GetOrg(r.Context(), r.PathValue("orgSlug"))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toGenOrg(o))
}

func (s *server) listMembers(w http.ResponseWriter, r *http.Request) {
	pg, err := s.orgs.ListMembers(r.Context(), r.PathValue("orgSlug"), pageRequest(r))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	out := gen.MemberList{Items: make([]gen.Member, len(pg.Items)), NextCursor: nextCursor(pg.NextCursor)}
	for i, m := range pg.Items {
		out.Items[i] = toGenMember(m)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) addMember(w http.ResponseWriter, r *http.Request) {
	var body gen.MemberAdd
	if err := decodeJSON(r, &body); err != nil {
		s.errs.write(w, r, err)
		return
	}
	m, err := s.orgs.AddMember(r.Context(), r.PathValue("orgSlug"), body.Email, domain.Role(body.Role))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toGenMember(m))
}

func (s *server) updateMember(w http.ResponseWriter, r *http.Request) {
	var body gen.MemberUpdate
	if err := decodeJSON(r, &body); err != nil {
		s.errs.write(w, r, err)
		return
	}
	m, err := s.orgs.UpdateMember(r.Context(), r.PathValue("orgSlug"), r.PathValue("userId"), domain.Role(body.Role))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toGenMember(m))
}

func (s *server) removeMember(w http.ResponseWriter, r *http.Request) {
	if err := s.orgs.RemoveMember(r.Context(), r.PathValue("orgSlug"), r.PathValue("userId")); err != nil {
		s.errs.write(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listProjects(w http.ResponseWriter, r *http.Request) {
	pg, err := s.orgs.ListProjects(r.Context(), r.PathValue("orgSlug"), pageRequest(r))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	out := gen.ProjectList{Items: make([]gen.Project, len(pg.Items)), NextCursor: nextCursor(pg.NextCursor)}
	for i, p := range pg.Items {
		out.Items[i] = toGenProject(p)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) createProject(w http.ResponseWriter, r *http.Request) {
	var body gen.ProjectCreate
	if err := decodeJSON(r, &body); err != nil {
		s.errs.write(w, r, err)
		return
	}
	orgSlug := r.PathValue("orgSlug")
	p, err := s.orgs.CreateProject(r.Context(), orgSlug, body.Slug, body.Name)
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/orgs/"+orgSlug+"/projects/"+p.Slug)
	writeJSON(w, http.StatusCreated, toGenProject(p))
}

func (s *server) getProject(w http.ResponseWriter, r *http.Request) {
	p, err := s.orgs.GetProject(r.Context(), r.PathValue("orgSlug"), r.PathValue("projectSlug"))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toGenProject(p))
}

func (s *server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	pg, err := s.orgs.ListAuditEvents(r.Context(), r.PathValue("orgSlug"), pageRequest(r))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	out := gen.AuditEventList{Items: make([]gen.AuditEvent, len(pg.Items)), NextCursor: nextCursor(pg.NextCursor)}
	for i, e := range pg.Items {
		ip, ua := e.SourceIP, e.UserAgent
		out.Items[i] = gen.AuditEvent{
			Id: e.ID, OccurredAt: e.OccurredAt, ActorKind: e.ActorKind, ActorId: e.ActorID, Action: e.Action,
			TargetType: e.TargetType, TargetId: e.TargetID, Result: gen.AuditEventResult(e.Result),
			RequestId: e.RequestID, SourceIp: &ip, UserAgent: &ua,
		}
	}
	writeJSON(w, http.StatusOK, out)
}
