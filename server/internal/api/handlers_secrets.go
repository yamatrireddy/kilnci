// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/yamatrireddy/kilnci/server/internal/api/gen"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/service/paging"
	"github.com/yamatrireddy/kilnci/server/internal/service/secrets"
)

// SecretService is what the secret handlers need from internal/service/secrets.
type SecretService interface {
	List(ctx context.Context, t secrets.Target, pr paging.Request) (paging.Page[secrets.View], error)
	Put(ctx context.Context, t secrets.Target, name string, in secrets.Input) (secrets.Written, error)
	Delete(ctx context.Context, t secrets.Target, name string) error
}

func secretTarget(r *http.Request) secrets.Target {
	return secrets.Target{OrgSlug: r.PathValue("orgSlug"), ProjectSlug: r.PathValue("projectSlug")}
}

func toGenSecret(v secrets.View) gen.Secret {
	out := gen.Secret{
		Name: v.Name, Scope: gen.SecretScope(v.Scope()), ValueVersion: v.ValueVersion, Masked: v.Masked,
		Branches: nonNilStrings(v.Branches), AllowUnprotected: v.AllowUnprotected, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt,
	}
	if v.CreatedBy != "" {
		out.CreatedBy = &v.CreatedBy
	}
	if v.UpdatedBy != "" {
		out.UpdatedBy = &v.UpdatedBy
	}
	if v.Scope() == domain.SecretScopeOrg {
		all, slugs := v.AllProjects, nonNilStrings(v.ProjectSlugs)
		out.AllProjects, out.ProjectSlugs = &all, &slugs
	}
	return out
}

func secretETag(version int64) string { return `"` + strconv.FormatInt(version, 10) + `"` }

func (s *server) listSecrets(w http.ResponseWriter, r *http.Request) {
	pg, err := s.secrets.List(r.Context(), secretTarget(r), pageRequest(r))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	out := gen.SecretList{Items: make([]gen.Secret, len(pg.Items)), NextCursor: nextCursor(pg.NextCursor)}
	for i, v := range pg.Items {
		out.Items[i] = toGenSecret(v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) putSecret(w http.ResponseWriter, r *http.Request) {
	var body gen.SecretPut
	if err := decodeJSON(r, &body); err != nil {
		s.errs.write(w, r, err)
		return
	}
	in := secrets.Input{
		AllowUnprotected: body.AllowUnprotected != nil && *body.AllowUnprotected,
		AllProjects:      body.AllProjects != nil && *body.AllProjects,
	}
	if body.Value != nil {
		in.Value = *body.Value
	}
	if body.Branches != nil {
		in.Branches = *body.Branches
	}
	if body.ProjectSlugs != nil {
		in.ProjectSlugs = *body.ProjectSlugs
	}
	if im := r.Header.Get("If-Match"); im != "" {
		v, err := strconv.ParseInt(strings.Trim(im, `"`), 10, 64)
		if err != nil || v < 1 || im != secretETag(v) {
			s.errs.write(w, r, domain.NewValidationError("If-Match", "must be an ETag from a previous write"))
			return
		}
		in.IfMatch = &v
	}
	res, err := s.secrets.Put(r.Context(), secretTarget(r), r.PathValue("secretName"), in)
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	status := http.StatusOK
	if res.Created {
		status = http.StatusCreated
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", secretETag(res.Secret.ValueVersion))
	writeJSON(w, status, gen.SecretWritten{Secret: toGenSecret(res.Secret), Warnings: nonNilStrings(res.Warnings)})
}

func (s *server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	if err := s.secrets.Delete(r.Context(), secretTarget(r), r.PathValue("secretName")); err != nil {
		s.errs.write(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
