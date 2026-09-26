// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/api/gen"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/service/paging"
)

// RunnerService is what the runner handlers need from internal/service/runners.
type RunnerService interface {
	CreateRegistrationToken(ctx context.Context, orgSlug string, labels []string, trusted bool, ttl time.Duration) (string, domain.RunnerRegistrationToken, error)
	ListRunners(ctx context.Context, orgSlug string, pr paging.Request) (paging.Page[domain.Runner], error)
	RevokeRunner(ctx context.Context, orgSlug, runnerID string) error
}

func toGenRunner(r domain.Runner) gen.Runner {
	return gen.Runner{
		Id: r.ID, Name: r.Name, Labels: nonNilStrings(r.Labels), Trusted: r.Trusted, Version: r.Version,
		CreatedAt: r.CreatedAt, CertExpiresAt: r.CertExpiresAt, LastSeenAt: r.LastSeenAt, RevokedAt: r.RevokedAt,
	}
}

func (s *server) listRunners(w http.ResponseWriter, r *http.Request) {
	pg, err := s.runners.ListRunners(r.Context(), r.PathValue("orgSlug"), pageRequest(r))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	out := gen.RunnerList{Items: make([]gen.Runner, len(pg.Items)), NextCursor: nextCursor(pg.NextCursor)}
	for i, rn := range pg.Items {
		out.Items[i] = toGenRunner(rn)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) revokeRunner(w http.ResponseWriter, r *http.Request) {
	if err := s.runners.RevokeRunner(r.Context(), r.PathValue("orgSlug"), r.PathValue("runnerId")); err != nil {
		s.errs.write(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) createRunnerRegistrationToken(w http.ResponseWriter, r *http.Request) {
	var body gen.RunnerRegistrationTokenCreate
	if err := decodeJSON(r, &body); err != nil {
		s.errs.write(w, r, err)
		return
	}
	token, meta, err := s.runners.CreateRegistrationToken(r.Context(), r.PathValue("orgSlug"), body.Labels, body.Trusted,
		time.Duration(body.ExpiresInMinutes)*time.Minute)
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, gen.RunnerRegistrationTokenCreated{
		Token: token,
		RegistrationToken: gen.RunnerRegistrationToken{
			Id: meta.ID, Labels: nonNilStrings(meta.Labels), Trusted: meta.Trusted, CreatedAt: meta.CreatedAt, ExpiresAt: meta.ExpiresAt,
		},
	})
}
