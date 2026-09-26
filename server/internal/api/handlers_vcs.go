// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"net/http"
	"strconv"

	"github.com/yamatrireddy/kilnci/server/internal/api/gen"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	gh "github.com/yamatrireddy/kilnci/server/internal/webhooks/github"
)

// VCSService is what the VCS handlers need from internal/service/vcs.
type VCSService interface {
	Ingest(ctx context.Context, event, deliveryID, signature string, body []byte) error
	BindInstallation(ctx context.Context, installationID int64, orgSlug string) (domain.GitHubInstallation, error)
	UnbindInstallation(ctx context.Context, installationID int64) error
	ListInstallations(ctx context.Context, orgSlug string) ([]domain.GitHubInstallation, error)
	LinkRepository(ctx context.Context, orgSlug, projectSlug string, installationID int64, fullName string) (domain.Repository, error)
	GetRepository(ctx context.Context, orgSlug, projectSlug string) (domain.Repository, error)
	UnlinkRepository(ctx context.Context, orgSlug, projectSlug string) error
	CreateManualRun(ctx context.Context, orgSlug, projectSlug, branch, idempotencyKey string) (domain.Run, error)
}

// githubWebhook reads the raw (size-limited) body and hands it to the
// service, which verifies the signature before anything parses it.
func (s *server) githubWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	if err := s.vcs.Ingest(r.Context(), r.Header.Get(gh.EventHeader), r.Header.Get(gh.DeliveryHeader),
		r.Header.Get(gh.SignatureHeader), body); err != nil {
		s.errs.write(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func toGenInstallation(i domain.GitHubInstallation) gen.GitHubInstallation {
	return gen.GitHubInstallation{InstallationId: i.InstallationID, AccountLogin: i.AccountLogin, CreatedAt: i.CreatedAt, DisabledAt: i.DisabledAt}
}

func toGenRepository(r domain.Repository) gen.Repository {
	return gen.Repository{
		InstallationId: r.InstallationID, RepoId: r.RepoID, FullName: r.FullName, DefaultBranch: r.DefaultBranch,
		Private: r.Private, CreatedAt: r.CreatedAt, DisabledAt: r.DisabledAt,
	}
}

func (s *server) bindGitHubInstallation(w http.ResponseWriter, r *http.Request) {
	var body gen.GitHubInstallationBind
	if err := decodeJSON(r, &body); err != nil {
		s.errs.write(w, r, err)
		return
	}
	b, err := s.vcs.BindInstallation(r.Context(), body.InstallationId, body.OrgSlug)
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toGenInstallation(b))
}

func (s *server) unbindGitHubInstallation(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("installationId"), 10, 64)
	if err != nil {
		s.errs.write(w, r, domain.ErrNotFound)
		return
	}
	if err := s.vcs.UnbindInstallation(r.Context(), id); err != nil {
		s.errs.write(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listGitHubInstallations(w http.ResponseWriter, r *http.Request) {
	list, err := s.vcs.ListInstallations(r.Context(), r.PathValue("orgSlug"))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	out := gen.GitHubInstallationList{Items: make([]gen.GitHubInstallation, len(list))}
	for i, b := range list {
		out.Items[i] = toGenInstallation(b)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) getRepository(w http.ResponseWriter, r *http.Request) {
	repo, err := s.vcs.GetRepository(r.Context(), r.PathValue("orgSlug"), r.PathValue("projectSlug"))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toGenRepository(repo))
}

func (s *server) linkRepository(w http.ResponseWriter, r *http.Request) {
	var body gen.RepositoryLink
	if err := decodeJSON(r, &body); err != nil {
		s.errs.write(w, r, err)
		return
	}
	repo, err := s.vcs.LinkRepository(r.Context(), r.PathValue("orgSlug"), r.PathValue("projectSlug"), body.InstallationId, body.FullName)
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toGenRepository(repo))
}

func (s *server) unlinkRepository(w http.ResponseWriter, r *http.Request) {
	if err := s.vcs.UnlinkRepository(r.Context(), r.PathValue("orgSlug"), r.PathValue("projectSlug")); err != nil {
		s.errs.write(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) createRun(w http.ResponseWriter, r *http.Request) {
	var body gen.RunCreate
	if err := decodeJSON(r, &body); err != nil {
		s.errs.write(w, r, err)
		return
	}
	orgSlug, projectSlug := r.PathValue("orgSlug"), r.PathValue("projectSlug")
	run, err := s.vcs.CreateManualRun(r.Context(), orgSlug, projectSlug, body.Branch, r.Header.Get("Idempotency-Key"))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/orgs/"+orgSlug+"/projects/"+projectSlug+"/runs/"+run.ID)
	writeJSON(w, http.StatusCreated, toGenRun(run))
}
