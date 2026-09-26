// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/vcs/github"
)

// BindInstallation binds a GitHub App installation to an org (instance
// admins only, ADR-0008 §2). The installation must exist for this App and
// must not be bound already.
func (s *Service) BindInstallation(ctx context.Context, installationID int64, orgSlug string) (domain.GitHubInstallation, error) {
	ctx, span := tracer.Start(ctx, "vcs.BindInstallation")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return domain.GitHubInstallation{}, err
	}
	if err := s.az.Check(ctx, p, authz.ActionVCSInstallationsManage, authz.Resource{}); err != nil {
		return domain.GitHubInstallation{}, fmt.Errorf("authorize: %w", err)
	}
	if s.gh == nil {
		return domain.GitHubInstallation{}, ErrNotConfigured
	}
	if installationID <= 0 {
		return domain.GitHubInstallation{}, domain.NewValidationError("installationId", "must be positive")
	}
	if domain.ValidateSlug("orgSlug", orgSlug) != nil {
		return domain.GitHubInstallation{}, domain.NewValidationError("orgSlug", "is not a valid slug")
	}
	org, err := s.store.GetOrgBySlug(ctx, orgSlug)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.GitHubInstallation{}, domain.NewValidationError("orgSlug", "does not exist")
	}
	if err != nil {
		return domain.GitHubInstallation{}, fmt.Errorf("bind installation: %w", err)
	}
	inst, err := s.gh.GetInstallation(ctx, installationID)
	if errors.Is(err, github.ErrNotFound) {
		return domain.GitHubInstallation{}, domain.NewValidationError("installationId", "is not an installation of this GitHub App")
	}
	if err != nil {
		return domain.GitHubInstallation{}, fmt.Errorf("bind installation: %w", err)
	}
	b := domain.GitHubInstallation{
		InstallationID: installationID, OrgID: org.ID, AccountLogin: truncate(inst.AccountLogin, 255), BoundBy: p.UserID, CreatedAt: s.now().UTC(),
	}
	ctx = logging.WithOrgID(ctx, org.ID)
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		if err := s.store.BindGitHubInstallation(ctx, b); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		return s.audit.Record(ctx, audit.Entry{
			OrgID: org.ID, Action: "vcs:installation:bind", TargetType: "github_installation",
			TargetID: strconv.FormatInt(installationID, 10), Details: map[string]string{"account": b.AccountLogin},
		})
	})
	if err != nil {
		return domain.GitHubInstallation{}, fmt.Errorf("bind installation: %w", err)
	}
	return b, nil
}

// UnbindInstallation removes a binding and every repository link that used
// it (instance admins only).
func (s *Service) UnbindInstallation(ctx context.Context, installationID int64) error {
	ctx, span := tracer.Start(ctx, "vcs.UnbindInstallation")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return err
	}
	if err := s.az.Check(ctx, p, authz.ActionVCSInstallationsManage, authz.Resource{}); err != nil {
		return fmt.Errorf("authorize: %w", err)
	}
	b, err := s.store.GetGitHubInstallation(ctx, installationID)
	if err != nil {
		return fmt.Errorf("unbind installation: %w", err)
	}
	ctx = logging.WithOrgID(ctx, b.OrgID)
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		if err := s.store.DeleteGitHubInstallation(ctx, installationID); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		return s.audit.Record(ctx, audit.Entry{
			OrgID: b.OrgID, Action: "vcs:installation:unbind", TargetType: "github_installation", TargetID: strconv.FormatInt(installationID, 10),
		})
	})
	if err != nil {
		return fmt.Errorf("unbind installation: %w", err)
	}
	return nil
}

// ListInstallations lists the installations bound to an org (org admins).
func (s *Service) ListInstallations(ctx context.Context, orgSlug string) ([]domain.GitHubInstallation, error) {
	ctx, span := tracer.Start(ctx, "vcs.ListInstallations")
	defer span.End()
	_, org, err := s.resolveOrg(ctx, orgSlug, authz.ActionVCSInstallationsList)
	if err != nil {
		return nil, err
	}
	out, err := s.store.ListGitHubInstallationsForOrg(ctx, org.ID)
	if err != nil {
		return nil, fmt.Errorf("list installations: %w", err)
	}
	return out, nil
}

// LinkRepository links a project to a repository (org admins). The
// installation must be bound to the project's own org and must be able to
// see the repository; the link records the repository's immutable ID.
func (s *Service) LinkRepository(ctx context.Context, orgSlug, projectSlug string, installationID int64, fullName string) (domain.Repository, error) {
	ctx, span := tracer.Start(ctx, "vcs.LinkRepository")
	defer span.End()
	p, proj, err := s.resolveProject(ctx, orgSlug, projectSlug, authz.ActionRepositoryManage)
	if err != nil {
		return domain.Repository{}, err
	}
	if s.gh == nil {
		return domain.Repository{}, ErrNotConfigured
	}
	b, err := s.store.GetGitHubInstallation(ctx, installationID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && (b.OrgID != proj.OrgID || b.DisabledAt != nil)) {
		// Another tenant's installation is indistinguishable from none.
		return domain.Repository{}, domain.NewValidationError("installationId", "is not an installation bound to this org")
	}
	if err != nil {
		return domain.Repository{}, fmt.Errorf("link repository: %w", err)
	}
	if !github.ValidFullName(fullName) {
		return domain.Repository{}, domain.NewValidationError("fullName", "must be owner/repository")
	}
	repo, err := s.gh.GetRepository(ctx, installationID, fullName)
	if errors.Is(err, github.ErrNotFound) {
		return domain.Repository{}, domain.NewValidationError("fullName", "is not accessible to this installation")
	}
	if err != nil {
		return domain.Repository{}, fmt.Errorf("link repository: %w", err)
	}
	link := domain.Repository{
		ID: s.ids.New(), OrgID: proj.OrgID, ProjectID: proj.ID, InstallationID: installationID, RepoID: repo.ID,
		FullName: truncate(repo.FullName, 255), CloneURL: repo.CloneURL, DefaultBranch: truncate(repo.DefaultBranch, 255),
		Private: repo.Private, LinkedBy: p.UserID, CreatedAt: s.now().UTC(),
	}
	ctx = logging.WithOrgID(ctx, proj.OrgID)
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		if err := s.store.LinkRepository(ctx, link); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		return s.audit.Record(ctx, audit.Entry{
			OrgID: proj.OrgID, Action: "repository:link", TargetType: "project", TargetID: proj.ID,
			Details: map[string]string{"repo_id": strconv.FormatInt(repo.ID, 10), "full_name": link.FullName, "installation_id": strconv.FormatInt(installationID, 10)},
		})
	})
	if err != nil {
		return domain.Repository{}, fmt.Errorf("link repository: %w", err)
	}
	return link, nil
}

// GetRepository returns a project's repository link (org viewers).
func (s *Service) GetRepository(ctx context.Context, orgSlug, projectSlug string) (domain.Repository, error) {
	ctx, span := tracer.Start(ctx, "vcs.GetRepository")
	defer span.End()
	_, proj, err := s.resolveProject(ctx, orgSlug, projectSlug, authz.ActionRepositoryRead)
	if err != nil {
		return domain.Repository{}, err
	}
	r, err := s.store.GetRepositoryForProject(ctx, proj.OrgID, proj.ID)
	if err != nil {
		return domain.Repository{}, fmt.Errorf("get repository: %w", err)
	}
	return r, nil
}

// UnlinkRepository removes a project's repository link (org admins).
func (s *Service) UnlinkRepository(ctx context.Context, orgSlug, projectSlug string) error {
	ctx, span := tracer.Start(ctx, "vcs.UnlinkRepository")
	defer span.End()
	_, proj, err := s.resolveProject(ctx, orgSlug, projectSlug, authz.ActionRepositoryManage)
	if err != nil {
		return err
	}
	ctx = logging.WithOrgID(ctx, proj.OrgID)
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		if err := s.store.UnlinkRepository(ctx, proj.OrgID, proj.ID); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		return s.audit.Record(ctx, audit.Entry{OrgID: proj.OrgID, Action: "repository:unlink", TargetType: "project", TargetID: proj.ID})
	})
	if err != nil {
		return fmt.Errorf("unlink repository: %w", err)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
