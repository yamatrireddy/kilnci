// SPDX-License-Identifier: Apache-2.0

// Package vcs connects projects to GitHub (ADR-0008): instance admins bind
// App installations to orgs, org admins link a project to one repository of
// their own org's installations, verified webhooks are queued and turned
// into runs by a worker, developers start runs on a branch, commit statuses
// are delivered from an outbox, and runners get a short-lived, read-only,
// single-repository checkout credential for private repositories.
package vcs

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/service/runs"
	"github.com/yamatrireddy/kilnci/server/internal/store"
	"github.com/yamatrireddy/kilnci/server/internal/vcs/github"
)

var tracer = otel.Tracer("github.com/yamatrireddy/kilnci/server/internal/service/vcs")

// GitHub is what this service needs from internal/vcs/github.
type GitHub interface {
	Token(ctx context.Context, installationID, repoID int64, perms map[string]string) (string, time.Time, error)
	GetInstallation(ctx context.Context, installationID int64) (github.Installation, error)
	GetRepository(ctx context.Context, installationID int64, fullName string) (github.Repository, error)
	GetFile(ctx context.Context, installationID, repoID int64, filePath, sha string, maxBytes int64) ([]byte, error)
	ResolveBranch(ctx context.Context, installationID, repoID int64, branch string) (string, error)
	CreateStatus(ctx context.Context, installationID, repoID int64, sha string, s github.Status) error
}

// Store is the persistence this service needs.
type Store interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
	GetOrgForMember(ctx context.Context, slug, userID string) (domain.OrgWithRole, error)
	GetOrgBySlug(ctx context.Context, slug string) (domain.Org, error)
	GetProject(ctx context.Context, orgID, slug string) (domain.Project, error)
	BindGitHubInstallation(ctx context.Context, i domain.GitHubInstallation) error
	GetGitHubInstallation(ctx context.Context, installationID int64) (domain.GitHubInstallation, error)
	ListGitHubInstallationsForOrg(ctx context.Context, orgID string) ([]domain.GitHubInstallation, error)
	DeleteGitHubInstallation(ctx context.Context, installationID int64) error
	DisableGitHubInstallation(ctx context.Context, installationID int64, now time.Time) error
	DisableRepositories(ctx context.Context, installationID int64, repoIDs []int64, now time.Time) error
	LinkRepository(ctx context.Context, r domain.Repository) error
	GetRepositoryForProject(ctx context.Context, orgID, projectID string) (domain.Repository, error)
	GetActiveRepositoryByRepoID(ctx context.Context, repoID int64) (domain.Repository, error)
	UnlinkRepository(ctx context.Context, orgID, projectID string) error
	InsertWebhookDelivery(ctx context.Context, d store.WebhookDelivery) (bool, error)
	ClaimWebhookDeliveries(ctx context.Context, now time.Time, limit int32) ([]store.WebhookDelivery, error)
	FinishWebhookDelivery(ctx context.Context, id string, failed bool, outcome string, now time.Time) error
	RetryWebhookDelivery(ctx context.Context, id, outcome string, next time.Time) error
	DeleteOldWebhookDeliveries(ctx context.Context, before time.Time) (int64, error)
	InsertCommitStatus(ctx context.Context, c store.CommitStatus) error
	ClaimCommitStatuses(ctx context.Context, now time.Time, limit int32) ([]store.CommitStatus, error)
	MarkCommitStatusSent(ctx context.Context, id string, now time.Time) error
	RetryCommitStatus(ctx context.Context, id string, next time.Time) error
	GetRunStatusTarget(ctx context.Context, orgID, projectID string) (store.StatusTarget, error)
}

// Authorizer decides whether a principal may act on a resource.
type Authorizer interface {
	Check(ctx context.Context, p *authz.Principal, a authz.Action, res authz.Resource) error
}

// Auditor records privileged actions.
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) error
}

// RunCreator creates runs (internal/service/runs).
type RunCreator interface {
	CreateRun(ctx context.Context, nr runs.NewRun) (domain.Run, error)
}

// Options configures the service.
type Options struct {
	// WebhookSecret verifies deliveries; empty disables webhook ingest.
	WebhookSecret []byte
	// PublicOrigin builds links in commit statuses.
	PublicOrigin string
	Log          *slog.Logger
}

// Service implements the VCS use cases. gh may be nil when GitHub is not
// configured; every GitHub-backed operation then fails with ErrNotConfigured.
type Service struct {
	store Store
	az    Authorizer
	audit Auditor
	gh    GitHub
	runs  RunCreator
	ids   *ids.Generator
	opts  Options
	now   func() time.Time
}

// ErrNotConfigured means the GitHub App is not configured on this server.
var ErrNotConfigured = fmt.Errorf("GitHub integration is not configured: %w", domain.ErrNotFound)

// NewService returns a Service. now may be nil.
func NewService(s Store, az Authorizer, a Auditor, gh GitHub, rc RunCreator, gen *ids.Generator, opts Options, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	return &Service{store: s, az: az, audit: a, gh: gh, runs: rc, ids: gen, opts: opts, now: now}
}

func principal(ctx context.Context) (*authz.Principal, error) {
	p, ok := authz.FromContext(ctx)
	if !ok {
		return nil, domain.ErrUnauthenticated
	}
	return p, nil
}

// resolveOrg finds an org through the caller's membership and authorizes a.
func (s *Service) resolveOrg(ctx context.Context, orgSlug string, a authz.Action) (*authz.Principal, domain.OrgWithRole, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, domain.OrgWithRole{}, err
	}
	if domain.ValidateSlug("orgSlug", orgSlug) != nil {
		return nil, domain.OrgWithRole{}, domain.ErrNotFound
	}
	org, err := s.store.GetOrgForMember(ctx, orgSlug, p.UserID)
	if err != nil {
		return nil, domain.OrgWithRole{}, fmt.Errorf("resolve org: %w", err)
	}
	if err := s.az.Check(ctx, p, a, authz.Resource{OrgID: org.ID}); err != nil {
		return nil, domain.OrgWithRole{}, fmt.Errorf("authorize %s: %w", a, err)
	}
	return p, org, nil
}

func (s *Service) resolveProject(ctx context.Context, orgSlug, projectSlug string, a authz.Action) (*authz.Principal, domain.Project, error) {
	p, org, err := s.resolveOrg(ctx, orgSlug, a)
	if err != nil {
		return nil, domain.Project{}, err
	}
	if domain.ValidateSlug("projectSlug", projectSlug) != nil {
		return nil, domain.Project{}, domain.ErrNotFound
	}
	proj, err := s.store.GetProject(ctx, org.ID, projectSlug)
	if err != nil {
		return nil, domain.Project{}, fmt.Errorf("resolve project: %w", err)
	}
	return p, proj, nil
}
