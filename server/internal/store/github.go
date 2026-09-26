// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/store/db"
)

func toInstallation(r db.GithubInstallation) domain.GitHubInstallation {
	return domain.GitHubInstallation{
		InstallationID: r.InstallationID, OrgID: r.OrgID, AccountLogin: r.AccountLogin, BoundBy: deref(r.BoundBy),
		CreatedAt: r.CreatedAt, DisabledAt: r.DisabledAt,
	}
}

func toRepository(r db.Repository) domain.Repository {
	return domain.Repository{
		ID: r.ID, OrgID: r.OrgID, ProjectID: r.ProjectID, InstallationID: r.InstallationID, RepoID: r.RepoID,
		FullName: r.FullName, CloneURL: r.CloneUrl, DefaultBranch: r.DefaultBranch, Private: r.Private,
		LinkedBy: deref(r.LinkedBy), CreatedAt: r.CreatedAt, DisabledAt: r.DisabledAt,
	}
}

// BindGitHubInstallation binds an installation to an org; domain.ErrConflict
// if it is already bound.
func (s *Store) BindGitHubInstallation(ctx context.Context, i domain.GitHubInstallation) error {
	return mapErr("bind github installation", s.q(ctx).BindGitHubInstallation(ctx, db.BindGitHubInstallationParams{
		InstallationID: i.InstallationID, OrgID: i.OrgID, AccountLogin: i.AccountLogin, BoundBy: nilIfEmpty(i.BoundBy), CreatedAt: i.CreatedAt,
	}))
}

// GetGitHubInstallation returns a binding.
func (s *Store) GetGitHubInstallation(ctx context.Context, installationID int64) (domain.GitHubInstallation, error) {
	r, err := s.q(ctx).GetGitHubInstallation(ctx, installationID)
	return toInstallation(r), mapErr("get github installation", err)
}

// ListGitHubInstallationsForOrg lists an org's bound installations.
func (s *Store) ListGitHubInstallationsForOrg(ctx context.Context, orgID string) ([]domain.GitHubInstallation, error) {
	rows, err := s.q(ctx).ListGitHubInstallationsForOrg(ctx, orgID)
	if err != nil {
		return nil, mapErr("list github installations", err)
	}
	out := make([]domain.GitHubInstallation, len(rows))
	for i, r := range rows {
		out[i] = toInstallation(r)
	}
	return out, nil
}

// DeleteGitHubInstallation removes a binding (and, by cascade, its links).
func (s *Store) DeleteGitHubInstallation(ctx context.Context, installationID int64) error {
	n, err := s.q(ctx).DeleteGitHubInstallation(ctx, installationID)
	if err == nil && n == 0 {
		return fmt.Errorf("delete github installation: %w", domain.ErrNotFound)
	}
	return mapErr("delete github installation", err)
}

// DisableGitHubInstallation disables a binding and all its repository links
// (the installation was deleted or suspended on GitHub).
func (s *Store) DisableGitHubInstallation(ctx context.Context, installationID int64, now time.Time) error {
	if err := s.q(ctx).DisableGitHubInstallation(ctx, db.DisableGitHubInstallationParams{Now: &now, InstallationID: installationID}); err != nil {
		return mapErr("disable github installation", err)
	}
	return mapErr("disable repositories", s.q(ctx).DisableRepositoriesForInstallation(ctx, db.DisableRepositoriesForInstallationParams{Now: &now, InstallationID: installationID}))
}

// DisableRepositories disables the links of repositories removed from an
// installation.
func (s *Store) DisableRepositories(ctx context.Context, installationID int64, repoIDs []int64, now time.Time) error {
	return mapErr("disable repositories", s.q(ctx).DisableRepositoriesByRepoID(ctx, db.DisableRepositoriesByRepoIDParams{
		Now: &now, InstallationID: installationID, RepoIds: repoIDs,
	}))
}

// LinkRepository links a project to a repository; domain.ErrConflict if the
// project or the repository is already linked, domain.ErrNotFound if the
// installation is not bound to the project's org.
func (s *Store) LinkRepository(ctx context.Context, r domain.Repository) error {
	return mapErr("link repository", s.q(ctx).LinkRepository(ctx, db.LinkRepositoryParams{
		ID: r.ID, OrgID: r.OrgID, ProjectID: r.ProjectID, InstallationID: r.InstallationID, RepoID: r.RepoID,
		FullName: r.FullName, CloneUrl: r.CloneURL, DefaultBranch: r.DefaultBranch, Private: r.Private,
		LinkedBy: nilIfEmpty(r.LinkedBy), CreatedAt: r.CreatedAt,
	}))
}

// GetRepositoryForProject returns a project's repository link.
func (s *Store) GetRepositoryForProject(ctx context.Context, orgID, projectID string) (domain.Repository, error) {
	r, err := s.q(ctx).GetRepositoryForProject(ctx, db.GetRepositoryForProjectParams{OrgID: orgID, ProjectID: projectID})
	return toRepository(r), mapErr("get repository", err)
}

// GetActiveRepositoryByRepoID returns the enabled link for a GitHub
// repository whose installation binding is enabled.
func (s *Store) GetActiveRepositoryByRepoID(ctx context.Context, repoID int64) (domain.Repository, error) {
	r, err := s.q(ctx).GetActiveRepositoryByRepoID(ctx, repoID)
	return toRepository(r), mapErr("get repository by repo id", err)
}

// UnlinkRepository removes a project's repository link.
func (s *Store) UnlinkRepository(ctx context.Context, orgID, projectID string) error {
	n, err := s.q(ctx).UnlinkRepository(ctx, db.UnlinkRepositoryParams{OrgID: orgID, ProjectID: projectID})
	if err == nil && n == 0 {
		return fmt.Errorf("unlink repository: %w", domain.ErrNotFound)
	}
	return mapErr("unlink repository", err)
}

// WebhookDelivery is a verified delivery to process.
type WebhookDelivery struct {
	ID         string
	DeliveryID string
	BodySHA256 []byte
	Event      string
	Payload    []byte
	ReceivedAt time.Time
	Attempts   int
}

// InsertWebhookDelivery queues a delivery. It reports false (and stores
// nothing) if the delivery ID or the exact body was seen before.
func (s *Store) InsertWebhookDelivery(ctx context.Context, d WebhookDelivery) (bool, error) {
	n, err := s.q(ctx).InsertWebhookDelivery(ctx, db.InsertWebhookDeliveryParams{
		ID: d.ID, DeliveryID: d.DeliveryID, BodySha256: d.BodySHA256, Event: d.Event, Payload: d.Payload, ReceivedAt: d.ReceivedAt,
	})
	return n > 0, mapErr("insert webhook delivery", err)
}

// ClaimWebhookDeliveries locks up to limit due deliveries (inside InTx).
func (s *Store) ClaimWebhookDeliveries(ctx context.Context, now time.Time, limit int32) ([]WebhookDelivery, error) {
	rows, err := s.q(ctx).ClaimWebhookDeliveries(ctx, db.ClaimWebhookDeliveriesParams{Now: now, MaxRows: limit})
	if err != nil {
		return nil, mapErr("claim webhook deliveries", err)
	}
	out := make([]WebhookDelivery, len(rows))
	for i, r := range rows {
		out[i] = WebhookDelivery{ID: r.ID, Event: r.Event, Payload: r.Payload, Attempts: int(r.Attempts)}
	}
	return out, nil
}

// FinishWebhookDelivery records a delivery's final outcome.
func (s *Store) FinishWebhookDelivery(ctx context.Context, id string, failed bool, outcome string, now time.Time) error {
	st := "done"
	if failed {
		st = "failed"
	}
	return mapErr("finish webhook delivery", s.q(ctx).FinishWebhookDelivery(ctx, db.FinishWebhookDeliveryParams{
		Status: st, Outcome: outcome, Now: &now, ID: id,
	}))
}

// RetryWebhookDelivery schedules another attempt.
func (s *Store) RetryWebhookDelivery(ctx context.Context, id, outcome string, next time.Time) error {
	return mapErr("retry webhook delivery", s.q(ctx).RetryWebhookDelivery(ctx, db.RetryWebhookDeliveryParams{NextAttemptAt: next, Outcome: outcome, ID: id}))
}

// DeleteOldWebhookDeliveries prunes deduplication records older than before.
func (s *Store) DeleteOldWebhookDeliveries(ctx context.Context, before time.Time) (int64, error) {
	n, err := s.q(ctx).DeleteOldWebhookDeliveries(ctx, before)
	return n, mapErr("delete old webhook deliveries", err)
}

// CommitStatus is an outbox entry.
type CommitStatus struct {
	ID, OrgID, RunID       string
	RepoID, InstallationID int64
	CommitSHA              string
	State, Context         string
	Description, TargetURL string
	CreatedAt              time.Time
	Attempts               int
}

// InsertCommitStatus queues a commit status.
func (s *Store) InsertCommitStatus(ctx context.Context, c CommitStatus) error {
	return mapErr("insert commit status", s.q(ctx).InsertCommitStatus(ctx, db.InsertCommitStatusParams{
		ID: c.ID, OrgID: c.OrgID, RunID: c.RunID, RepoID: c.RepoID, InstallationID: c.InstallationID, CommitSha: c.CommitSHA,
		State: c.State, Context: c.Context, Description: c.Description, TargetUrl: c.TargetURL, CreatedAt: c.CreatedAt,
	}))
}

// ClaimCommitStatuses marks superseded entries sent and locks up to limit
// due ones (inside InTx).
func (s *Store) ClaimCommitStatuses(ctx context.Context, now time.Time, limit int32) ([]CommitStatus, error) {
	if err := s.q(ctx).SupersedeCommitStatuses(ctx, &now); err != nil {
		return nil, mapErr("supersede commit statuses", err)
	}
	rows, err := s.q(ctx).ClaimCommitStatuses(ctx, db.ClaimCommitStatusesParams{Now: now, MaxRows: limit})
	if err != nil {
		return nil, mapErr("claim commit statuses", err)
	}
	out := make([]CommitStatus, len(rows))
	for i, r := range rows {
		out[i] = CommitStatus{ID: r.ID, InstallationID: r.InstallationID, RepoID: r.RepoID, CommitSHA: r.CommitSha,
			State: r.State, Context: r.Context, Description: r.Description, TargetURL: r.TargetUrl, Attempts: int(r.Attempts)}
	}
	return out, nil
}

// MarkCommitStatusSent records a delivered (or abandoned) status.
func (s *Store) MarkCommitStatusSent(ctx context.Context, id string, now time.Time) error {
	return mapErr("mark commit status sent", s.q(ctx).MarkCommitStatusSent(ctx, db.MarkCommitStatusSentParams{Now: &now, ID: id}))
}

// RetryCommitStatus schedules another attempt.
func (s *Store) RetryCommitStatus(ctx context.Context, id string, next time.Time) error {
	return mapErr("retry commit status", s.q(ctx).RetryCommitStatus(ctx, db.RetryCommitStatusParams{NextAttemptAt: next, ID: id}))
}

// StatusTarget is where a run's commit status goes.
type StatusTarget struct {
	RepoID, InstallationID int64
	OrgSlug, ProjectSlug   string
}

// GetRunStatusTarget returns the active repository link of a run's project.
func (s *Store) GetRunStatusTarget(ctx context.Context, orgID, projectID string) (StatusTarget, error) {
	r, err := s.q(ctx).GetRunStatusTarget(ctx, db.GetRunStatusTargetParams{OrgID: orgID, ProjectID: projectID})
	return StatusTarget{RepoID: r.RepoID, InstallationID: r.InstallationID, OrgSlug: r.OrgSlug, ProjectSlug: r.ProjectSlug},
		mapErr("get run status target", err)
}
