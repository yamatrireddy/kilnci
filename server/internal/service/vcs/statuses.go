// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/engine/spec"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/service/runs"
	"github.com/yamatrireddy/kilnci/server/internal/store"
	"github.com/yamatrireddy/kilnci/server/internal/vcs/github"
)

// statusFor maps a run status to a GitHub commit status.
func statusFor(r domain.Run) (state, description string) {
	switch r.Status {
	case domain.RunAwaitingApproval:
		return "pending", "Waiting for a maintainer to approve the run"
	case domain.RunQueued:
		return "pending", "Queued"
	case domain.RunRunning:
		return "pending", "Running"
	case domain.RunSucceeded:
		return "success", "Succeeded"
	case domain.RunCanceled:
		return "error", "Canceled"
	default:
		if r.Error != "" {
			return "error", "The pipeline could not be loaded"
		}
		return "failure", "Failed"
	}
}

// RunChanged queues a commit status for a run of a linked project, inside
// the transaction that changed the run (scheduler.RunObserver).
func (s *Service) RunChanged(ctx context.Context, r domain.Run) error {
	target, err := s.store.GetRunStatusTarget(ctx, r.OrgID, r.ProjectID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil // no active repository link
	}
	if err != nil {
		return fmt.Errorf("status target: %w", err)
	}
	state, desc := statusFor(r)
	return s.store.InsertCommitStatus(ctx, store.CommitStatus{ //nolint:wrapcheck // store errors are contextual
		ID: s.ids.New(), OrgID: r.OrgID, RunID: r.ID, RepoID: target.RepoID, InstallationID: target.InstallationID,
		CommitSHA: r.CommitSHA, State: state, Context: "kiln/" + target.ProjectSlug, Description: desc,
		TargetURL: s.opts.PublicOrigin + "/orgs/" + url.PathEscape(target.OrgSlug) + "/projects/" +
			url.PathEscape(target.ProjectSlug) + "/runs/" + r.ID,
		CreatedAt: s.now().UTC(),
	})
}

// Outbox delivery.
const (
	statusBatch       = 50
	maxStatusAttempts = 10
)

// DeliverStatuses posts due commit statuses to GitHub. An older status for
// the same commit and context is superseded by a newer one and never sent.
func (s *Service) DeliverStatuses(ctx context.Context) (int, error) {
	if s.gh == nil {
		return 0, nil
	}
	ctx, span := tracer.Start(ctx, "vcs.DeliverStatuses")
	defer span.End()
	sent := 0
	err := s.store.InTx(ctx, func(ctx context.Context) error {
		now := s.now().UTC()
		batch, err := s.store.ClaimCommitStatuses(ctx, now, statusBatch)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		for _, c := range batch {
			err := s.gh.CreateStatus(ctx, c.InstallationID, c.RepoID, c.CommitSHA, github.Status{
				State: c.State, Context: c.Context, Description: c.Description, TargetURL: c.TargetURL,
			})
			switch {
			case err == nil, errors.Is(err, github.ErrNotFound), c.Attempts+1 >= maxStatusAttempts:
				if err != nil {
					s.opts.Log.WarnContext(ctx, "dropping commit status", "error", err)
				}
				if err := s.store.MarkCommitStatusSent(ctx, c.ID, now); err != nil {
					return err //nolint:wrapcheck // store errors are contextual
				}
				sent++
			default:
				backoff := time.Duration(5<<min(c.Attempts, 8)) * time.Second
				if err := s.store.RetryCommitStatus(ctx, c.ID, now.Add(backoff)); err != nil {
					return err //nolint:wrapcheck // store errors are contextual
				}
			}
		}
		return nil
	})
	if err != nil {
		return sent, fmt.Errorf("deliver statuses: %w", err)
	}
	return sent, nil
}

// Checkout is where a run's code comes from.
type Checkout struct {
	RepositoryURL       string
	AuthorizationHeader string
}

// Checkout returns the clone URL of a run's repository and, for private
// repositories only, a short-lived Authorization header for an installation
// token limited to contents:read on that one repository (ADR-0006 §3).
// Public repositories get no credential at all.
func (s *Service) Checkout(ctx context.Context, r domain.Run) (Checkout, error) {
	link, err := s.store.GetRepositoryForProject(ctx, r.OrgID, r.ProjectID)
	if errors.Is(err, domain.ErrNotFound) {
		return Checkout{}, nil // not linked: empty workspace
	}
	if err != nil {
		return Checkout{}, fmt.Errorf("checkout: %w", err)
	}
	if link.DisabledAt != nil {
		return Checkout{}, fmt.Errorf("checkout: repository link is disabled: %w", domain.ErrConflict)
	}
	co := Checkout{RepositoryURL: link.CloneURL}
	if !link.Private {
		return co, nil
	}
	if s.gh == nil {
		return Checkout{}, ErrNotConfigured
	}
	tok, _, err := s.gh.Token(ctx, link.InstallationID, link.RepoID, github.PermContentsRead)
	if err != nil {
		return Checkout{}, fmt.Errorf("checkout token: %w", err)
	}
	co.AuthorizationHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+tok))
	return co, nil
}

// CreateManualRun starts a run of the pipeline at the head of branch
// (developers). An Idempotency-Key makes retries return the same run.
func (s *Service) CreateManualRun(ctx context.Context, orgSlug, projectSlug, branch, idempotencyKey string) (domain.Run, error) {
	ctx, span := tracer.Start(ctx, "vcs.CreateManualRun")
	defer span.End()
	p, proj, err := s.resolveProject(ctx, orgSlug, projectSlug, authz.ActionRunsCreate)
	if err != nil {
		return domain.Run{}, err
	}
	if !validBranch(branch) {
		return domain.Run{}, domain.NewValidationError("branch", "is not a valid branch name")
	}
	if len(idempotencyKey) > 255 {
		return domain.Run{}, domain.NewValidationError("Idempotency-Key", "must be at most 255 characters")
	}
	if s.gh == nil {
		return domain.Run{}, ErrNotConfigured
	}
	link, err := s.store.GetRepositoryForProject(ctx, proj.OrgID, proj.ID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && link.DisabledAt != nil) {
		return domain.Run{}, fmt.Errorf("project has no linked repository: %w", domain.ErrConflict)
	}
	if err != nil {
		return domain.Run{}, fmt.Errorf("manual run: %w", err)
	}
	sha, err := s.gh.ResolveBranch(ctx, link.InstallationID, link.RepoID, branch)
	if errors.Is(err, github.ErrNotFound) {
		return domain.Run{}, domain.NewValidationError("branch", "does not exist")
	}
	if err != nil {
		return domain.Run{}, fmt.Errorf("manual run: %w", err)
	}
	pl, loadErr, err := s.loadPipeline(ctx, link, sha)
	if err != nil {
		return domain.Run{}, fmt.Errorf("manual run: %w", err)
	}
	if errors.Is(loadErr, runs.ErrNoPipeline) {
		return domain.Run{}, domain.NewValidationError("branch", "has no "+spec.Path)
	}
	run, err := s.runs.CreateRun(ctx, runs.NewRun{
		OrgID: proj.OrgID, ProjectID: proj.ID, Event: domain.EventManual, Ref: "refs/heads/" + branch, Branch: branch,
		CommitSHA: sha, Title: "Manual run on " + branch, ActorLogin: p.UserID, CreatedBy: p.UserID,
		// A developer running a branch of the linked repository is trusted.
		Trusted: true, IdempotencyKey: idempotencyKey, Pipeline: pl, PipelineErr: loadErr,
	})
	if err != nil {
		return domain.Run{}, fmt.Errorf("manual run: %w", err)
	}
	if err := s.audit.Record(logging.WithOrgID(ctx, proj.OrgID), audit.Entry{
		OrgID: proj.OrgID, Action: "runs:create", TargetType: "run", TargetID: run.ID,
		Details: map[string]string{"project_id": proj.ID, "branch": branch, "commit_sha": sha},
	}); err != nil {
		return domain.Run{}, fmt.Errorf("manual run: %w", err)
	}
	return run, nil
}
