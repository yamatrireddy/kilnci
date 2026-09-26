// SPDX-License-Identifier: Apache-2.0

// Package scheduler moves runs and jobs through their lifecycles: it queues
// jobs whose dependencies succeeded, skips jobs whose dependencies did not,
// finalizes runs, hands queued jobs to runners under time-bound leases, and
// reaps expired leases and timed-out jobs (ADR-0005 §7).
//
// Every status change is validated by internal/engine and applied by the
// store as a compare-and-swap, and all changes for one run happen while the
// run row is locked, so concurrent runners, reapers, and users cannot race.
package scheduler

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/engine"
	"github.com/yamatrireddy/kilnci/server/internal/engine/dag"
	"github.com/yamatrireddy/kilnci/server/internal/store"
)

var tracer = otel.Tracer("github.com/yamatrireddy/kilnci/server/internal/scheduler")

// ProgressStore is the persistence Progress needs.
type ProgressStore interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
	LockRun(ctx context.Context, orgID, runID string) (domain.Run, error)
	ListJobs(ctx context.Context, orgID, runID string) ([]domain.Job, error)
	UpdateJobStatus(ctx context.Context, c store.JobStatusChange) error
	UpdateRunStatus(ctx context.Context, c store.RunStatusChange) error
}

// RunObserver is told about every run status change, inside the
// transaction that made it, so side effects (commit statuses) commit or roll
// back with the change.
type RunObserver interface {
	RunChanged(ctx context.Context, run domain.Run) error
}

// Progressor advances runs. It is safe for concurrent use once built.
type Progressor struct {
	store    ProgressStore
	now      func() time.Time
	observer RunObserver
}

// SetObserver registers o; call it during wiring, before any use.
func (p *Progressor) SetObserver(o RunObserver) { p.observer = o }

// NewProgressor returns a Progressor. now may be nil (time.Now).
func NewProgressor(s ProgressStore, now func() time.Time) *Progressor {
	if now == nil {
		now = time.Now
	}
	return &Progressor{store: s, now: now}
}

// SkipReason is recorded on jobs skipped because a dependency did not succeed.
const SkipReason = "a job it needs did not succeed"

func outcomeOf(s domain.JobStatus) dag.Outcome {
	switch s {
	case domain.JobPending:
		return dag.Waiting
	case domain.JobQueued, domain.JobRunning:
		return dag.Active
	case domain.JobSucceeded:
		return dag.Succeeded
	default:
		return dag.Blocked
	}
}

// Progress re-evaluates one run: pending jobs whose dependencies all
// succeeded are queued, pending jobs with a failed, canceled, or skipped
// dependency are skipped, a queued run with started jobs becomes running,
// and a run whose jobs are all finished gets its final status. It is
// idempotent and does nothing for runs that are awaiting approval or
// finished. It joins the caller's transaction if there is one.
func (p *Progressor) Progress(ctx context.Context, orgID, runID string) (domain.Run, error) {
	ctx, span := tracer.Start(ctx, "scheduler.Progress")
	defer span.End()
	var run domain.Run
	err := p.store.InTx(ctx, func(ctx context.Context) error {
		var err error
		run, err = p.store.LockRun(ctx, orgID, runID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if run.Status.IsTerminal() || run.Status == domain.RunAwaitingApproval {
			return nil
		}
		jobs, err := p.store.ListJobs(ctx, orgID, runID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		now := p.now().UTC()
		nodes := make([]dag.Node, len(jobs))
		outcomes := make(map[string]dag.Outcome, len(jobs))
		byName := make(map[string]*domain.Job, len(jobs))
		for i := range jobs {
			j := &jobs[i]
			nodes[i] = dag.Node{ID: j.Name, Needs: j.Needs}
			outcomes[j.Name] = outcomeOf(j.Status)
			byName[j.Name] = j
		}
		ready, skip := dag.Advance(nodes, outcomes)
		for _, name := range skip {
			if err := p.setJob(ctx, byName[name], domain.JobSkipped, now, SkipReason); err != nil {
				return err
			}
		}
		for _, name := range ready {
			if err := p.setJob(ctx, byName[name], domain.JobQueued, now, ""); err != nil {
				return err
			}
		}

		statuses := make([]domain.JobStatus, len(jobs))
		started := false
		for i, j := range jobs {
			statuses[i] = j.Status
			if j.Status != domain.JobPending && j.Status != domain.JobQueued && j.Status != domain.JobSkipped && j.Status != domain.JobCanceled {
				started = true
			}
		}
		if final, done := engine.RunOutcome(statuses); done {
			return p.setRun(ctx, &run, final, now)
		}
		if started && run.Status == domain.RunQueued {
			return p.setRun(ctx, &run, domain.RunRunning, now)
		}
		return nil
	})
	if err != nil {
		return domain.Run{}, fmt.Errorf("progress run: %w", err)
	}
	return run, nil
}

func (p *Progressor) setJob(ctx context.Context, j *domain.Job, to domain.JobStatus, now time.Time, reason string) error {
	if err := engine.JobTransition(j.Status, to); err != nil {
		return err //nolint:wrapcheck // domain error
	}
	if err := p.store.UpdateJobStatus(ctx, store.JobStatusChange{
		OrgID: j.OrgID, JobID: j.ID, From: j.Status, To: to, At: now, FailureReason: reason,
	}); err != nil {
		return err //nolint:wrapcheck // store errors are contextual
	}
	j.Status = to
	return nil
}

func (p *Progressor) setRun(ctx context.Context, r *domain.Run, to domain.RunStatus, now time.Time) error {
	if err := engine.RunTransition(r.Status, to); err != nil {
		return err //nolint:wrapcheck // domain error
	}
	c := store.RunStatusChange{OrgID: r.OrgID, RunID: r.ID, From: r.Status, To: to}
	if to == domain.RunRunning {
		c.StartedAt = &now
	}
	if to.IsTerminal() {
		c.FinishedAt = &now
	}
	if err := p.store.UpdateRunStatus(ctx, c); err != nil {
		return err //nolint:wrapcheck // store errors are contextual
	}
	r.Status = to
	if c.StartedAt != nil && r.StartedAt == nil {
		r.StartedAt = c.StartedAt
	}
	if c.FinishedAt != nil && r.FinishedAt == nil {
		r.FinishedAt = c.FinishedAt
	}
	if p.observer != nil {
		return p.observer.RunChanged(ctx, *r)
	}
	return nil
}
