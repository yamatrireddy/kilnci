// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/store/db"
)

func toRun(r db.Run) domain.Run {
	return domain.Run{
		ID: r.ID, OrgID: r.OrgID, ProjectID: r.ProjectID, Number: r.Number, Status: domain.RunStatus(r.Status),
		Event: domain.TriggerEvent(r.Event), Ref: r.Ref, Branch: r.Branch, CommitSHA: r.CommitSha, Title: r.Title,
		PRNumber: int(r.PrNumber), IsFork: r.IsFork, Trusted: r.Trusted, ActorLogin: r.ActorLogin,
		CreatedBy: deref(r.CreatedBy), IdempotencyKey: deref(r.IdempotencyKey), Error: r.Error,
		CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
	}
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// NextRunNumber allocates the next run number for a project. It locks the
// project's counter row until the transaction ends, so call it inside InTx.
func (s *Store) NextRunNumber(ctx context.Context, orgID, projectID string) (int64, error) {
	n, err := s.q(ctx).NextRunNumber(ctx, db.NextRunNumberParams{ProjectID: projectID, OrgID: orgID})
	return n, mapErr("next run number", err)
}

// CreateRun inserts a run. domain.ErrConflict on a duplicate idempotency key.
func (s *Store) CreateRun(ctx context.Context, r domain.Run) (domain.Run, error) {
	pr, err := int32Of("prNumber", int64(r.PRNumber))
	if err != nil {
		return domain.Run{}, err
	}
	row, err := s.q(ctx).CreateRun(ctx, db.CreateRunParams{
		ID: r.ID, OrgID: r.OrgID, ProjectID: r.ProjectID, Number: r.Number, Status: string(r.Status),
		Event: string(r.Event), Ref: r.Ref, Branch: r.Branch, CommitSha: r.CommitSHA, Title: r.Title,
		PrNumber: pr, IsFork: r.IsFork, Trusted: r.Trusted, ActorLogin: r.ActorLogin,
		CreatedBy: nilIfEmpty(r.CreatedBy), IdempotencyKey: nilIfEmpty(r.IdempotencyKey), Error: r.Error,
		CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
	})
	return toRun(row), mapErr("create run", err)
}

// GetRun returns a run of a project in an org.
func (s *Store) GetRun(ctx context.Context, orgID, projectID, runID string) (domain.Run, error) {
	row, err := s.q(ctx).GetRun(ctx, db.GetRunParams{OrgID: orgID, ProjectID: projectID, ID: runID})
	return toRun(row), mapErr("get run", err)
}

// LockRun returns a run and locks it until the transaction ends.
func (s *Store) LockRun(ctx context.Context, orgID, runID string) (domain.Run, error) {
	row, err := s.q(ctx).LockRun(ctx, db.LockRunParams{OrgID: orgID, ID: runID})
	return toRun(row), mapErr("lock run", err)
}

// GetRunByIdempotencyKey finds the run created with key, if any.
func (s *Store) GetRunByIdempotencyKey(ctx context.Context, orgID, projectID, key string) (domain.Run, error) {
	row, err := s.q(ctx).GetRunByIdempotencyKey(ctx, db.GetRunByIdempotencyKeyParams{OrgID: orgID, ProjectID: projectID, IdempotencyKey: &key})
	return toRun(row), mapErr("get run by idempotency key", err)
}

// ListRuns lists a project's runs, newest first, before beforeID.
func (s *Store) ListRuns(ctx context.Context, orgID, projectID, beforeID string, limit int32) ([]domain.Run, error) {
	rows, err := s.q(ctx).ListRuns(ctx, db.ListRunsParams{OrgID: orgID, ProjectID: projectID, BeforeID: beforeID, MaxRows: limit})
	if err != nil {
		return nil, mapErr("list runs", err)
	}
	out := make([]domain.Run, len(rows))
	for i, r := range rows {
		out[i] = toRun(r)
	}
	return out, nil
}

// RunStatusChange is a compare-and-swap of a run's status. Callers validate
// the transition with engine.RunTransition first.
type RunStatusChange struct {
	OrgID, RunID string
	From, To     domain.RunStatus
	StartedAt    *time.Time
	FinishedAt   *time.Time
}

// UpdateRunStatus applies c, or returns domain.ErrConflict if the run is no
// longer in c.From.
func (s *Store) UpdateRunStatus(ctx context.Context, c RunStatusChange) error {
	n, err := s.q(ctx).UpdateRunStatus(ctx, db.UpdateRunStatusParams{
		ToStatus: string(c.To), StartedAt: c.StartedAt, FinishedAt: c.FinishedAt,
		OrgID: c.OrgID, ID: c.RunID, FromStatus: string(c.From),
	})
	if err == nil && n == 0 {
		return fmt.Errorf("update run status: %w", domain.ErrConflict)
	}
	return mapErr("update run status", err)
}

// CreateJob inserts a job.
func (s *Store) CreateJob(ctx context.Context, j domain.Job) error {
	steps, err := json.Marshal(j.Steps)
	if err != nil {
		return fmt.Errorf("marshal steps: %w", err)
	}
	env := j.Env
	if env == nil {
		env = []domain.EnvVar{}
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal env: %w", err)
	}
	timeout, err := int32Of("timeout", int64(j.Timeout/time.Second))
	if err != nil {
		return err
	}
	attempt, err := int32Of("attempt", int64(j.Attempt))
	if err != nil {
		return err
	}
	maxAttempts, err := int32Of("maxAttempts", int64(j.MaxAttempts))
	if err != nil {
		return err
	}
	return mapErr("create job", s.q(ctx).CreateJob(ctx, db.CreateJobParams{
		ID: j.ID, OrgID: j.OrgID, RunID: j.RunID, Name: j.Name, Status: string(j.Status),
		Needs: nonNil(j.Needs), Image: j.Image, Labels: nonNil(j.Labels), Steps: steps, Env: envJSON,
		TimeoutSeconds: timeout, Attempt: attempt, MaxAttempts: maxAttempts, Trusted: j.Trusted, CreatedAt: j.CreatedAt,
	}))
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ListJobs returns a run's jobs in creation order.
func (s *Store) ListJobs(ctx context.Context, orgID, runID string) ([]domain.Job, error) {
	rows, err := s.q(ctx).ListJobs(ctx, db.ListJobsParams{OrgID: orgID, RunID: runID})
	if err != nil {
		return nil, mapErr("list jobs", err)
	}
	out := make([]domain.Job, len(rows))
	for i, r := range rows {
		j, err := toJob(r)
		if err != nil {
			return nil, err
		}
		out[i] = j
	}
	return out, nil
}

func toJob(r db.ListJobsRow) (domain.Job, error) {
	j := domain.Job{
		ID: r.ID, OrgID: r.OrgID, RunID: r.RunID, Name: r.Name, Status: domain.JobStatus(r.Status),
		Needs: r.Needs, Image: r.Image, Labels: r.Labels, Timeout: time.Duration(r.TimeoutSeconds) * time.Second,
		Attempt: int(r.Attempt), MaxAttempts: int(r.MaxAttempts), Trusted: r.Trusted, RunnerID: deref(r.RunnerID),
		CancelRequested: r.CancelRequested, FailureReason: r.FailureReason, CreatedAt: r.CreatedAt,
		QueuedAt: r.QueuedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
	}
	if r.ExitCode != nil {
		c := int(*r.ExitCode)
		j.ExitCode = &c
	}
	if err := json.Unmarshal(r.Steps, &j.Steps); err != nil {
		return domain.Job{}, fmt.Errorf("decode job steps: %w", err)
	}
	if err := json.Unmarshal(r.Env, &j.Env); err != nil {
		return domain.Job{}, fmt.Errorf("decode job env: %w", err)
	}
	return j, nil
}

// JobStatusChange is a compare-and-swap of a job's status for jobs that are
// not leased. Callers validate with engine.JobTransition first.
type JobStatusChange struct {
	OrgID, JobID  string
	From, To      domain.JobStatus
	At            time.Time
	FailureReason string
}

// UpdateJobStatus applies c, or returns domain.ErrConflict if the job is no
// longer in c.From (or is leased).
func (s *Store) UpdateJobStatus(ctx context.Context, c JobStatusChange) error {
	at := c.At
	n, err := s.q(ctx).UpdateJobStatus(ctx, db.UpdateJobStatusParams{
		ToStatus: string(c.To), At: &at, FailureReason: c.FailureReason,
		OrgID: c.OrgID, ID: c.JobID, FromStatus: string(c.From),
	})
	if err == nil && n == 0 {
		return fmt.Errorf("update job status: %w", domain.ErrConflict)
	}
	return mapErr("update job status", err)
}

// RequestJobCancel flags a running job so its runner stops it at the next
// heartbeat. Returns domain.ErrConflict if the job is not running.
func (s *Store) RequestJobCancel(ctx context.Context, orgID, jobID string) error {
	n, err := s.q(ctx).RequestJobCancel(ctx, db.RequestJobCancelParams{OrgID: orgID, ID: jobID})
	if err == nil && n == 0 {
		return fmt.Errorf("request job cancel: %w", domain.ErrConflict)
	}
	return mapErr("request job cancel", err)
}
