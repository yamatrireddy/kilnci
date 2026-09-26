// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/store/db"
)

// LeaseCandidate is a queued job a runner may try to lease.
type LeaseCandidate struct {
	JobID, RunID string
}

// ListLeaseCandidates returns queued jobs in orgID that a runner with labels
// and trust level may run, oldest first. It takes no locks.
func (s *Store) ListLeaseCandidates(ctx context.Context, orgID string, labels []string, trusted bool, limit int32) ([]LeaseCandidate, error) {
	rows, err := s.q(ctx).ListLeaseCandidates(ctx, db.ListLeaseCandidatesParams{
		OrgID: orgID, RunnerLabels: nonNil(labels), RunnerTrusted: trusted, MaxRows: limit,
	})
	if err != nil {
		return nil, mapErr("list lease candidates", err)
	}
	out := make([]LeaseCandidate, len(rows))
	for i, r := range rows {
		out[i] = LeaseCandidate{JobID: r.ID, RunID: r.RunID}
	}
	return out, nil
}

// LeaseGrant describes a lease to acquire.
type LeaseGrant struct {
	OrgID, JobID, RunnerID string
	RunnerLabels           []string
	RunnerTrusted          bool
	LeaseID                []byte
	Now, ExpiresAt         time.Time
}

// AcquireLease moves a queued job to running under the lease in g. It
// returns domain.ErrConflict if the job is no longer queued or no longer
// matches the runner (someone else leased it first).
func (s *Store) AcquireLease(ctx context.Context, g LeaseGrant) error {
	n, err := s.q(ctx).AcquireLease(ctx, db.AcquireLeaseParams{
		RunnerID: &g.RunnerID, LeaseID: g.LeaseID, LeaseExpiresAt: &g.ExpiresAt, Now: &g.Now,
		OrgID: g.OrgID, ID: g.JobID, RunnerLabels: nonNil(g.RunnerLabels), RunnerTrusted: g.RunnerTrusted,
	})
	if err == nil && n == 0 {
		return fmt.Errorf("acquire lease: %w", domain.ErrConflict)
	}
	return mapErr("acquire lease", err)
}

// LeaseRef identifies a lease held by a runner.
type LeaseRef struct {
	OrgID, JobID, RunnerID string
	LeaseID                []byte
}

// GetLeasedJob returns the job held under ref, or domain.ErrNotFound if the
// lease does not exist, belongs to another runner, or has expired.
func (s *Store) GetLeasedJob(ctx context.Context, ref LeaseRef, now time.Time) (domain.Job, error) {
	r, err := s.q(ctx).GetLeasedJob(ctx, db.GetLeasedJobParams{
		OrgID: ref.OrgID, ID: ref.JobID, RunnerID: &ref.RunnerID, LeaseID: ref.LeaseID, Now: &now,
	})
	if err != nil {
		return domain.Job{}, mapErr("get leased job", err)
	}
	return toJob(db.ListJobsRow{
		ID: r.ID, OrgID: r.OrgID, RunID: r.RunID, Name: r.Name, Status: r.Status, Needs: r.Needs, Image: r.Image,
		Labels: r.Labels, Steps: r.Steps, Env: r.Env, TimeoutSeconds: r.TimeoutSeconds, Attempt: r.Attempt,
		MaxAttempts: r.MaxAttempts, Trusted: r.Trusted, RunnerID: r.RunnerID, CancelRequested: r.CancelRequested,
		ExitCode: r.ExitCode, FailureReason: r.FailureReason, CreatedAt: r.CreatedAt, QueuedAt: r.QueuedAt,
		StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
	})
}

// LeaseState is what a heartbeat learns about its job.
type LeaseState struct {
	CancelRequested bool
	StartedAt       time.Time
	Timeout         time.Duration
}

// RenewLease extends ref's lease to expiresAt. domain.ErrNotFound if the
// lease is not held (any more) by that runner.
func (s *Store) RenewLease(ctx context.Context, ref LeaseRef, now, expiresAt time.Time) (LeaseState, error) {
	r, err := s.q(ctx).RenewLease(ctx, db.RenewLeaseParams{
		LeaseExpiresAt: &expiresAt, OrgID: ref.OrgID, ID: ref.JobID, RunnerID: &ref.RunnerID, LeaseID: ref.LeaseID, Now: &now,
	})
	if err != nil {
		return LeaseState{}, mapErr("renew lease", err)
	}
	st := LeaseState{CancelRequested: r.CancelRequested, Timeout: time.Duration(r.TimeoutSeconds) * time.Second}
	if r.StartedAt != nil {
		st.StartedAt = *r.StartedAt
	}
	return st, nil
}

// LeaseResult finishes a leased job.
type LeaseResult struct {
	To            domain.JobStatus
	ExitCode      *int
	FailureReason string
	Now           time.Time
}

// CompleteLeasedJob records a leased job's result and releases the lease.
// domain.ErrNotFound if the lease is not held (any more) by that runner.
func (s *Store) CompleteLeasedJob(ctx context.Context, ref LeaseRef, res LeaseResult) error {
	var code *int32
	if res.ExitCode != nil {
		c, err := int32Of("exitCode", int64(*res.ExitCode))
		if err != nil {
			return err
		}
		code = &c
	}
	n, err := s.q(ctx).CompleteLeasedJob(ctx, db.CompleteLeasedJobParams{
		ToStatus: string(res.To), ExitCode: code, FailureReason: res.FailureReason, Now: &res.Now,
		OrgID: ref.OrgID, ID: ref.JobID, RunnerID: &ref.RunnerID, LeaseID: ref.LeaseID,
	})
	if err == nil && n == 0 {
		return fmt.Errorf("complete leased job: %w", domain.ErrNotFound)
	}
	return mapErr("complete leased job", err)
}

// ExpiredLease is a running job whose lease lapsed or whose timeout passed.
type ExpiredLease struct {
	OrgID, JobID, RunID string
}

// ListExpiredLeases returns up to limit running jobs across all orgs whose
// lease expired or whose timeout plus grace passed.
func (s *Store) ListExpiredLeases(ctx context.Context, now time.Time, grace time.Duration, limit int32) ([]ExpiredLease, error) {
	g, err := int32Of("grace", int64(grace/time.Second))
	if err != nil {
		return nil, err
	}
	rows, err := s.q(ctx).ListExpiredLeases(ctx, db.ListExpiredLeasesParams{Now: &now, GraceSeconds: g, MaxRows: limit})
	if err != nil {
		return nil, mapErr("list expired leases", err)
	}
	out := make([]ExpiredLease, len(rows))
	for i, r := range rows {
		out[i] = ExpiredLease{OrgID: r.OrgID, JobID: r.ID, RunID: r.RunID}
	}
	return out, nil
}

// RequeueExpiredJob gives a job whose lease lapsed another attempt, if it
// has attempts and time left and was not being canceled. It reports whether
// the job was requeued.
func (s *Store) RequeueExpiredJob(ctx context.Context, orgID, jobID string, now time.Time) (bool, error) {
	n, err := s.q(ctx).RequeueExpiredJob(ctx, db.RequeueExpiredJobParams{OrgID: orgID, ID: jobID, Now: &now})
	return n > 0, mapErr("requeue expired job", err)
}

// FailExpiredJob ends a job whose lease lapsed or whose timeout passed. It
// reports whether the job still qualified (it may have finished or renewed).
func (s *Store) FailExpiredJob(ctx context.Context, orgID, jobID string, to domain.JobStatus, reason string, now time.Time, grace time.Duration) (bool, error) {
	g, err := int32Of("grace", int64(grace/time.Second))
	if err != nil {
		return false, err
	}
	n, err := s.q(ctx).FailExpiredJob(ctx, db.FailExpiredJobParams{
		ToStatus: string(to), FailureReason: reason, Now: &now, OrgID: orgID, ID: jobID, GraceSeconds: g,
	})
	return n > 0, mapErr("fail expired job", err)
}
