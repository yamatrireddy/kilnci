// SPDX-License-Identifier: Apache-2.0

package scheduler

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/engine"
	"github.com/yamatrireddy/kilnci/server/internal/store"
)

// Store is the persistence the scheduler needs.
type Store interface {
	ProgressStore
	ListLeaseCandidates(ctx context.Context, orgID string, labels []string, trusted bool, limit int32) ([]store.LeaseCandidate, error)
	AcquireLease(ctx context.Context, g store.LeaseGrant) error
	GetLeasedJob(ctx context.Context, ref store.LeaseRef, now time.Time) (domain.Job, error)
	RenewLease(ctx context.Context, ref store.LeaseRef, now, expiresAt time.Time) (store.LeaseState, error)
	CompleteLeasedJob(ctx context.Context, ref store.LeaseRef, res store.LeaseResult) error
	ListExpiredLeases(ctx context.Context, now time.Time, grace time.Duration, limit int32) ([]store.ExpiredLease, error)
	RequeueExpiredJob(ctx context.Context, orgID, jobID string, now time.Time) (bool, error)
	FailExpiredJob(ctx context.Context, orgID, jobID string, to domain.JobStatus, reason string, now time.Time, grace time.Duration) (bool, error)
}

// Runner is the identity a lease is granted to, as loaded from the
// database by the runner authentication layer (never from the client).
type Runner struct {
	ID      string
	OrgID   string
	Labels  []string
	Trusted bool
}

// Lease is a job handed to a runner.
type Lease struct {
	ID        []byte
	ExpiresAt time.Time
	Job       domain.Job
	Run       domain.Run
}

// Options configures the scheduler.
type Options struct {
	// LeaseTTL is how long a lease lives without a heartbeat. Default 60s.
	LeaseTTL time.Duration
	// TimeoutGrace is how long past a job's timeout the server waits for the
	// runner to report before failing the job itself. Default 2m.
	TimeoutGrace time.Duration
	// ReapInterval is how often RunReaper looks for expired leases. Default 15s.
	ReapInterval time.Duration
}

// Scheduler grants, renews, and completes job leases and reaps expired ones.
type Scheduler struct {
	store    Store
	progress *Progressor
	opts     Options
	now      func() time.Time
	log      *slog.Logger
}

// New returns a Scheduler. now may be nil (time.Now).
func New(s Store, log *slog.Logger, opts Options, now func() time.Time) *Scheduler {
	if now == nil {
		now = time.Now
	}
	if opts.LeaseTTL <= 0 {
		opts.LeaseTTL = time.Minute
	}
	if opts.TimeoutGrace <= 0 {
		opts.TimeoutGrace = 2 * time.Minute
	}
	if opts.ReapInterval <= 0 {
		opts.ReapInterval = 15 * time.Second
	}
	return &Scheduler{store: s, progress: NewProgressor(s, now), opts: opts, now: now, log: log}
}

// Progressor returns the run progressor that shares this scheduler's store.
func (s *Scheduler) Progressor() *Progressor { return s.progress }

// leaseCandidates bounds how many queued jobs one Lease call tries.
const leaseCandidates = 10

// Lease hands the oldest eligible queued job of the runner's org to the
// runner: its required labels must be a subset of the runner's, and trusted
// runners never receive untrusted jobs. It returns (nil, nil) when nothing
// is available.
func (s *Scheduler) Lease(ctx context.Context, r Runner) (*Lease, error) {
	ctx, span := tracer.Start(ctx, "scheduler.Lease")
	defer span.End()
	if r.ID == "" || r.OrgID == "" {
		return nil, domain.ErrUnauthenticated
	}
	cands, err := s.store.ListLeaseCandidates(ctx, r.OrgID, r.Labels, r.Trusted, leaseCandidates)
	if err != nil {
		return nil, fmt.Errorf("lease: %w", err)
	}
	for _, c := range cands {
		lease, err := s.tryLease(ctx, r, c)
		if errors.Is(err, domain.ErrConflict) {
			continue // another runner won this job, or its run moved on
		}
		if err != nil {
			return nil, fmt.Errorf("lease: %w", err)
		}
		return lease, nil
	}
	return nil, nil
}

func (s *Scheduler) tryLease(ctx context.Context, r Runner, c store.LeaseCandidate) (*Lease, error) {
	leaseID := make([]byte, 16)
	if _, err := rand.Read(leaseID); err != nil {
		return nil, fmt.Errorf("generate lease id: %w", err)
	}
	now := s.now().UTC()
	lease := &Lease{ID: leaseID, ExpiresAt: now.Add(s.opts.LeaseTTL)}
	err := s.store.InTx(ctx, func(ctx context.Context) error {
		run, err := s.store.LockRun(ctx, r.OrgID, c.RunID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if run.Status != domain.RunQueued && run.Status != domain.RunRunning {
			return domain.ErrConflict
		}
		if err := engine.JobTransition(domain.JobQueued, domain.JobRunning); err != nil {
			return err //nolint:wrapcheck // domain error
		}
		if err := s.store.AcquireLease(ctx, store.LeaseGrant{
			OrgID: r.OrgID, JobID: c.JobID, RunnerID: r.ID, RunnerLabels: r.Labels, RunnerTrusted: r.Trusted,
			LeaseID: leaseID, Now: now, ExpiresAt: lease.ExpiresAt,
		}); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if lease.Run, err = s.progress.Progress(ctx, r.OrgID, c.RunID); err != nil {
			return err //nolint:wrapcheck // contextual
		}
		lease.Job, err = s.store.GetLeasedJob(ctx, s.ref(r, c.JobID, leaseID), now)
		return err //nolint:wrapcheck // store errors are contextual
	})
	if err != nil {
		return nil, err //nolint:wrapcheck // contextual
	}
	return lease, nil
}

func (s *Scheduler) ref(r Runner, jobID string, leaseID []byte) store.LeaseRef {
	return store.LeaseRef{OrgID: r.OrgID, JobID: jobID, RunnerID: r.ID, LeaseID: leaseID}
}

// HeartbeatResult tells the runner whether to keep going.
type HeartbeatResult struct {
	ExpiresAt time.Time
	// Cancel asks the runner to stop the job and report it; Reason says why.
	Cancel bool
	Reason string
}

// ErrLeaseLost means the lease is not held by this runner any more (it
// expired, was reaped, or never existed). The runner must stop the job.
var ErrLeaseLost = fmt.Errorf("lease lost: %w", domain.ErrNotFound)

// Heartbeat renews a lease and reports whether the job was canceled or has
// run past its timeout.
func (s *Scheduler) Heartbeat(ctx context.Context, r Runner, jobID string, leaseID []byte) (HeartbeatResult, error) {
	ctx, span := tracer.Start(ctx, "scheduler.Heartbeat")
	defer span.End()
	now := s.now().UTC()
	exp := now.Add(s.opts.LeaseTTL)
	st, err := s.store.RenewLease(ctx, s.ref(r, jobID, leaseID), now, exp)
	if errors.Is(err, domain.ErrNotFound) {
		return HeartbeatResult{}, ErrLeaseLost
	}
	if err != nil {
		return HeartbeatResult{}, fmt.Errorf("heartbeat: %w", err)
	}
	res := HeartbeatResult{ExpiresAt: exp}
	switch {
	case st.CancelRequested:
		res.Cancel, res.Reason = true, "canceled"
	case !st.StartedAt.IsZero() && now.After(st.StartedAt.Add(st.Timeout)):
		res.Cancel, res.Reason = true, "timed out"
	}
	return res, nil
}

// Result is a runner's report of how a job ended.
type Result struct {
	Status   domain.JobStatus // succeeded, failed, or canceled
	ExitCode *int
	// Reason is runner-supplied text; it is sanitized and truncated.
	Reason string
}

const maxReasonBytes = 1024

// Complete records a job's result under its lease and advances the run.
// It returns ErrLeaseLost if the lease is no longer held by this runner, so
// a runner can never report on a job it does not hold (threat T-14).
func (s *Scheduler) Complete(ctx context.Context, r Runner, jobID string, leaseID []byte, res Result) error {
	ctx, span := tracer.Start(ctx, "scheduler.Complete")
	defer span.End()
	switch res.Status {
	case domain.JobSucceeded, domain.JobFailed, domain.JobCanceled:
	default:
		return domain.NewValidationError("status", "must be succeeded, failed, or canceled")
	}
	if res.Status == domain.JobSucceeded && (res.ExitCode == nil || *res.ExitCode != 0) {
		return domain.NewValidationError("exitCode", "a succeeded job must report exit code 0")
	}
	ref := s.ref(r, jobID, leaseID)
	now := s.now().UTC()
	job, err := s.store.GetLeasedJob(ctx, ref, now)
	if errors.Is(err, domain.ErrNotFound) {
		return ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("complete: %w", err)
	}
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.store.LockRun(ctx, r.OrgID, job.RunID); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if err := engine.JobTransition(domain.JobRunning, res.Status); err != nil {
			return err //nolint:wrapcheck // domain error
		}
		if err := s.store.CompleteLeasedJob(ctx, ref, store.LeaseResult{
			To: res.Status, ExitCode: res.ExitCode, FailureReason: sanitizeReason(res.Reason), Now: now,
		}); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		_, err := s.progress.Progress(ctx, r.OrgID, job.RunID)
		return err //nolint:wrapcheck // contextual
	})
	if errors.Is(err, domain.ErrNotFound) {
		return ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("complete: %w", err)
	}
	return nil
}

func sanitizeReason(s string) string {
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
	if len(s) > maxReasonBytes {
		cut := maxReasonBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return strings.TrimSpace(s)
}

// reapBatch bounds one Reap pass.
const reapBatch = 100

// Reap handles running jobs whose lease expired or whose timeout (plus
// grace) passed: a job with attempts and time left is re-queued; otherwise
// it fails (or is canceled, if cancellation was requested). It returns how
// many jobs it changed.
func (s *Scheduler) Reap(ctx context.Context) (int, error) {
	ctx, span := tracer.Start(ctx, "scheduler.Reap")
	defer span.End()
	now := s.now().UTC()
	expired, err := s.store.ListExpiredLeases(ctx, now, s.opts.TimeoutGrace, reapBatch)
	if err != nil {
		return 0, fmt.Errorf("reap: %w", err)
	}
	changed := 0
	for _, e := range expired {
		ok, err := s.reapOne(ctx, e, now)
		if err != nil {
			return changed, fmt.Errorf("reap job %s: %w", e.JobID, err)
		}
		if ok {
			changed++
		}
	}
	return changed, nil
}

func (s *Scheduler) reapOne(ctx context.Context, e store.ExpiredLease, now time.Time) (bool, error) {
	changed := false
	err := s.store.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.store.LockRun(ctx, e.OrgID, e.RunID); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		jobs, err := s.store.ListJobs(ctx, e.OrgID, e.RunID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		var job *domain.Job
		for i := range jobs {
			if jobs[i].ID == e.JobID {
				job = &jobs[i]
			}
		}
		if job == nil || job.Status != domain.JobRunning {
			return nil // finished meanwhile
		}
		if engine.JobTransition(domain.JobRunning, domain.JobQueued) == nil {
			requeued, err := s.store.RequeueExpiredJob(ctx, e.OrgID, e.JobID, now)
			if err != nil {
				return err //nolint:wrapcheck // store errors are contextual
			}
			if requeued {
				changed = true
				return nil
			}
		}
		to, reason := domain.JobFailed, "the runner stopped responding"
		switch {
		case job.CancelRequested:
			to, reason = domain.JobCanceled, "canceled"
		case job.StartedAt != nil && !now.Before(job.StartedAt.Add(job.Timeout)):
			reason = fmt.Sprintf("timed out after %s", job.Timeout)
		}
		if err := engine.JobTransition(domain.JobRunning, to); err != nil {
			return err //nolint:wrapcheck // domain error
		}
		ok, err := s.store.FailExpiredJob(ctx, e.OrgID, e.JobID, to, reason, now, s.opts.TimeoutGrace)
		if err != nil || !ok {
			return err //nolint:wrapcheck // store errors are contextual
		}
		changed = true
		_, err = s.progress.Progress(ctx, e.OrgID, e.RunID)
		return err //nolint:wrapcheck // contextual
	})
	return changed, err //nolint:wrapcheck // contextual
}

// RunReaper calls Reap every ReapInterval until ctx is done.
func (s *Scheduler) RunReaper(ctx context.Context) {
	t := time.NewTicker(s.opts.ReapInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.Reap(ctx); err != nil && ctx.Err() == nil {
				s.log.ErrorContext(ctx, "reap expired leases", "error", err)
			} else if n > 0 {
				s.log.InfoContext(ctx, "reaped expired leases", "jobs", n)
			}
		}
	}
}
