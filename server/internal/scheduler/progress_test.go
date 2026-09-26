// SPDX-License-Identifier: Apache-2.0

package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/store"
)

// fakeStore is an in-memory ProgressStore with the same compare-and-swap
// semantics as the SQL store.
type fakeStore struct {
	mu   sync.Mutex
	runs map[string]*domain.Run
	jobs map[string][]*domain.Job // by run ID
}

func newFake() *fakeStore {
	return &fakeStore{runs: map[string]*domain.Run{}, jobs: map[string][]*domain.Job{}}
}

func (f *fakeStore) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func (f *fakeStore) LockRun(_ context.Context, orgID, runID string) (domain.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runs[runID]
	if !ok || r.OrgID != orgID {
		return domain.Run{}, domain.ErrNotFound
	}
	return *r, nil
}

func (f *fakeStore) ListJobs(_ context.Context, orgID, runID string) ([]domain.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.Job
	for _, j := range f.jobs[runID] {
		if j.OrgID == orgID {
			out = append(out, *j)
		}
	}
	return out, nil
}

func (f *fakeStore) job(id string) *domain.Job {
	for _, js := range f.jobs {
		for _, j := range js {
			if j.ID == id {
				return j
			}
		}
	}
	return nil
}

func (f *fakeStore) UpdateJobStatus(_ context.Context, c store.JobStatusChange) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	j := f.job(c.JobID)
	if j == nil || j.OrgID != c.OrgID || j.Status != c.From || j.Status == domain.JobRunning {
		return fmt.Errorf("fake: %w", domain.ErrConflict)
	}
	j.Status = c.To
	if c.FailureReason != "" {
		j.FailureReason = c.FailureReason
	}
	return nil
}

func (f *fakeStore) UpdateRunStatus(_ context.Context, c store.RunStatusChange) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.runs[c.RunID]
	if r == nil || r.OrgID != c.OrgID || r.Status != c.From {
		return fmt.Errorf("fake: %w", domain.ErrConflict)
	}
	r.Status = c.To
	if r.StartedAt == nil {
		r.StartedAt = c.StartedAt
	}
	if r.FinishedAt == nil {
		r.FinishedAt = c.FinishedAt
	}
	return nil
}

func (f *fakeStore) add(status domain.RunStatus, jobs ...domain.Job) *domain.Run {
	r := &domain.Run{ID: fmt.Sprintf("run%d", len(f.runs)), OrgID: "org", Status: status}
	f.runs[r.ID] = r
	for i := range jobs {
		j := jobs[i]
		j.ID, j.OrgID, j.RunID = r.ID+"-"+j.Name, "org", r.ID
		if j.Status == "" {
			j.Status = domain.JobPending
		}
		f.jobs[r.ID] = append(f.jobs[r.ID], &j)
	}
	return r
}

func (f *fakeStore) statusOf(runID, name string) domain.JobStatus {
	for _, j := range f.jobs[runID] {
		if j.Name == name {
			return j.Status
		}
	}
	return ""
}

var fixed = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func clock() time.Time { return fixed }

func TestProgress_QueuesRootsThenDependents(t *testing.T) {
	f := newFake()
	r := f.add(domain.RunQueued,
		domain.Job{Name: "lint"}, domain.Job{Name: "build"},
		domain.Job{Name: "test", Needs: []string{"build"}},
		domain.Job{Name: "deploy", Needs: []string{"test", "lint"}})
	p := NewProgressor(f, clock)
	ctx := context.Background()

	run, err := p.Progress(ctx, "org", r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != domain.RunQueued || f.statusOf(r.ID, "lint") != domain.JobQueued ||
		f.statusOf(r.ID, "build") != domain.JobQueued || f.statusOf(r.ID, "test") != domain.JobPending {
		t.Fatalf("after first progress: run=%s jobs=%v", run.Status, f.jobs[r.ID])
	}
	// Idempotent.
	if _, err := p.Progress(ctx, "org", r.ID); err != nil {
		t.Fatal(err)
	}

	f.job(r.ID + "-build").Status = domain.JobSucceeded
	run, _ = p.Progress(ctx, "org", r.ID)
	if run.Status != domain.RunRunning || run.StartedAt == nil || f.statusOf(r.ID, "test") != domain.JobQueued {
		t.Fatalf("after build: run=%s test=%s", run.Status, f.statusOf(r.ID, "test"))
	}

	f.job(r.ID + "-lint").Status = domain.JobSucceeded
	f.job(r.ID + "-test").Status = domain.JobSucceeded
	_, _ = p.Progress(ctx, "org", r.ID)
	f.job(r.ID + "-deploy").Status = domain.JobSucceeded
	run, _ = p.Progress(ctx, "org", r.ID)
	if run.Status != domain.RunSucceeded || run.FinishedAt == nil {
		t.Fatalf("final run = %+v", run)
	}
}

func TestProgress_FailureSkipsDependentsAndFailsRun(t *testing.T) {
	f := newFake()
	r := f.add(domain.RunRunning,
		domain.Job{Name: "build", Status: domain.JobFailed},
		domain.Job{Name: "test", Needs: []string{"build"}},
		domain.Job{Name: "deploy", Needs: []string{"test"}},
		domain.Job{Name: "docs", Status: domain.JobSucceeded})
	run, err := NewProgressor(f, clock).Progress(context.Background(), "org", r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if f.statusOf(r.ID, "test") != domain.JobSkipped || f.statusOf(r.ID, "deploy") != domain.JobSkipped {
		t.Fatalf("dependents not skipped: %v", f.jobs[r.ID])
	}
	if f.job(r.ID+"-test").FailureReason != SkipReason {
		t.Fatal("skip reason not recorded")
	}
	if run.Status != domain.RunFailed {
		t.Fatalf("run = %s, want failed", run.Status)
	}
}

func TestProgress_LeavesAwaitingApprovalAndFinishedRunsAlone(t *testing.T) {
	for _, st := range []domain.RunStatus{domain.RunAwaitingApproval, domain.RunSucceeded, domain.RunCanceled} {
		f := newFake()
		r := f.add(st, domain.Job{Name: "a"})
		run, err := NewProgressor(f, nil).Progress(context.Background(), "org", r.ID)
		if err != nil || run.Status != st || f.statusOf(r.ID, "a") != domain.JobPending {
			t.Fatalf("%s: run=%s job=%s err=%v", st, run.Status, f.statusOf(r.ID, "a"), err)
		}
	}
}

func TestProgress_CrossOrgIsNotFound(t *testing.T) {
	f := newFake()
	r := f.add(domain.RunQueued, domain.Job{Name: "a"})
	_, err := NewProgressor(f, clock).Progress(context.Background(), "other-org", r.ID)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want not found", err)
	}
	if f.statusOf(r.ID, "a") != domain.JobPending {
		t.Fatal("foreign org progressed the run")
	}
}

func TestProgress_AllCanceledCancelsQueuedRun(t *testing.T) {
	f := newFake()
	r := f.add(domain.RunQueued, domain.Job{Name: "a", Status: domain.JobCanceled}, domain.Job{Name: "b", Status: domain.JobCanceled})
	run, err := NewProgressor(f, clock).Progress(context.Background(), "org", r.ID)
	if err != nil || run.Status != domain.RunCanceled {
		t.Fatalf("run = %s err=%v", run.Status, err)
	}
}

func TestProgress_ConcurrentChangeIsAConflict(t *testing.T) {
	f := newFake()
	r := f.add(domain.RunQueued, domain.Job{Name: "a"})
	// A job already moved by someone else must not be overwritten.
	cs := &conflictStore{fakeStore: f}
	_, err := NewProgressor(cs, clock).Progress(context.Background(), "org", r.ID)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("err = %v, want conflict", err)
	}
}

type conflictStore struct{ *fakeStore }

func (c *conflictStore) UpdateJobStatus(context.Context, store.JobStatusChange) error {
	return domain.ErrConflict
}
