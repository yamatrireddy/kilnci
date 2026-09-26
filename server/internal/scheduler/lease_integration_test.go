// SPDX-License-Identifier: Apache-2.0

//go:build integration

package scheduler_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/engine/spec"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/scheduler"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/service/runs"
	"github.com/yamatrireddy/kilnci/server/internal/store"
	"github.com/yamatrireddy/kilnci/server/internal/store/storetest"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	t       *testing.T
	st      *store.Store
	sched   *scheduler.Scheduler
	runs    *runs.Service
	clk     *clock
	org     domain.Org
	project domain.Project
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := storetest.New(t)
	gen := ids.NewGenerator(nil)
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	sched := scheduler.New(st, logging.Discard(), scheduler.Options{LeaseTTL: time.Minute, TimeoutGrace: time.Minute}, clk.now)
	rec := audit.NewRecorder(st, gen, clk.now)
	svc := runs.NewService(st, authz.NewAuthorizer(st), rec, sched.Progressor(), gen, clk.now)
	org, err := st.CreateOrg(t.Context(), domain.Org{ID: gen.New(), Slug: storetest.Unique("o"), Name: "O", CreatedAt: clk.now()})
	if err != nil {
		t.Fatal(err)
	}
	proj, err := st.CreateProject(t.Context(), domain.Project{ID: gen.New(), OrgID: org.ID, Slug: "p", Name: "P", CreatedAt: clk.now()})
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, st: st, sched: sched, runs: svc, clk: clk, org: org, project: proj}
}

func (e *env) run(yaml string, fork bool) domain.Run {
	e.t.Helper()
	pl, err := spec.Parse([]byte(yaml))
	if err != nil {
		e.t.Fatal(err)
	}
	ev, ref := domain.EventPush, "refs/heads/main"
	if fork {
		ev, ref = domain.EventPullRequest, "refs/pull/3/head"
	}
	r, err := e.runs.CreateRun(e.t.Context(), runs.NewRun{
		OrgID: e.org.ID, ProjectID: e.project.ID, Event: ev, Ref: ref, CommitSHA: strings.Repeat("c", 40),
		IsFork: fork, Trusted: !fork, Pipeline: pl,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *env) jobs(runID string) map[string]domain.Job {
	e.t.Helper()
	js, err := e.st.ListJobs(e.t.Context(), e.org.ID, runID)
	if err != nil {
		e.t.Fatal(err)
	}
	out := map[string]domain.Job{}
	for _, j := range js {
		out[j.Name] = j
	}
	return out
}

func (e *env) runStatus(runID string) domain.RunStatus {
	e.t.Helper()
	r, err := e.st.GetRun(e.t.Context(), e.org.ID, e.project.ID, runID)
	if err != nil {
		e.t.Fatal(err)
	}
	return r.Status
}

func (e *env) runner(labels []string, trusted bool) scheduler.Runner {
	return scheduler.Runner{ID: ids.NewGenerator(nil).New(), OrgID: e.org.ID, Labels: labels, Trusted: trusted}
}

const twoJobs = `version: 1
jobs:
  build:
    image: alpine
    steps: [{run: make}]
  test:
    image: alpine
    needs: [build]
    retries: 1
    timeout: 5m
    steps: [{run: make test}]
`

func exit(code int) *int { return &code }

func TestLease_FullLifecycle(t *testing.T) {
	e := newEnv(t)
	r := e.run(twoJobs, false)
	rn := e.runner(nil, false)
	ctx := t.Context()

	l, err := e.sched.Lease(ctx, rn)
	if err != nil || l == nil {
		t.Fatalf("lease = %v, %v", l, err)
	}
	if l.Job.Name != "build" || l.Job.Status != domain.JobRunning || l.Job.Attempt != 1 || l.Run.Status != domain.RunRunning || len(l.ID) != 16 {
		t.Fatalf("lease = %+v", l)
	}
	// Nothing else is runnable until build finishes.
	if l2, err := e.sched.Lease(ctx, rn); err != nil || l2 != nil {
		t.Fatalf("second lease = %v, %v", l2, err)
	}
	hb, err := e.sched.Heartbeat(ctx, rn, l.Job.ID, l.ID)
	if err != nil || hb.Cancel {
		t.Fatalf("heartbeat = %+v %v", hb, err)
	}
	if err := e.sched.Complete(ctx, rn, l.Job.ID, l.ID, scheduler.Result{Status: domain.JobSucceeded, ExitCode: exit(0)}); err != nil {
		t.Fatal(err)
	}
	if e.jobs(r.ID)["test"].Status != domain.JobQueued {
		t.Fatal("dependent not queued after success")
	}
	l, err = e.sched.Lease(ctx, rn)
	if err != nil || l == nil || l.Job.Name != "test" {
		t.Fatalf("lease test = %+v %v", l, err)
	}
	if err := e.sched.Complete(ctx, rn, l.Job.ID, l.ID, scheduler.Result{Status: domain.JobFailed, ExitCode: exit(2), Reason: "step failed\x1b[31m"}); err != nil {
		t.Fatal(err)
	}
	j := e.jobs(r.ID)["test"]
	if j.Status != domain.JobFailed || *j.ExitCode != 2 || j.FailureReason != "step failed [31m" {
		t.Fatalf("test job = %+v", j)
	}
	if e.runStatus(r.ID) != domain.RunFailed {
		t.Fatalf("run = %s", e.runStatus(r.ID))
	}
	// The lease is gone: late reports and heartbeats are rejected.
	if err := e.sched.Complete(ctx, rn, l.Job.ID, l.ID, scheduler.Result{Status: domain.JobSucceeded, ExitCode: exit(0)}); !errors.Is(err, scheduler.ErrLeaseLost) {
		t.Fatalf("late complete err = %v", err)
	}
	if _, err := e.sched.Heartbeat(ctx, rn, l.Job.ID, l.ID); !errors.Is(err, scheduler.ErrLeaseLost) {
		t.Fatalf("late heartbeat err = %v", err)
	}
}

// TestLease_BoundToRunnerAndLeaseID: threat T-14 / scenario S3.
func TestLease_BoundToRunnerAndLeaseID(t *testing.T) {
	e := newEnv(t)
	e.run(twoJobs, false)
	owner, other := e.runner(nil, false), e.runner(nil, false)
	ctx := t.Context()
	l, err := e.sched.Lease(ctx, owner)
	if err != nil || l == nil {
		t.Fatal(err)
	}
	ok := scheduler.Result{Status: domain.JobSucceeded, ExitCode: exit(0)}
	if err := e.sched.Complete(ctx, other, l.Job.ID, l.ID, ok); !errors.Is(err, scheduler.ErrLeaseLost) {
		t.Fatalf("other runner complete err = %v", err)
	}
	wrong := append([]byte(nil), l.ID...)
	wrong[0] ^= 0xff
	if err := e.sched.Complete(ctx, owner, l.Job.ID, wrong, ok); !errors.Is(err, scheduler.ErrLeaseLost) {
		t.Fatalf("wrong lease id err = %v", err)
	}
	if _, err := e.sched.Heartbeat(ctx, other, l.Job.ID, l.ID); !errors.Is(err, scheduler.ErrLeaseLost) {
		t.Fatalf("other runner heartbeat err = %v", err)
	}
	foreign := scheduler.Runner{ID: other.ID, OrgID: ids.NewGenerator(nil).New()}
	if l2, err := e.sched.Lease(ctx, foreign); err != nil || l2 != nil {
		t.Fatalf("foreign-org runner leased %+v %v", l2, err)
	}
	if err := e.sched.Complete(ctx, owner, l.Job.ID, l.ID, scheduler.Result{Status: domain.JobSucceeded, ExitCode: exit(1)}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("success with nonzero exit err = %v", err)
	}
	if err := e.sched.Complete(ctx, owner, l.Job.ID, l.ID, scheduler.Result{Status: domain.JobQueued}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bogus status err = %v", err)
	}
}

func TestLease_LabelsAndTrust(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.run("version: 1\njobs:\n  gpu:\n    image: alpine\n    runs-on: [gpu, linux]\n    steps: [{run: x}]\n", false)
	if l, _ := e.sched.Lease(ctx, e.runner([]string{"linux"}, false)); l != nil {
		t.Fatal("runner without gpu label leased a gpu job")
	}
	if l, err := e.sched.Lease(ctx, e.runner([]string{"linux", "gpu", "big"}, false)); err != nil || l == nil {
		t.Fatalf("superset runner could not lease: %v", err)
	}

	fork := e.run(twoJobs, true)
	if _, err := e.runs.ApproveRun(authz.WithPrincipal(ctx, nil), "", "", fork.ID); err == nil {
		t.Fatal("approve without principal succeeded")
	}
	// Approve directly through the store path used by the service.
	approveFork(t, e, fork.ID)
	if l, _ := e.sched.Lease(ctx, e.runner(nil, true)); l != nil {
		t.Fatalf("trusted runner leased a fork job: %+v", l.Job)
	}
	l, err := e.sched.Lease(ctx, e.runner(nil, false))
	if err != nil || l == nil || l.Run.ID != fork.ID || l.Job.Trusted {
		t.Fatalf("untrusted runner lease = %+v %v", l, err)
	}

	// Trusted runs may go to trusted runners.
	e.run(twoJobs, false)
	if l, err := e.sched.Lease(ctx, e.runner(nil, true)); err != nil || l == nil || !l.Job.Trusted {
		t.Fatalf("trusted runner lease = %+v %v", l, err)
	}
}

func approveFork(t *testing.T, e *env, runID string) {
	t.Helper()
	err := e.st.UpdateRunStatus(t.Context(), store.RunStatusChange{OrgID: e.org.ID, RunID: runID, From: domain.RunAwaitingApproval, To: domain.RunQueued})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.sched.Progressor().Progress(t.Context(), e.org.ID, runID); err != nil {
		t.Fatal(err)
	}
}

func TestLease_AwaitingApprovalIsNotLeasable(t *testing.T) {
	e := newEnv(t)
	e.run(twoJobs, true)
	if l, err := e.sched.Lease(t.Context(), e.runner(nil, false)); err != nil || l != nil {
		t.Fatalf("leased an unapproved fork job: %+v %v", l, err)
	}
}

func TestLease_ConcurrentRunnersNeverShareAJob(t *testing.T) {
	e := newEnv(t)
	const n = 8
	for range n {
		e.run("version: 1\njobs:\n  a:\n    image: alpine\n    steps: [{run: x}]\n", false)
	}
	var mu sync.Mutex
	seen := map[string]bool{}
	var wg sync.WaitGroup
	for range 2 * n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := e.sched.Lease(t.Context(), e.runner(nil, false))
			if err != nil {
				t.Errorf("lease: %v", err)
				return
			}
			if l == nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[l.Job.ID] {
				t.Errorf("job %s leased twice", l.Job.ID)
			}
			seen[l.Job.ID] = true
		}()
	}
	wg.Wait()
	if len(seen) == 0 || len(seen) > n {
		t.Fatalf("leased %d jobs", len(seen))
	}
}

func TestReap_RequeuesThenFailsExpiredLeases(t *testing.T) {
	e := newEnv(t)
	r := e.run(twoJobs, false)
	ctx := t.Context()
	rn := e.runner(nil, false)
	l, _ := e.sched.Lease(ctx, rn)
	_ = e.sched.Complete(ctx, rn, l.Job.ID, l.ID, scheduler.Result{Status: domain.JobSucceeded, ExitCode: exit(0)})

	// test has retries: 1 → two attempts.
	l, _ = e.sched.Lease(ctx, rn)
	e.clk.advance(2 * time.Minute)
	if n, err := e.sched.Reap(ctx); err != nil || n < 1 { // the database is shared with other tests
		t.Fatalf("reap = %d %v", n, err)
	}
	if j := e.jobs(r.ID)["test"]; j.Status != domain.JobQueued || j.RunnerID != "" {
		t.Fatalf("after first reap: %+v", j)
	}
	if _, err := e.sched.Heartbeat(ctx, rn, l.Job.ID, l.ID); !errors.Is(err, scheduler.ErrLeaseLost) {
		t.Fatalf("heartbeat on reaped lease err = %v", err)
	}
	l, _ = e.sched.Lease(ctx, rn)
	if l == nil || l.Job.Attempt != 2 {
		t.Fatalf("second attempt lease = %+v", l)
	}
	e.clk.advance(2 * time.Minute)
	if n, err := e.sched.Reap(ctx); err != nil || n < 1 {
		t.Fatalf("second reap = %d %v", n, err)
	}
	j := e.jobs(r.ID)["test"]
	if j.Status != domain.JobFailed || j.FailureReason != "the runner stopped responding" {
		t.Fatalf("after attempts exhausted: %+v", j)
	}
	if e.runStatus(r.ID) != domain.RunFailed {
		t.Fatalf("run = %s", e.runStatus(r.ID))
	}
	if _, err := e.sched.Reap(ctx); err != nil {
		t.Fatal(err)
	}
	if j := e.jobs(r.ID)["test"]; j.Status != domain.JobFailed {
		t.Fatalf("idle reap changed the finished job: %+v", j)
	}
}

func TestHeartbeat_ReportsCancelAndTimeout(t *testing.T) {
	e := newEnv(t)
	r := e.run(twoJobs, false)
	ctx := t.Context()
	rn := e.runner(nil, false)
	l, _ := e.sched.Lease(ctx, rn)
	_ = e.sched.Complete(ctx, rn, l.Job.ID, l.ID, scheduler.Result{Status: domain.JobSucceeded, ExitCode: exit(0)})
	l, _ = e.sched.Lease(ctx, rn) // test: 5m timeout

	// Keep the lease alive past the job timeout: the runner is told to stop.
	for range 7 {
		e.clk.advance(50 * time.Second)
		if _, err := e.sched.Heartbeat(ctx, rn, l.Job.ID, l.ID); err != nil {
			t.Fatal(err)
		}
	}
	hb, err := e.sched.Heartbeat(ctx, rn, l.Job.ID, l.ID)
	if err != nil || !hb.Cancel || hb.Reason != "timed out" {
		t.Fatalf("heartbeat past timeout = %+v %v", hb, err)
	}
	// The runner never reports: after timeout + grace the reaper fails it.
	e.clk.advance(2 * time.Minute)
	_, _ = e.sched.Heartbeat(ctx, rn, l.Job.ID, l.ID)
	if n, err := e.sched.Reap(ctx); err != nil || n < 1 { // the database is shared with other tests
		t.Fatalf("reap = %d %v", n, err)
	}
	if j := e.jobs(r.ID)["test"]; j.Status != domain.JobFailed || !strings.HasPrefix(j.FailureReason, "timed out") {
		t.Fatalf("timed out job = %+v", j)
	}
}

func TestCancel_RunningJobIsCanceledThroughTheRunner(t *testing.T) {
	e := newEnv(t)
	r := e.run(twoJobs, false)
	ctx := t.Context()
	rn := e.runner(nil, false)
	l, _ := e.sched.Lease(ctx, rn)
	if err := e.st.RequestJobCancel(ctx, e.org.ID, l.Job.ID); err != nil {
		t.Fatal(err)
	}
	// Simulate the service's cancel of the pending job.
	if err := e.st.UpdateJobStatus(ctx, store.JobStatusChange{OrgID: e.org.ID, JobID: e.jobs(r.ID)["test"].ID, From: domain.JobPending, To: domain.JobCanceled, At: e.clk.now()}); err != nil {
		t.Fatal(err)
	}
	hb, err := e.sched.Heartbeat(ctx, rn, l.Job.ID, l.ID)
	if err != nil || !hb.Cancel || hb.Reason != "canceled" {
		t.Fatalf("heartbeat = %+v %v", hb, err)
	}
	if err := e.sched.Complete(ctx, rn, l.Job.ID, l.ID, scheduler.Result{Status: domain.JobCanceled, ExitCode: exit(137)}); err != nil {
		t.Fatal(err)
	}
	if e.runStatus(r.ID) != domain.RunCanceled {
		t.Fatalf("run = %s", e.runStatus(r.ID))
	}
}
