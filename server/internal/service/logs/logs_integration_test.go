// SPDX-License-Identifier: Apache-2.0

//go:build integration

package logs_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/engine/spec"
	"github.com/yamatrireddy/kilnci/server/internal/platform/bus"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/platform/objstore"
	"github.com/yamatrireddy/kilnci/server/internal/scheduler"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/service/logs"
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
	t        *testing.T
	clk      *clock
	st       *store.Store
	logs     *logs.Service
	sched    *scheduler.Scheduler
	runs     *runs.Service
	org      domain.Org
	project  domain.Project
	viewer   *authz.Principal
	outsider *authz.Principal
}

func newEnv(t *testing.T, maxBytes int64) *env {
	t.Helper()
	ctx := t.Context()
	st := storetest.New(t)
	gen := ids.NewGenerator(nil)
	obj, err := objstore.NewFS(t.TempDir() + "/logs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = obj.Close() })
	az := authz.NewAuthorizer(st)
	clk := &clock{t: time.Now().UTC()}
	sched := scheduler.New(st, logging.Discard(), scheduler.Options{LeaseTTL: time.Minute, TimeoutGrace: time.Minute}, clk.now)
	e := &env{t: t, st: st, sched: sched, clk: clk,
		logs: logs.NewService(st, az, obj, bus.NewInProcess(), logs.Options{MaxLogBytes: maxBytes, StreamPoll: 50 * time.Millisecond}, clk.now),
		runs: runs.NewService(st, az, audit.NewRecorder(st, gen, nil), sched.Progressor(), gen, nil),
	}
	mkOrg := func() domain.Org {
		o, err := st.CreateOrg(ctx, domain.Org{ID: gen.New(), Slug: storetest.Unique("o"), Name: "O", CreatedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	mkUser := func(org domain.Org, role domain.Role) *authz.Principal {
		u, err := st.CreateUser(ctx, domain.User{ID: gen.New(), Issuer: "https://idp.test", Subject: storetest.Unique("s"),
			Email: storetest.Unique("u") + "@kiln.test", DisplayName: "U", CreatedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AddMembership(ctx, domain.Membership{OrgID: org.ID, UserID: u.ID, Role: role}, time.Now()); err != nil {
			t.Fatal(err)
		}
		return &authz.Principal{Kind: authz.KindUser, Method: authz.MethodSession, UserID: u.ID}
	}
	e.org = mkOrg()
	e.project, err = st.CreateProject(ctx, domain.Project{ID: gen.New(), OrgID: e.org.ID, Slug: "p", Name: "P", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	e.viewer = mkUser(e.org, domain.RoleViewer)
	e.outsider = mkUser(mkOrg(), domain.RoleOwner)
	return e
}

// leased creates a one-job run and leases the job to a fresh runner.
func (e *env) leased() (scheduler.Runner, *scheduler.Lease) {
	e.t.Helper()
	ctx := e.t.Context()
	pl, err := spec.Parse([]byte("version: 1\njobs:\n  a:\n    image: alpine\n    retries: 1\n    steps: [{run: x}]\n"))
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.runs.CreateRun(ctx, runs.NewRun{OrgID: e.org.ID, ProjectID: e.project.ID, Event: domain.EventPush,
		Ref: "refs/heads/main", CommitSHA: strings.Repeat("a", 40), Trusted: true, Pipeline: pl}); err != nil {
		e.t.Fatal(err)
	}
	id := ids.NewGenerator(nil).New()
	now := e.clk.now()
	if err := e.st.CreateRunner(ctx, domain.Runner{ID: id, OrgID: e.org.ID, Name: "r", CertSerial: id, CertDER: []byte{1},
		CertSPKIHash: []byte{1}, CertRenewedAt: now, CertExpiresAt: now.Add(time.Hour), CreatedAt: now}); err != nil {
		e.t.Fatal(err)
	}
	rn := scheduler.Runner{ID: id, OrgID: e.org.ID}
	l, err := e.sched.Lease(ctx, rn)
	if err != nil || l == nil {
		e.t.Fatalf("lease: %v", err)
	}
	return rn, l
}

func (e *env) ref(l *scheduler.Lease) logs.JobRef {
	return logs.JobRef{OrgSlug: e.org.Slug, ProjectSlug: e.project.Slug, RunID: l.Run.ID, JobID: l.Job.ID}
}

func (e *env) read(p *authz.Principal, ref logs.JobRef) (string, error) {
	var b bytes.Buffer
	err := e.logs.Read(authz.WithPrincipal(e.t.Context(), p), ref, &b)
	return b.String(), err
}

func TestAppend_OrderedIdempotentAndLeaseBound(t *testing.T) {
	e := newEnv(t, 0)
	ctx := t.Context()
	rn, l := e.leased()
	for i, chunk := range []string{"hello ", "world\n"} {
		if tr, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, i, []byte(chunk)); err != nil || tr {
			t.Fatalf("append %d = %v %v", i, tr, err)
		}
	}
	// Identical replay is fine; different content for the same seq is not.
	if _, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, 1, []byte("world\n")); err != nil {
		t.Fatalf("replay = %v", err)
	}
	if _, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, 1, []byte("forged\n")); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("forged replay = %v", err)
	}
	if _, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, 5, []byte("gap")); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("gap = %v", err)
	}
	if _, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, 2, make([]byte, logs.MaxChunkBytes+1)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("oversized = %v", err)
	}
	other := scheduler.Runner{ID: ids.NewGenerator(nil).New(), OrgID: e.org.ID}
	if _, err := e.logs.Append(ctx, other, l.Job.ID, l.ID, 2, []byte("x")); !errors.Is(err, scheduler.ErrLeaseLost) {
		t.Fatalf("other runner = %v", err)
	}
	if got, err := e.read(e.viewer, e.ref(l)); err != nil || got != "hello world\n" {
		t.Fatalf("read = %q %v", got, err)
	}
	if _, err := e.read(e.outsider, e.ref(l)); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("outsider read = %v", err)
	}
	bad := e.ref(l)
	bad.RunID = ids.NewGenerator(nil).New()
	if _, err := e.read(e.viewer, bad); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("job under another run = %v", err)
	}
	if _, err := e.read(nil, e.ref(l)); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("anonymous read = %v", err)
	}
}

func TestAppend_TruncatesAtTheLimit(t *testing.T) {
	e := newEnv(t, 1<<20)
	ctx := t.Context()
	rn, l := e.leased()
	chunk := bytes.Repeat([]byte("x"), 200<<10)
	truncatedAt := -1
	for i := range 8 {
		tr, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, i, chunk)
		if err != nil {
			t.Fatal(err)
		}
		if tr && truncatedAt < 0 {
			truncatedAt = i
		}
	}
	got, err := e.read(e.viewer, e.ref(l))
	if err != nil {
		t.Fatal(err)
	}
	if truncatedAt < 0 || len(got) > 1<<20 || !strings.HasSuffix(got, logs.TruncationMarker) {
		t.Fatalf("truncatedAt=%d len=%d suffix=%q", truncatedAt, len(got), got[max(0, len(got)-60):])
	}
}

func TestStream_FollowsUntilTheJobEnds(t *testing.T) {
	e := newEnv(t, 0)
	ctx := t.Context()
	rn, l := e.leased()
	if _, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, 0, []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []logs.Event
	done := make(chan error, 1)
	go func() {
		done <- e.logs.Stream(authz.WithPrincipal(ctx, e.viewer), e.ref(l), logs.Position{}, func(ev logs.Event) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, ev)
			return nil
		})
	}()
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) >= 2 })
	if _, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, 1, []byte("second\n")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) >= 3 })
	zero := 0
	if err := e.sched.Complete(ctx, rn, l.Job.ID, l.ID, scheduler.Result{Status: domain.JobSucceeded, ExitCode: &zero}); err != nil {
		t.Fatal(err)
	}
	e.logs.Notify(ctx, e.org.ID, l.Job.ID)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not end after the job finished")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 4 || !got[0].NewAttempt || got[0].Attempt != 1 || string(got[1].Data) != "first\n" || got[2].Seq != 1 ||
		!got[3].End || got[3].Status != domain.JobSucceeded {
		t.Fatalf("events = %+v", got)
	}

	// Resuming after seq 0 replays only what follows.
	var resumed []logs.Event
	if err := e.logs.Stream(authz.WithPrincipal(ctx, e.viewer), e.ref(l), logs.Position{Attempt: 1, Seq: 1}, func(ev logs.Event) error {
		resumed = append(resumed, ev)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(resumed) != 3 || !resumed[0].NewAttempt || resumed[1].Seq != 1 || !resumed[2].End {
		t.Fatalf("resumed = %+v", resumed)
	}
	if err := e.logs.Stream(authz.WithPrincipal(ctx, e.outsider), e.ref(l), logs.Position{}, func(logs.Event) error { return nil }); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("outsider stream = %v", err)
	}
}

// TestAppend_EachAttemptHasItsOwnLog: a job re-queued after its lease
// lapsed logs its second attempt from chunk 0, readers see the latest
// attempt, and the first attempt's runner can no longer append (security
// review finding: retries collided with the first attempt's chunks).
func TestAppend_EachAttemptHasItsOwnLog(t *testing.T) {
	e := newEnv(t, 0)
	ctx := t.Context()
	rn, l1 := e.leased()
	if _, err := e.logs.Append(ctx, rn, l1.Job.ID, l1.ID, 0, []byte("attempt one\n")); err != nil {
		t.Fatal(err)
	}
	e.clk.advance(2 * time.Minute) // the lease lapses
	if _, err := e.logs.Append(ctx, rn, l1.Job.ID, l1.ID, 1, []byte("late\n")); !errors.Is(err, scheduler.ErrLeaseLost) {
		t.Fatalf("append on a lapsed lease = %v", err)
	}
	if n, err := e.sched.Reap(ctx); err != nil || n < 1 { // the database is shared with other tests
		t.Fatalf("reap = %d %v", n, err)
	}
	// Until the retry is leased, readers still see the first attempt.
	if got, err := e.read(e.viewer, e.ref(l1)); err != nil || got != "attempt one\n" {
		t.Fatalf("read between attempts = %q %v", got, err)
	}
	l2, err := e.sched.Lease(ctx, rn)
	if err != nil || l2 == nil || l2.Job.ID != l1.Job.ID || l2.Job.Attempt != 2 {
		t.Fatalf("second lease = %+v %v", l2, err)
	}
	if _, err := e.logs.Append(ctx, rn, l1.Job.ID, l1.ID, 1, []byte("stale\n")); !errors.Is(err, scheduler.ErrLeaseLost) {
		t.Fatalf("append with the first lease after a re-lease = %v", err)
	}
	if tr, err := e.logs.Append(ctx, rn, l2.Job.ID, l2.ID, 0, []byte("attempt two\n")); err != nil || tr {
		t.Fatalf("second attempt seq 0 = %v %v", tr, err)
	}
	if got, err := e.read(e.viewer, e.ref(l2)); err != nil || got != "attempt two\n" {
		t.Fatalf("read = %q %v", got, err)
	}
	// Both attempts' chunks are kept, attributed to their lease.
	first, err := e.st.GetJobLogChunk(ctx, e.org.ID, l1.Job.ID, 1, 0)
	if err != nil || first.Attempt != 1 {
		t.Fatalf("first attempt chunk = %+v %v", first, err)
	}
	if _, err := e.st.GetJobLogChunk(ctx, e.org.ID, l1.Job.ID, 1, 1); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("stale append was stored: %v", err)
	}
}

// TestStream_FollowsARetry: a stream open across a retry announces the new
// attempt and restarts its chunk numbers.
func TestStream_FollowsARetry(t *testing.T) {
	e := newEnv(t, 0)
	ctx := t.Context()
	rn, l1 := e.leased()
	if _, err := e.logs.Append(ctx, rn, l1.Job.ID, l1.ID, 0, []byte("one\n")); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []logs.Event
	done := make(chan error, 1)
	go func() {
		done <- e.logs.Stream(authz.WithPrincipal(ctx, e.viewer), e.ref(l1), logs.Position{}, func(ev logs.Event) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, ev)
			return nil
		})
	}()
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) >= 2 })
	e.clk.advance(2 * time.Minute)
	if _, err := e.sched.Reap(ctx); err != nil {
		t.Fatal(err)
	}
	l2, err := e.sched.Lease(ctx, rn)
	if err != nil || l2 == nil || l2.Job.ID != l1.Job.ID {
		t.Fatalf("second lease = %+v %v", l2, err)
	}
	if _, err := e.logs.Append(ctx, rn, l2.Job.ID, l2.ID, 0, []byte("two\n")); err != nil {
		t.Fatal(err)
	}
	zero := 0
	if err := e.sched.Complete(ctx, rn, l2.Job.ID, l2.ID, scheduler.Result{Status: domain.JobSucceeded, ExitCode: &zero}); err != nil {
		t.Fatal(err)
	}
	e.logs.Notify(ctx, e.org.ID, l2.Job.ID)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not end after the job finished")
	}
	mu.Lock()
	defer mu.Unlock()
	want := []logs.Event{
		{Attempt: 1, NewAttempt: true}, {Attempt: 1, Data: []byte("one\n")},
		{Attempt: 2, NewAttempt: true}, {Attempt: 2, Data: []byte("two\n")},
		{Attempt: 2, End: true, Status: domain.JobSucceeded},
	}
	if len(got) != len(want) {
		t.Fatalf("events = %+v", got)
	}
	for i := range want {
		if got[i].Attempt != want[i].Attempt || got[i].NewAttempt != want[i].NewAttempt || got[i].Seq != want[i].Seq ||
			string(got[i].Data) != string(want[i].Data) || got[i].End != want[i].End || got[i].Status != want[i].Status {
			t.Fatalf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestAppend_ReplayOfTheTruncatingChunk: the chunk that reached the limit
// is stored cut short, but replaying what the runner sent is still an
// idempotent replay, not a conflict.
func TestAppend_ReplayOfTheTruncatingChunk(t *testing.T) {
	e := newEnv(t, 300<<10)
	ctx := t.Context()
	rn, l := e.leased()
	chunk := bytes.Repeat([]byte("y"), 200<<10)
	if tr, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, 0, chunk); err != nil || tr {
		t.Fatalf("first = %v %v", tr, err)
	}
	if tr, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, 1, chunk); err != nil || !tr {
		t.Fatalf("truncating = %v %v", tr, err)
	}
	if tr, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, 1, chunk); err != nil || !tr {
		t.Fatalf("replay of the truncating chunk = %v %v", tr, err)
	}
	if _, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, 1, bytes.Repeat([]byte("z"), 200<<10)); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("different content = %v", err)
	}
}

// TestAppend_ConcurrentSameSeq: two appends racing for one chunk number
// with different content store one and reject the other as a conflict, and
// the stored object matches the recorded chunk (security review).
func TestAppend_ConcurrentSameSeq(t *testing.T) {
	e := newEnv(t, 0)
	ctx := t.Context()
	rn, l := e.leased()
	for round := range 20 {
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range 2 {
			wg.Go(func() {
				_, errs[i] = e.logs.Append(ctx, rn, l.Job.ID, l.ID, round, []byte(fmt.Sprintf("r%d-%d\n", round, i)))
			})
		}
		wg.Wait()
		ok, conflicts := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, domain.ErrConflict):
				conflicts++
			default:
				t.Fatalf("round %d: unexpected error %v", round, err)
			}
		}
		if ok != 1 || conflicts != 1 {
			t.Fatalf("round %d: %d stored, %d conflicts", round, ok, conflicts)
		}
	}
	got, err := e.read(e.viewer, e.ref(l))
	if err != nil {
		t.Fatal(err)
	}
	for round := range 20 {
		if !strings.Contains(got, fmt.Sprintf("r%d-", round)) {
			t.Fatalf("round %d missing from %q", round, got)
		}
	}
	if strings.Count(got, "\n") != 20 {
		t.Fatalf("log = %q", got)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
