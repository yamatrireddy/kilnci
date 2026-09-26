// SPDX-License-Identifier: Apache-2.0

//go:build integration

package logs_test

import (
	"bytes"
	"errors"
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

type env struct {
	t        *testing.T
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
	sched := scheduler.New(st, logging.Discard(), scheduler.Options{}, nil)
	e := &env{t: t, st: st, sched: sched,
		logs: logs.NewService(st, az, obj, bus.NewInProcess(), logs.Options{MaxLogBytes: maxBytes, StreamPoll: 50 * time.Millisecond}, nil),
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
	pl, _ := spec.Parse([]byte("version: 1\njobs:\n  a:\n    image: alpine\n    steps: [{run: x}]\n"))
	if _, err := e.runs.CreateRun(ctx, runs.NewRun{OrgID: e.org.ID, ProjectID: e.project.ID, Event: domain.EventPush,
		Ref: "refs/heads/main", CommitSHA: strings.Repeat("a", 40), Trusted: true, Pipeline: pl}); err != nil {
		e.t.Fatal(err)
	}
	id := ids.NewGenerator(nil).New()
	now := time.Now()
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
		done <- e.logs.Stream(authz.WithPrincipal(ctx, e.viewer), e.ref(l), 0, func(ev logs.Event) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, ev)
			return nil
		})
	}()
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) >= 1 })
	if _, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, 1, []byte("second\n")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) >= 2 })
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
	if len(got) != 3 || string(got[0].Data) != "first\n" || got[1].Seq != 1 || !got[2].End || got[2].Status != domain.JobSucceeded {
		t.Fatalf("events = %+v", got)
	}

	// Resuming after seq 0 replays only what follows.
	var resumed []logs.Event
	if err := e.logs.Stream(authz.WithPrincipal(ctx, e.viewer), e.ref(l), 1, func(ev logs.Event) error {
		resumed = append(resumed, ev)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(resumed) != 2 || resumed[0].Seq != 1 || !resumed[1].End {
		t.Fatalf("resumed = %+v", resumed)
	}
	if err := e.logs.Stream(authz.WithPrincipal(ctx, e.outsider), e.ref(l), 0, func(logs.Event) error { return nil }); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("outsider stream = %v", err)
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
