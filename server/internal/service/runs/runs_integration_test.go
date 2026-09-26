// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runs_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/engine/spec"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/scheduler"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/service/paging"
	"github.com/yamatrireddy/kilnci/server/internal/service/runs"
	"github.com/yamatrireddy/kilnci/server/internal/store"
	"github.com/yamatrireddy/kilnci/server/internal/store/storetest"
)

type harness struct {
	t        *testing.T
	st       *store.Store
	svc      *runs.Service
	recorder *audit.Recorder
	gen      *ids.Generator
	org      domain.Org
	project  domain.Project
	other    domain.Project // second project in the same org
	users    map[domain.Role]*authz.Principal
	outsider *authz.Principal
}

const pipelineYAML = `version: 1
env:
  SHARED: base
  OVERRIDE: base
jobs:
  build:
    image: golang:1.27
    runs-on: [linux]
    env:
      OVERRIDE: job
    steps:
      - run: go build ./...
  test:
    image: golang:1.27
    needs: [build]
    retries: 2
    steps:
      - name: Unit
        run: go test ./...
  lint:
    image: golang:1.27
    steps:
      - run: golangci-lint run
`

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := t.Context()
	st := storetest.New(t)
	gen := ids.NewGenerator(nil)
	now := func() time.Time { return time.Now().UTC() }
	rec := audit.NewRecorder(st, gen, now)
	h := &harness{t: t, st: st, recorder: rec, gen: gen, users: map[domain.Role]*authz.Principal{}}
	h.svc = runs.NewService(st, authz.NewAuthorizer(st), rec, scheduler.NewProgressor(st, now), gen, now)

	mkOrg := func() domain.Org {
		o, err := st.CreateOrg(ctx, domain.Org{ID: gen.New(), Slug: storetest.Unique("o"), Name: "Org", CreatedAt: now()})
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	mkUser := func(org domain.Org, role domain.Role) *authz.Principal {
		u, err := st.CreateUser(ctx, domain.User{ID: gen.New(), Issuer: "https://idp.test", Subject: storetest.Unique("s"),
			Email: storetest.Unique("u") + "@kiln.test", DisplayName: "U", CreatedAt: now()})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AddMembership(ctx, domain.Membership{OrgID: org.ID, UserID: u.ID, Role: role}, now()); err != nil {
			t.Fatal(err)
		}
		return &authz.Principal{Kind: authz.KindUser, Method: authz.MethodSession, UserID: u.ID}
	}
	mkProject := func(org domain.Org) domain.Project {
		p, err := st.CreateProject(ctx, domain.Project{ID: gen.New(), OrgID: org.ID, Slug: storetest.Unique("p"), Name: "P", CreatedAt: now()})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	h.org = mkOrg()
	h.project, h.other = mkProject(h.org), mkProject(h.org)
	for _, r := range domain.AllRoles {
		h.users[r] = mkUser(h.org, r)
	}
	foreign := mkOrg()
	h.outsider = mkUser(foreign, domain.RoleOwner)
	return h
}

func (h *harness) as(p *authz.Principal) context.Context {
	return authz.WithPrincipal(h.t.Context(), p)
}

func (h *harness) create(nr runs.NewRun) domain.Run {
	h.t.Helper()
	nr.Trusted = !nr.IsFork // the harness models same-repository changes as trusted
	if nr.Pipeline == nil && nr.PipelineErr == nil {
		pl, err := spec.Parse([]byte(pipelineYAML))
		if err != nil {
			h.t.Fatal(err)
		}
		nr.Pipeline = pl
	}
	if nr.OrgID == "" {
		nr.OrgID, nr.ProjectID = h.org.ID, h.project.ID
	}
	if nr.Event == "" {
		nr.Event = domain.EventPush
	}
	if nr.Ref == "" {
		nr.Ref, nr.Branch = "refs/heads/main", "main"
	}
	if nr.CommitSHA == "" {
		nr.CommitSHA = strings.Repeat("a1", 20)
	}
	r, err := h.svc.CreateRun(h.t.Context(), nr)
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

func (h *harness) detail(runID string) runs.Detail {
	h.t.Helper()
	d, err := h.svc.GetRun(h.as(h.users[domain.RoleViewer]), h.org.Slug, h.project.Slug, runID)
	if err != nil {
		h.t.Fatal(err)
	}
	return d
}

func jobStatus(d runs.Detail, name string) domain.JobStatus {
	for _, j := range d.Jobs {
		if j.Name == name {
			return j.Status
		}
	}
	return ""
}

func TestCreateRun_QueuesRootJobsAndStoresPipeline(t *testing.T) {
	h := newHarness(t)
	r := h.create(runs.NewRun{Title: "Fix\x1b[31m bug\u202e\u200dx\nsecond line", ActorLogin: "octocat"})
	if r.Status != domain.RunQueued || r.Number < 1 || !r.Trusted || r.IsFork {
		t.Fatalf("run = %+v", r)
	}
	if r.Title != "Fix\uFFFD[31m bug\uFFFD\uFFFDx" {
		t.Fatalf("title not sanitized: %q", r.Title)
	}
	d := h.detail(r.ID)
	if len(d.Jobs) != 3 || jobStatus(d, "build") != domain.JobQueued || jobStatus(d, "lint") != domain.JobQueued ||
		jobStatus(d, "test") != domain.JobPending {
		t.Fatalf("jobs = %+v", d.Jobs)
	}
	for _, j := range d.Jobs {
		switch j.Name {
		case "build":
			want := []domain.EnvVar{{Name: "OVERRIDE", Value: "job"}, {Name: "SHARED", Value: "base"}}
			if len(j.Env) != 2 || j.Env[0] != want[0] || j.Env[1] != want[1] || j.Labels[0] != "linux" {
				t.Fatalf("build env/labels = %+v %v", j.Env, j.Labels)
			}
		case "test":
			if j.MaxAttempts != 3 || j.Steps[0].Name != "Unit" || j.Steps[0].Run != "go test ./..." || j.Timeout != spec.DefaultJobTimeout {
				t.Fatalf("test job = %+v", j)
			}
		}
	}
	// Numbers are sequential per project.
	r2 := h.create(runs.NewRun{})
	if r2.Number != r.Number+1 {
		t.Fatalf("numbers %d then %d", r.Number, r2.Number)
	}
}

func TestCreateRun_ForkRunsAwaitApprovalAndAreUntrusted(t *testing.T) {
	h := newHarness(t)
	r := h.create(runs.NewRun{Event: domain.EventPullRequest, Ref: "refs/pull/9/head", Branch: "patch", PRNumber: 9, IsFork: true})
	if r.Status != domain.RunAwaitingApproval || r.Trusted {
		t.Fatalf("fork run = %+v", r)
	}
	for _, j := range h.detail(r.ID).Jobs {
		if j.Status != domain.JobPending || j.Trusted {
			t.Fatalf("fork job %s = %s trusted=%v", j.Name, j.Status, j.Trusted)
		}
	}
}

func TestCreateRun_InvalidPipelineCreatesFailedRun(t *testing.T) {
	h := newHarness(t)
	_, perr := spec.Parse([]byte("version: 1\n"))
	r := h.create(runs.NewRun{PipelineErr: perr})
	if r.Status != domain.RunFailed || r.Error != "invalid pipeline: jobs (line 1): is required" || r.FinishedAt == nil {
		t.Fatalf("run = %+v", r)
	}
	// Raw errors never reach viewers; only fixed messages do.
	r = h.create(runs.NewRun{PipelineErr: errors.New("fetch https://internal.example/secret: status 500")})
	if r.Error != "the pipeline could not be loaded" {
		t.Fatalf("raw error stored: %q", r.Error)
	}
	r = h.create(runs.NewRun{PipelineErr: fmt.Errorf("fetch: %w", runs.ErrNoPipeline)})
	if r.Error != "no .kiln/pipeline.yaml in this commit" {
		t.Fatalf("missing pipeline error = %q", r.Error)
	}
	if d := h.detail(r.ID); len(d.Jobs) != 0 {
		t.Fatalf("failed run has jobs: %+v", d.Jobs)
	}
}

// TestCreateRun_TrustFailsClosed: a caller that does not positively assert
// trust (e.g. fork detection failed because the head repo was deleted) gets
// an untrusted run that needs approval.
func TestCreateRun_TrustFailsClosed(t *testing.T) {
	h := newHarness(t)
	pl, _ := spec.Parse([]byte(pipelineYAML))
	r, err := h.svc.CreateRun(t.Context(), runs.NewRun{
		OrgID: h.org.ID, ProjectID: h.project.ID, Event: domain.EventPullRequest, Ref: "refs/pull/4/head",
		CommitSHA: strings.Repeat("b", 40), Pipeline: pl,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Trusted || r.Status != domain.RunAwaitingApproval {
		t.Fatalf("zero-value trust gave %+v", r)
	}
	// A fork is never trusted even if a caller claims it is.
	r, err = h.svc.CreateRun(t.Context(), runs.NewRun{
		OrgID: h.org.ID, ProjectID: h.project.ID, Event: domain.EventPullRequest, Ref: "refs/pull/5/head",
		CommitSHA: strings.Repeat("b", 40), Pipeline: pl, Trusted: true, IsFork: true,
	})
	if err != nil || r.Trusted || r.Status != domain.RunAwaitingApproval {
		t.Fatalf("trusted fork = %+v %v", r, err)
	}
}

// TestCreateRun_OrgMustOwnProject: the composite foreign key rejects a run
// filed under another org's project even if a caller mixes them up.
func TestCreateRun_OrgMustOwnProject(t *testing.T) {
	h := newHarness(t)
	other := newHarness(t)
	pl, _ := spec.Parse([]byte(pipelineYAML))
	_, err := h.svc.CreateRun(t.Context(), runs.NewRun{
		OrgID: h.org.ID, ProjectID: other.project.ID, Event: domain.EventPush, Ref: "refs/heads/main",
		CommitSHA: strings.Repeat("b", 40), Pipeline: pl, Trusted: true,
	})
	if err == nil {
		t.Fatal("run created under another org's project")
	}
}

func TestCreateRun_IdempotencyKeyReturnsSameRun(t *testing.T) {
	h := newHarness(t)
	a := h.create(runs.NewRun{Event: domain.EventManual, IdempotencyKey: "retry-1"})
	b := h.create(runs.NewRun{Event: domain.EventManual, IdempotencyKey: "retry-1"})
	if a.ID != b.ID {
		t.Fatalf("idempotent create returned %s then %s", a.ID, b.ID)
	}
	// Reusing the key for a different request is rejected.
	pl, _ := spec.Parse([]byte(pipelineYAML))
	_, err := h.svc.CreateRun(t.Context(), runs.NewRun{
		OrgID: h.org.ID, ProjectID: h.project.ID, Event: domain.EventManual, Ref: "refs/heads/main",
		CommitSHA: strings.Repeat("f", 40), IdempotencyKey: "retry-1", Pipeline: pl, Trusted: true,
	})
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("key reuse with another SHA err = %v", err)
	}
	// The same key in another project is independent.
	c := h.create(runs.NewRun{OrgID: h.org.ID, ProjectID: h.other.ID, Event: domain.EventManual, Ref: "refs/heads/main", IdempotencyKey: "retry-1"})
	if c.ID == a.ID {
		t.Fatal("idempotency key leaked across projects")
	}
}

func TestCreateRun_RejectsBadIdentifiers(t *testing.T) {
	h := newHarness(t)
	pl, _ := spec.Parse([]byte(pipelineYAML))
	cases := []runs.NewRun{
		{CommitSHA: "not-a-sha", Ref: "refs/heads/main", Event: domain.EventPush},
		{CommitSHA: strings.Repeat("a", 40), Ref: "refs/heads/../x", Event: domain.EventPush},
		{CommitSHA: strings.Repeat("a", 40), Ref: "refs/tags/v1", Event: domain.EventPush},
		{CommitSHA: strings.Repeat("a", 40), Ref: "refs/heads/main", Event: "schedule"},
		{CommitSHA: strings.Repeat("a", 40), Ref: "refs/pull/1/head", Event: domain.EventPullRequest, PRNumber: 1 << 31},
	}
	for _, nr := range cases {
		nr.OrgID, nr.ProjectID, nr.Pipeline = h.org.ID, h.project.ID, pl
		if _, err := h.svc.CreateRun(t.Context(), nr); !errors.Is(err, domain.ErrValidation) {
			t.Errorf("CreateRun(%q, %q, %q) err = %v, want validation", nr.CommitSHA, nr.Ref, nr.Event, err)
		}
	}
}

func TestCancelRun(t *testing.T) {
	h := newHarness(t)
	r := h.create(runs.NewRun{})
	dev := h.as(h.users[domain.RoleDeveloper])
	d, err := h.svc.CancelRun(dev, h.org.Slug, h.project.Slug, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Run.Status != domain.RunCanceled || d.Run.FinishedAt == nil {
		t.Fatalf("run = %+v", d.Run)
	}
	for _, j := range d.Jobs {
		if j.Status != domain.JobCanceled {
			t.Fatalf("job %s = %s", j.Name, j.Status)
		}
	}
	if _, err := h.svc.CancelRun(dev, h.org.Slug, h.project.Slug, r.ID); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second cancel err = %v, want conflict", err)
	}

	// A fork run awaiting approval can be canceled too.
	fork := h.create(runs.NewRun{Event: domain.EventPullRequest, Ref: "refs/pull/1/head", IsFork: true})
	d, err = h.svc.CancelRun(dev, h.org.Slug, h.project.Slug, fork.ID)
	if err != nil || d.Run.Status != domain.RunCanceled {
		t.Fatalf("cancel fork run = %v %+v", err, d.Run)
	}
	if err := h.recorder.VerifyChain(t.Context(), h.org.ID); err != nil {
		t.Fatal(err)
	}
}

func TestApproveRun(t *testing.T) {
	h := newHarness(t)
	fork := h.create(runs.NewRun{Event: domain.EventPullRequest, Ref: "refs/pull/1/head", IsFork: true})
	dev := h.as(h.users[domain.RoleDeveloper])
	d, err := h.svc.ApproveRun(dev, h.org.Slug, h.project.Slug, fork.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Run.Status != domain.RunQueued || jobStatus(d, "build") != domain.JobQueued || jobStatus(d, "test") != domain.JobPending {
		t.Fatalf("approved run = %+v jobs=%+v", d.Run, d.Jobs)
	}
	if d.Run.Trusted {
		t.Fatal("approval must not make a fork run trusted")
	}
	if _, err := h.svc.ApproveRun(dev, h.org.Slug, h.project.Slug, fork.ID); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second approve err = %v", err)
	}
	trusted := h.create(runs.NewRun{})
	if _, err := h.svc.ApproveRun(dev, h.org.Slug, h.project.Slug, trusted.ID); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("approving a queued run err = %v", err)
	}
}

func TestRunAccessControl(t *testing.T) {
	h := newHarness(t)
	r := h.create(runs.NewRun{})
	viewer := h.as(h.users[domain.RoleViewer])

	// Viewers read but cannot cancel or approve.
	if _, err := h.svc.CancelRun(viewer, h.org.Slug, h.project.Slug, r.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("viewer cancel err = %v", err)
	}
	if _, err := h.svc.ApproveRun(viewer, h.org.Slug, h.project.Slug, r.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("viewer approve err = %v", err)
	}
	// Outsiders get 404 for everything, even with a valid run ID.
	out := h.as(h.outsider)
	if _, err := h.svc.GetRun(out, h.org.Slug, h.project.Slug, r.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("outsider get err = %v", err)
	}
	if _, err := h.svc.ListRuns(out, h.org.Slug, h.project.Slug, paging.Request{}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("outsider list err = %v", err)
	}
	if _, err := h.svc.CancelRun(out, h.org.Slug, h.project.Slug, r.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("outsider cancel err = %v", err)
	}
	// A run ID from another project of the same org is not found here.
	if _, err := h.svc.GetRun(viewer, h.org.Slug, h.other.Slug, r.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-project get err = %v", err)
	}
	if _, err := h.svc.GetRun(viewer, h.org.Slug, h.project.Slug, "not-an-id"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("malformed id err = %v", err)
	}
	// Unauthenticated.
	if _, err := h.svc.GetRun(t.Context(), h.org.Slug, h.project.Slug, r.ID); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("anonymous get err = %v", err)
	}
}

func TestListRuns_PaginatesNewestFirst(t *testing.T) {
	h := newHarness(t)
	var created []string
	for range 5 {
		created = append(created, h.create(runs.NewRun{}).ID)
	}
	viewer := h.as(h.users[domain.RoleViewer])
	var got []string
	pr := paging.Request{Limit: 2}
	for {
		pg, err := h.svc.ListRuns(viewer, h.org.Slug, h.project.Slug, pr)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range pg.Items {
			got = append(got, r.ID)
		}
		if pg.NextCursor == "" {
			break
		}
		pr.Cursor = pg.NextCursor
	}
	if len(got) != 5 {
		t.Fatalf("listed %d runs", len(got))
	}
	for i := range got {
		if got[i] != created[len(created)-1-i] {
			t.Fatalf("order = %v, want reverse of %v", got, created)
		}
	}
	if _, err := h.svc.ListRuns(viewer, h.org.Slug, h.project.Slug, paging.Request{Cursor: "!!"}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad cursor err = %v", err)
	}
}

func TestLintPipeline(t *testing.T) {
	h := newHarness(t)
	ctx := h.as(h.outsider) // lint needs no membership
	problems, err := h.svc.LintPipeline(ctx, pipelineYAML)
	if err != nil || len(problems) != 0 {
		t.Fatalf("valid pipeline: %v %v", problems, err)
	}
	problems, err = h.svc.LintPipeline(ctx, "version: 1\njobs:\n  a:\n    image: alpine\n    steps: [{run: \"${{ x }}\"}]\n")
	if err != nil || len(problems) != 1 || !strings.Contains(problems[0].Message, "expressions") {
		t.Fatalf("expression pipeline: %v %v", problems, err)
	}
	if _, err := h.svc.LintPipeline(t.Context(), "version: 1"); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("anonymous lint err = %v", err)
	}
}
