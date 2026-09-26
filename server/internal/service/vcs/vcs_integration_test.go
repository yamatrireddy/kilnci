// SPDX-License-Identifier: Apache-2.0

//go:build integration

package vcs_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/scheduler"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/service/paging"
	"github.com/yamatrireddy/kilnci/server/internal/service/runs"
	"github.com/yamatrireddy/kilnci/server/internal/service/vcs"
	"github.com/yamatrireddy/kilnci/server/internal/store"
	"github.com/yamatrireddy/kilnci/server/internal/store/storetest"
	"github.com/yamatrireddy/kilnci/server/internal/vcs/github/githubtest"
	wh "github.com/yamatrireddy/kilnci/server/internal/webhooks/github"
)

const (
	webhookSecret = "test-webhook-secret-0123456789"
	goodPipeline  = "version: 1\non:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\njobs:\n  build:\n    image: alpine\n    steps: [{run: make}]\n"
)

func sha(c string) string { return strings.Repeat(c, 40) }

type env struct {
	t        *testing.T
	st       *store.Store
	svc      *vcs.Service
	runs     *runs.Service
	gh       *githubtest.Fake
	recorder *audit.Recorder
	org      domain.Org
	other    domain.Org
	project  domain.Project
	project2 domain.Project
	root     *authz.Principal // instance admin
	admin    *authz.Principal
	dev      *authz.Principal
	viewer   *authz.Principal
	outsider *authz.Principal // admin of the other org
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := t.Context()
	st := storetest.New(t)
	gen := ids.NewGenerator(nil)
	fake := &githubtest.Fake{
		Installations: map[int64]bool{11: true, 22: true},
		Repos: map[string]githubtest.Repo{
			"acme/private": {ID: 1001, Private: true, Installations: []int64{11}},
			"acme/public":  {ID: 1002, Installations: []int64{11}},
		},
		Files: map[string]string{},
	}
	client := fake.Client(t)
	az := authz.NewAuthorizer(st)
	rec := audit.NewRecorder(st, gen, nil)
	sched := scheduler.New(st, logging.Discard(), scheduler.Options{}, nil)
	runSvc := runs.NewService(st, az, rec, sched.Progressor(), gen, nil)
	svc := vcs.NewService(st, az, rec, client, runSvc, gen, vcs.Options{WebhookSecret: []byte(webhookSecret), PublicOrigin: "https://kiln.test"}, nil)
	sched.Progressor().SetObserver(svc)
	runSvc.SetObserver(svc)

	e := &env{t: t, st: st, svc: svc, runs: runSvc, gh: fake, recorder: rec}
	mkOrg := func() domain.Org {
		o, err := st.CreateOrg(ctx, domain.Org{ID: gen.New(), Slug: storetest.Unique("o"), Name: "O", CreatedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	mkUser := func(org domain.Org, role domain.Role, instanceAdmin bool) *authz.Principal {
		u, err := st.CreateUser(ctx, domain.User{ID: gen.New(), Issuer: "https://idp.test", Subject: storetest.Unique("s"),
			Email: storetest.Unique("u") + "@kiln.test", DisplayName: "U", InstanceAdmin: instanceAdmin, CreatedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AddMembership(ctx, domain.Membership{OrgID: org.ID, UserID: u.ID, Role: role}, time.Now()); err != nil {
			t.Fatal(err)
		}
		return &authz.Principal{Kind: authz.KindUser, Method: authz.MethodSession, UserID: u.ID, InstanceAdmin: instanceAdmin}
	}
	e.org, e.other = mkOrg(), mkOrg()
	for _, p := range []*domain.Project{&e.project, &e.project2} {
		var err error
		if *p, err = st.CreateProject(ctx, domain.Project{ID: gen.New(), OrgID: e.org.ID, Slug: storetest.Unique("p"), Name: "P", CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	e.root = mkUser(e.other, domain.RoleViewer, true)
	e.admin = mkUser(e.org, domain.RoleAdmin, false)
	e.dev = mkUser(e.org, domain.RoleDeveloper, false)
	e.viewer = mkUser(e.org, domain.RoleViewer, false)
	e.outsider = mkUser(e.other, domain.RoleAdmin, false)
	return e
}

// setup binds installation 11 to the org and links the private repo.
func (e *env) setup() {
	e.t.Helper()
	ctx := authz.WithPrincipal(e.t.Context(), e.root)
	// Unique per test: installation IDs are global, so rebind per test run.
	_ = e.svc.UnbindInstallation(ctx, 11)
	if _, err := e.svc.BindInstallation(ctx, 11, e.org.Slug); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.svc.LinkRepository(authz.WithPrincipal(e.t.Context(), e.admin), e.org.Slug, e.project.Slug, 11, "acme/private"); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) deliver(event string, payload any) {
	e.t.Helper()
	body, _ := json.Marshal(payload)
	if err := e.svc.Ingest(e.t.Context(), event, fmt.Sprintf("d-%d", time.Now().UnixNano()), wh.Sign([]byte(webhookSecret), body), body); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.svc.ProcessDeliveries(e.t.Context()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) runsOf(p domain.Project) []domain.Run {
	e.t.Helper()
	pg, err := e.runs.ListRuns(authz.WithPrincipal(e.t.Context(), e.viewer), e.org.Slug, p.Slug, paging.Request{Limit: 100})
	if err != nil {
		e.t.Fatal(err)
	}
	return pg.Items
}

func push(repoID, installationID int64, ref, after string) map[string]any {
	return map[string]any{
		"ref": ref, "after": after, "repository": map[string]any{"id": repoID}, "installation": map[string]any{"id": installationID},
		"head_commit": map[string]any{"message": "Fix the build\n\nbody", "timestamp": time.Now().Format(time.RFC3339)},
		"sender":      map[string]any{"login": "octocat"},
		// Deliveries are deduplicated by body hash across the shared test
		// database; real deliveries differ in their many other fields.
		"hook_nonce": time.Now().UnixNano(),
	}
}

func pr(number int, headRepo any, headSHA string) map[string]any {
	return map[string]any{
		"action": "opened", "number": number, "repository": map[string]any{"id": 1001}, "installation": map[string]any{"id": 11},
		"sender": map[string]any{"login": "stranger"}, "hook_nonce": time.Now().UnixNano(),
		"pull_request": map[string]any{"title": "Improve things", "head": map[string]any{"ref": "patch", "sha": headSHA, "repo": headRepo},
			"base": map[string]any{"ref": "main", "repo": map[string]any{"id": 1001}}},
	}
}

func TestInstallationBindingAndRepositoryLinking(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if _, err := e.svc.BindInstallation(authz.WithPrincipal(ctx, e.admin), 11, e.org.Slug); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("org admin bound an installation: %v", err)
	}
	root := authz.WithPrincipal(ctx, e.root)
	_ = e.svc.UnbindInstallation(root, 11)
	_ = e.svc.UnbindInstallation(root, 22)
	if _, err := e.svc.BindInstallation(root, 999, e.org.Slug); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("unknown installation = %v", err)
	}
	if _, err := e.svc.BindInstallation(root, 11, e.org.Slug); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.BindInstallation(root, 11, e.other.Slug); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second binding = %v", err)
	}
	if _, err := e.svc.BindInstallation(root, 22, e.other.Slug); err != nil {
		t.Fatal(err)
	}
	admin := authz.WithPrincipal(ctx, e.admin)
	// Another tenant's installation cannot be used, even for a real repo.
	if _, err := e.svc.LinkRepository(admin, e.org.Slug, e.project.Slug, 22, "acme/private"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("link through a foreign installation = %v", err)
	}
	if _, err := e.svc.LinkRepository(admin, e.org.Slug, e.project.Slug, 11, "acme/secret"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("inaccessible repo = %v", err)
	}
	link, err := e.svc.LinkRepository(admin, e.org.Slug, e.project.Slug, 11, "acme/private")
	if err != nil || link.RepoID != 1001 || !link.Private {
		t.Fatalf("link = %+v %v", link, err)
	}
	if _, err := e.svc.LinkRepository(admin, e.org.Slug, e.project2.Slug, 11, "acme/private"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("same repo twice = %v", err)
	}
	if _, err := e.svc.LinkRepository(authz.WithPrincipal(ctx, e.dev), e.org.Slug, e.project2.Slug, 11, "acme/public"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("developer linked a repo: %v", err)
	}
	if r, err := e.svc.GetRepository(authz.WithPrincipal(ctx, e.viewer), e.org.Slug, e.project.Slug); err != nil || r.RepoID != 1001 {
		t.Fatalf("viewer get = %+v %v", r, err)
	}
	if _, err := e.svc.GetRepository(authz.WithPrincipal(ctx, e.outsider), e.org.Slug, e.project.Slug); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("outsider get = %v", err)
	}
	if list, err := e.svc.ListInstallations(admin, e.org.Slug); err != nil || len(list) != 1 || list[0].InstallationID != 11 {
		t.Fatalf("installations = %+v %v", list, err)
	}
	if err := e.recorder.VerifyChain(ctx, e.org.ID); err != nil {
		t.Fatal(err)
	}
}

func TestWebhooks_PushAndPullRequestTriggers(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.gh.SetFile("1001@"+sha("a"), goodPipeline)
	e.gh.SetFile("1001@"+sha("b"), goodPipeline)
	e.gh.SetFile("1001@"+sha("d"), "version: 1\njobs: {}\n")

	// Signature is required; replays of the same body do nothing.
	body, _ := json.Marshal(push(1001, 11, "refs/heads/main", sha("a")))
	if err := e.svc.Ingest(t.Context(), "push", "d1", "sha256=00", body); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("bad signature = %v", err)
	}
	sig := wh.Sign([]byte(webhookSecret), body)
	for _, id := range []string{"d1", "d2", "d1"} {
		if err := e.svc.Ingest(t.Context(), "push", id, sig, body); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = e.svc.ProcessDeliveries(t.Context())
	rs := e.runsOf(e.project)
	if len(rs) != 1 || !rs[0].Trusted || rs[0].Status != domain.RunQueued || rs[0].Title != "Fix the build" || rs[0].Branch != "main" {
		t.Fatalf("push runs = %+v", rs)
	}

	e.deliver("push", push(1001, 11, "refs/heads/feature", sha("a")))             // filtered by on.push.branches
	e.deliver("push", push(1001, 22, "refs/heads/main", sha("b")))                // wrong installation
	e.deliver("push", push(4242, 11, "refs/heads/main", sha("b")))                // unlinked repo
	e.deliver("push", push(1001, 11, "refs/tags/v1", sha("b")))                   // tags ignored
	e.deliver("push", push(1001, 11, "refs/heads/main", strings.Repeat("0", 40))) // deletion
	if n := len(e.runsOf(e.project)); n != 1 {
		t.Fatalf("ignored pushes created runs: %d", n)
	}

	// Fork PR: untrusted and awaiting approval; a deleted fork too.
	e.deliver("pull_request", pr(7, map[string]any{"id": 5555}, sha("b")))
	e.deliver("pull_request", pr(8, nil, sha("b")))
	// Same-repository PR: trusted.
	e.deliver("pull_request", pr(9, map[string]any{"id": 1001}, sha("b")))
	// Invalid pipeline: a failed run explaining why.
	e.deliver("push", push(1001, 11, "refs/heads/main", sha("d")))
	byPR := map[int]domain.Run{}
	var invalid domain.Run
	for _, r := range e.runsOf(e.project) {
		if r.PRNumber > 0 {
			byPR[r.PRNumber] = r
		}
		if r.CommitSHA == sha("d") {
			invalid = r
		}
	}
	if r := byPR[7]; !r.IsFork || r.Trusted || r.Status != domain.RunAwaitingApproval || r.Ref != "refs/pull/7/head" {
		t.Fatalf("fork PR run = %+v", r)
	}
	if r := byPR[8]; !r.IsFork || r.Trusted {
		t.Fatalf("deleted-fork PR run = %+v", r)
	}
	if r := byPR[9]; r.IsFork || !r.Trusted || r.Status != domain.RunQueued {
		t.Fatalf("same-repo PR run = %+v", r)
	}
	if invalid.Status != domain.RunFailed || !strings.Contains(invalid.Error, "invalid pipeline") {
		t.Fatalf("invalid pipeline run = %+v", invalid)
	}

	// Uninstalling disables the link: later events do nothing.
	e.deliver("installation", map[string]any{"action": "deleted", "installation": map[string]any{"id": 11}})
	before := len(e.runsOf(e.project))
	e.deliver("push", push(1001, 11, "refs/heads/main", sha("b")))
	if n := len(e.runsOf(e.project)); n != before {
		t.Fatalf("push after uninstall created a run (%d -> %d)", before, n)
	}
}

func TestCommitStatuses_LatestWins(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.gh.SetFile("1001@"+sha("a"), goodPipeline)
	e.deliver("push", push(1001, 11, "refs/heads/main", sha("a")))
	r := e.runsOf(e.project)[0]
	// Cancel so there are two statuses queued (pending, then canceled).
	if _, err := e.runs.CancelRun(authz.WithPrincipal(t.Context(), e.dev), e.org.Slug, e.project.Slug, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DeliverStatuses(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The outbox is global; other tests' statuses may be delivered too.
	var mine []map[string]string
	for _, st := range e.gh.Statuses() {
		if st["context"] == "kiln/"+e.project.Slug {
			mine = append(mine, st)
		}
	}
	if len(mine) != 1 || mine[0]["state"] != "error" || mine[0]["sha"] != sha("a") ||
		!strings.Contains(mine[0]["target_url"], "/runs/"+r.ID) {
		t.Fatalf("statuses = %+v", mine)
	}
}

func TestCheckoutAndManualRuns(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := t.Context()
	e.gh.SetFile("1001@"+sha("c"), goodPipeline)
	dev := authz.WithPrincipal(ctx, e.dev)
	r1, err := e.svc.CreateManualRun(dev, e.org.Slug, e.project.Slug, "main", "manual-1")
	if err != nil || r1.CommitSHA != sha("c") || r1.Event != domain.EventManual || !r1.Trusted {
		t.Fatalf("manual run = %+v %v", r1, err)
	}
	r2, err := e.svc.CreateManualRun(dev, e.org.Slug, e.project.Slug, "main", "manual-1")
	if err != nil || r2.ID != r1.ID {
		t.Fatalf("idempotent replay = %+v %v", r2, err)
	}
	if _, err := e.svc.CreateManualRun(authz.WithPrincipal(ctx, e.viewer), e.org.Slug, e.project.Slug, "main", ""); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("viewer manual run = %v", err)
	}
	if _, err := e.svc.CreateManualRun(dev, e.org.Slug, e.project.Slug, "no-such-branch", ""); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("unknown branch = %v", err)
	}
	if _, err := e.svc.CreateManualRun(dev, e.org.Slug, e.project.Slug, "../main", ""); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad branch = %v", err)
	}
	if _, err := e.svc.CreateManualRun(dev, e.org.Slug, e.project2.Slug, "main", ""); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("unlinked project = %v", err)
	}

	co, err := e.svc.Checkout(ctx, r1)
	if err != nil || co.RepositoryURL != "https://github.com/acme/private.git" {
		t.Fatalf("checkout = %+v %v", co, err)
	}
	dec, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(co.AuthorizationHeader, "Basic "))
	if string(dec) != "x-access-token:ghs_fake_11" {
		t.Fatalf("private checkout credential = %q", dec)
	}
	// Public repositories get no credential at all.
	if _, err := e.svc.LinkRepository(authz.WithPrincipal(ctx, e.admin), e.org.Slug, e.project2.Slug, 11, "acme/public"); err != nil {
		t.Fatal(err)
	}
	co, err = e.svc.Checkout(ctx, domain.Run{OrgID: e.org.ID, ProjectID: e.project2.ID})
	if err != nil || co.AuthorizationHeader != "" || co.RepositoryURL != "https://github.com/acme/public.git" {
		t.Fatalf("public checkout = %+v %v", co, err)
	}
}
