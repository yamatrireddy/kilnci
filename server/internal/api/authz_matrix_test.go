// SPDX-License-Identifier: Apache-2.0

//go:build integration

package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/engine/spec"
	"github.com/yamatrireddy/kilnci/server/internal/service/runners"
	"github.com/yamatrireddy/kilnci/server/internal/service/runs"

	"github.com/yamatrireddy/kilnci/server/internal/store/storetest"
)

// fixture is a populated org with one member per role, a foreign-org user,
// and a read-only API token belonging to the owner.
type fixture struct {
	env       *env
	org       string // slug of org A
	project   string
	orgID     string
	projectID string
	runID     string
	actors    map[string]*client
}

const (
	owner, admin, developer, viewer, outsider, anon, token = "owner", "admin", "developer", "viewer", "outsider", "anonymous", "api-token"
)

var actorOrder = []string{owner, admin, developer, viewer, outsider, anon, token}

func newFixture(t *testing.T) *fixture {
	e := newEnv(t)
	root := e.loginWeb(e.bootstrap) // instance admin; becomes owner of both orgs

	orgA, orgB := storetest.Unique("a"), storetest.Unique("b")
	for _, slug := range []string{orgA, orgB} {
		e.mustStatus(e.do(root, http.MethodPost, "/api/v1/orgs", fmt.Sprintf(`{"slug":%q,"name":"Org"}`, slug)), http.StatusCreated)
	}
	proj := "web"
	e.mustStatus(e.do(root, http.MethodPost, "/api/v1/orgs/"+orgA+"/projects", `{"slug":"web","name":"Web"}`), http.StatusCreated)

	f := &fixture{env: e, org: orgA, project: proj, actors: map[string]*client{owner: root, anon: anonymous}}
	invite := func(org, role string) *client {
		email := storetest.Unique(role) + "@kiln.test"
		e.mustStatus(e.do(root, http.MethodPost, "/api/v1/orgs/"+org+"/members",
			fmt.Sprintf(`{"email":%q,"role":%q}`, email, role)), http.StatusCreated)
		return e.loginWeb(email) // claims the pending invite
	}
	f.actors[admin] = invite(orgA, "admin")
	f.actors[developer] = invite(orgA, "developer")
	f.actors[viewer] = invite(orgA, "viewer")
	f.actors[outsider] = invite(orgB, "owner")

	rec := e.do(root, http.MethodPost, "/api/v1/tokens",
		`{"name":"ci","scopes":["session:read","orgs:list","orgs:read","members:list","projects:list","projects:read","audit:read","runs:list","runs:read","pipelines:lint"],"expiresInDays":30}`)
	e.mustStatus(rec, http.StatusCreated)
	f.actors[token] = &client{bearer: decode[struct {
		Token string `json:"token"`
	}](t, rec).Token}

	type withID struct {
		ID string `json:"id"`
	}
	f.orgID = decode[withID](t, e.do(root, http.MethodGet, "/api/v1/orgs/"+orgA, "")).ID
	f.projectID = decode[withID](t, e.do(root, http.MethodGet, "/api/v1/orgs/"+orgA+"/projects/"+proj, "")).ID
	return f
}

// newRun creates a run in org A's project through the service (runs are
// normally created by webhook triggers). Fork runs await approval.
func (f *fixture) newRun(fork bool) string {
	f.env.t.Helper()
	pl, err := spec.Parse([]byte(testPipeline))
	if err != nil {
		f.env.t.Fatal(err)
	}
	run, err := f.env.runs.CreateRun(f.env.t.Context(), runs.NewRun{
		OrgID: f.orgID, ProjectID: f.projectID, Event: domain.EventPullRequest, Ref: "refs/pull/7/head",
		Branch: "feature", CommitSHA: strings.Repeat("ab", 20), Title: "Add feature", PRNumber: 7,
		IsFork: fork, Trusted: !fork, ActorLogin: "octocat", Pipeline: pl,
	})
	if err != nil {
		f.env.t.Fatal(err)
	}
	return run.ID
}

// target creates a fresh developer in org A and returns their user ID, so
// destructive cases never interfere with each other.
func (f *fixture) target() string {
	e := f.env
	email := storetest.Unique("target") + "@kiln.test"
	rec := e.do(f.actors[owner], http.MethodPost, "/api/v1/orgs/"+f.org+"/members", fmt.Sprintf(`{"email":%q,"role":"developer"}`, email))
	e.mustStatus(rec, http.StatusCreated)
	return decode[struct {
		UserID string `json:"userId"`
	}](e.t, rec).UserID
}

// ownerToken creates a fresh API token for the owner and returns its ID.
func (f *fixture) ownerToken() string {
	e := f.env
	rec := e.do(f.actors[owner], http.MethodPost, "/api/v1/tokens", `{"name":"t","scopes":["orgs:list"],"expiresInDays":1}`)
	e.mustStatus(rec, http.StatusCreated)
	return decode[struct {
		APIToken struct {
			ID string `json:"id"`
		} `json:"apiToken"`
	}](e.t, rec).APIToken.ID
}

type matrixCase struct {
	method, pattern string
	// build returns the concrete path and body for one request.
	build func(f *fixture) (path, body string)
	want  map[string]int
}

func statuses(ownerS, adminS, devS, viewerS, outsiderS, anonS, tokenS int) map[string]int {
	return map[string]int{owner: ownerS, admin: adminS, developer: devS, viewer: viewerS, outsider: outsiderS, anon: anonS, token: tokenS}
}

func static(path, body string) func(*fixture) (string, string) {
	return func(*fixture) (string, string) { return path, body }
}

// TestAuthzMatrix runs every authenticated endpoint against every role, a
// user from another org (must get 404 on org resources), an anonymous caller
// (401), and a read-only API token (403 outside its scopes).
// Required by security-standards §4 and threat-model scenario S2.
func TestAuthzMatrix(t *testing.T) {
	f := newFixture(t)
	f.runID = f.newRun(false)
	org := func(suffix string) string { return "/api/v1/orgs/" + f.org + suffix }

	cases := []matrixCase{
		{"GET", "/api/v1/session", static("/api/v1/session", ""), statuses(200, 200, 200, 200, 200, 401, 200)},
		{"GET", "/api/v1/orgs", static("/api/v1/orgs", ""), statuses(200, 200, 200, 200, 200, 401, 200)},
		{"POST", "/api/v1/orgs", func(*fixture) (string, string) {
			return "/api/v1/orgs", fmt.Sprintf(`{"slug":%q,"name":"New"}`, storetest.Unique("n"))
		}, statuses(201, 403, 403, 403, 403, 401, 403)},
		{"GET", "/api/v1/orgs/{orgSlug}", func(*fixture) (string, string) { return org(""), "" },
			statuses(200, 200, 200, 200, 404, 401, 200)},
		{"GET", "/api/v1/orgs/{orgSlug}/members", func(*fixture) (string, string) { return org("/members"), "" },
			statuses(200, 200, 200, 200, 404, 401, 200)},
		{"POST", "/api/v1/orgs/{orgSlug}/members", func(*fixture) (string, string) {
			return org("/members"), fmt.Sprintf(`{"email":%q,"role":"viewer"}`, storetest.Unique("m")+"@kiln.test")
		}, statuses(201, 201, 403, 403, 404, 401, 403)},
		{"PUT", "/api/v1/orgs/{orgSlug}/members/{userId}", func(f *fixture) (string, string) {
			return org("/members/" + f.target()), `{"role":"viewer"}`
		}, statuses(200, 200, 403, 403, 404, 401, 403)},
		{"DELETE", "/api/v1/orgs/{orgSlug}/members/{userId}", func(f *fixture) (string, string) {
			return org("/members/" + f.target()), ""
		}, statuses(204, 204, 403, 403, 404, 401, 403)},
		{"GET", "/api/v1/orgs/{orgSlug}/projects", func(*fixture) (string, string) { return org("/projects"), "" },
			statuses(200, 200, 200, 200, 404, 401, 200)},
		{"POST", "/api/v1/orgs/{orgSlug}/projects", func(*fixture) (string, string) {
			return org("/projects"), fmt.Sprintf(`{"slug":%q,"name":"P"}`, storetest.Unique("p"))
		}, statuses(201, 201, 403, 403, 404, 401, 403)},
		{"GET", "/api/v1/orgs/{orgSlug}/projects/{projectSlug}", func(f *fixture) (string, string) { return org("/projects/" + f.project), "" },
			statuses(200, 200, 200, 200, 404, 401, 200)},
		{"GET", "/api/v1/orgs/{orgSlug}/audit-events", func(*fixture) (string, string) { return org("/audit-events"), "" },
			statuses(200, 200, 403, 403, 404, 401, 200)},
		{"GET", "/api/v1/tokens", static("/api/v1/tokens", ""), statuses(200, 200, 200, 200, 200, 401, 403)},
		{"POST", "/api/v1/tokens", static("/api/v1/tokens", `{"name":"x","scopes":["orgs:list"],"expiresInDays":7}`),
			statuses(201, 201, 201, 201, 201, 401, 403)},
		{"GET", "/api/v1/orgs/{orgSlug}/projects/{projectSlug}/runs", func(f *fixture) (string, string) {
			return org("/projects/" + f.project + "/runs"), ""
		}, statuses(200, 200, 200, 200, 404, 401, 200)},
		{"GET", "/api/v1/orgs/{orgSlug}/projects/{projectSlug}/runs/{runId}", func(f *fixture) (string, string) {
			return org("/projects/" + f.project + "/runs/" + f.runID), ""
		}, statuses(200, 200, 200, 200, 404, 401, 200)},
		{"POST", "/api/v1/orgs/{orgSlug}/projects/{projectSlug}/runs/{runId}/cancel", func(f *fixture) (string, string) {
			return org("/projects/" + f.project + "/runs/" + f.newRun(false) + "/cancel"), ""
		}, statuses(200, 200, 200, 403, 404, 401, 403)},
		{"POST", "/api/v1/orgs/{orgSlug}/projects/{projectSlug}/runs/{runId}/approve", func(f *fixture) (string, string) {
			return org("/projects/" + f.project + "/runs/" + f.newRun(true) + "/approve"), ""
		}, statuses(200, 200, 200, 403, 404, 401, 403)},
		{"POST", "/api/v1/pipelines/lint", static("/api/v1/pipelines/lint", `{"pipeline":"version: 1"}`),
			statuses(200, 200, 200, 200, 200, 401, 200)},
		{"GET", "/api/v1/orgs/{orgSlug}/runners", func(*fixture) (string, string) { return org("/runners"), "" },
			statuses(200, 200, 403, 403, 404, 401, 403)},
		{"DELETE", "/api/v1/orgs/{orgSlug}/runners/{runnerId}", func(f *fixture) (string, string) {
			return org("/runners/" + f.newRunner()), ""
		}, statuses(204, 204, 403, 403, 404, 401, 403)},
		{"POST", "/api/v1/orgs/{orgSlug}/runner-registration-tokens", func(*fixture) (string, string) {
			return org("/runner-registration-tokens"), `{"labels":[],"trusted":true,"expiresInMinutes":5}`
		}, statuses(201, 201, 403, 403, 404, 401, 403)},
		// Everyone but the owner targets someone else's token: not found.
		{"DELETE", "/api/v1/tokens/{tokenId}", func(f *fixture) (string, string) { return "/api/v1/tokens/" + f.ownerToken(), "" },
			statuses(204, 404, 404, 404, 404, 401, 403)},
	}

	// Routes intentionally outside the matrix, each covered by a dedicated test.
	exempt := map[string]string{
		"GET /healthz":              "public",
		"GET /readyz":               "public",
		"GET /api/v1/auth/login":    "TestWebLogin_*",
		"GET /api/v1/auth/callback": "TestWebLogin_*",
		"POST /api/v1/auth/token":   "TestDesktopFlow",
		"DELETE /api/v1/session":    "TestLogout_RevokesSession",
	}
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.method+" "+c.pattern] = true
	}
	var missing []string
	for _, r := range f.env.rt.Routes() {
		k := r.Method + " " + r.Pattern
		if !covered[k] && exempt[k] == "" {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("routes missing from the authz matrix: %v", missing)
	}

	for _, c := range cases {
		for _, actor := range actorOrder {
			t.Run(c.method+" "+c.pattern+"/"+actor, func(t *testing.T) {
				path, body := c.build(f)
				rec := f.env.do(f.actors[actor], c.method, path, body)
				if rec.Code != c.want[actor] {
					t.Fatalf("%s %s as %s = %d, want %d; body=%s", c.method, path, actor, rec.Code, c.want[actor], rec.Body)
				}
			})
		}
	}

	// Every mutation above was audited and the org's chain is intact.
	orgRec := f.env.do(f.actors[owner], http.MethodGet, org(""), "")
	orgID := decode[struct {
		ID string `json:"id"`
	}](t, orgRec).ID
	if err := f.env.recorder.VerifyChain(t.Context(), orgID); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
}

// newRunner registers a runner in org A through the real token + CSR flow.
func (f *fixture) newRunner() string {
	e := f.env
	e.t.Helper()
	rec := e.do(f.actors[owner], http.MethodPost, "/api/v1/orgs/"+f.org+"/runner-registration-tokens",
		`{"labels":["linux"],"trusted":false,"expiresInMinutes":10}`)
	e.mustStatus(rec, http.StatusCreated)
	tok := decode[struct {
		Token string `json:"token"`
	}](e.t, rec).Token
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		e.t.Fatal(err)
	}
	reg, err := e.runners.Register(e.t.Context(), runners.RegisterRequest{Token: tok, CSRDER: csr, Name: "r1"})
	if err != nil {
		e.t.Fatal(err)
	}
	return reg.Runner.ID
}

// testPipeline has two jobs, the second needing the first.
const testPipeline = `version: 1
jobs:
  a:
    image: alpine
    steps: [{run: x}]
  b:
    image: alpine
    needs: [a]
    steps: [{run: y}]
`
