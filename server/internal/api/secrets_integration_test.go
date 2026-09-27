// SPDX-License-Identifier: Apache-2.0

//go:build integration

package api_test

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/yamatrireddy/kilnci/server/internal/api"
	"github.com/yamatrireddy/kilnci/server/internal/api/gen"
	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/secrets"
	secretsvc "github.com/yamatrireddy/kilnci/server/internal/service/secrets"
)

// Test-only value; not a real credential.
const testSecretValue = "fake-deploy-token-0123456789"

func TestSecrets_WriteOnlyLifecycle(t *testing.T) {
	f := newFixture(t)
	e, root := f.env, f.actors[owner]
	other := f.newProject()
	path := "/api/v1/orgs/" + f.org + "/secrets/DEPLOY_TOKEN"

	rec := e.do(root, http.MethodPut, path, fmt.Sprintf(`{"value":%q,"branches":["main","release/*"],"projectSlugs":[%q,%q]}`, testSecretValue, other, f.project))
	e.mustStatus(rec, http.StatusCreated)
	if strings.Contains(rec.Body.String(), testSecretValue) {
		t.Fatal("create response contains the value")
	}
	if rec.Header().Get("ETag") != `"1"` || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: ETag=%q Cache-Control=%q", rec.Header().Get("ETag"), rec.Header().Get("Cache-Control"))
	}
	w := decode[gen.SecretWritten](t, rec)
	if w.Secret.Scope != "org" || !w.Secret.Masked || w.Secret.ValueVersion != 1 || len(w.Warnings) != 0 ||
		w.Secret.ProjectSlugs == nil || len(*w.Secret.ProjectSlugs) != 2 || *w.Secret.AllProjects {
		t.Fatalf("written = %+v", w)
	}

	// The stored row is ciphertext bound to its row, and opens to the value.
	sealed, err := e.st.GetSealedSecret(t.Context(), f.orgID, "", "DEPLOY_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.Ciphertext, []byte(testSecretValue)) {
		t.Fatal("database holds the plaintext")
	}
	dk, err := e.st.GetDataKey(t.Context(), f.orgID, sealed.DEKVersion)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(dk.Wrapped, []byte(testSecretValue)) || !strings.HasPrefix(dk.KeyID, "local:") {
		t.Fatalf("data key row: key ID %q", dk.KeyID)
	}
	dek, err := e.keyring.DataKey(t.Context(), f.orgID, dk.Version, secrets.WrappedKey{KeyID: dk.KeyID, Ciphertext: dk.Wrapped})
	if err != nil {
		t.Fatal(err)
	}
	id := sealed.Secret.ID
	aad := secrets.AAD{OrgID: f.orgID, ScopeKind: secrets.ScopeOrg, ScopeID: f.orgID, Name: "DEPLOY_TOKEN", SecretID: id, DEKVersion: dk.Version, ValueVersion: 1}
	if pt, err := secrets.Open(dek, sealed.Ciphertext, aad); err != nil || string(pt) != testSecretValue {
		t.Fatalf("open: %v", err)
	}
	// Moved to the project scope, another row, or rolled forward, it does
	// not open (T-62).
	for _, a := range []secrets.AAD{
		{OrgID: f.orgID, ScopeKind: secrets.ScopeProject, ScopeID: f.projectID, Name: "DEPLOY_TOKEN", SecretID: id, DEKVersion: dk.Version, ValueVersion: 1},
		{OrgID: f.orgID, ScopeKind: secrets.ScopeOrg, ScopeID: f.orgID, Name: "DEPLOY_TOKEN", SecretID: id + "X", DEKVersion: dk.Version, ValueVersion: 1},
		{OrgID: f.orgID, ScopeKind: secrets.ScopeOrg, ScopeID: f.orgID, Name: "DEPLOY_TOKEN", SecretID: id, DEKVersion: dk.Version, ValueVersion: 2},
	} {
		if _, err := secrets.Open(dek, sealed.Ciphertext, a); err == nil {
			t.Fatalf("opened under %+v", a)
		}
	}

	// Replace: If-Match is required, the version increases, and a stale
	// If-Match is refused.
	e.mustStatus(e.do(root, http.MethodPut, path, `{"value":"new-value-abcdef","allProjects":true}`), http.StatusPreconditionRequired)
	rec = e.do(root, http.MethodPut, path, `{"value":"new-value-abcdef","allProjects":true}`, withHeader("If-Match", `"1"`))
	e.mustStatus(rec, http.StatusOK)
	if rec.Header().Get("ETag") != `"2"` {
		t.Fatalf("ETag = %q", rec.Header().Get("ETag"))
	}
	w = decode[gen.SecretWritten](t, rec)
	if !*w.Secret.AllProjects || len(*w.Secret.ProjectSlugs) != 0 || len(w.Secret.Branches) != 0 {
		t.Fatalf("replace did not replace restrictions: %+v", w.Secret)
	}
	e.mustStatus(e.do(root, http.MethodPut, path, `{"value":"another-value"}`, withHeader("If-Match", `"1"`)), http.StatusPreconditionFailed)
	for _, bad := range []string{"1", "*", `W/"2"`, `"2", "3"`} {
		e.mustStatus(e.do(root, http.MethodPut, path, `{"value":"another-value"}`, withHeader("If-Match", bad)), http.StatusUnprocessableEntity)
	}
	e.mustStatus(e.do(root, http.MethodPut, "/api/v1/orgs/"+f.org+"/secrets/MISSING", `{"value":"another-value"}`, withHeader("If-Match", `"1"`)), http.StatusPreconditionFailed)

	// Listing shows metadata only, to developers.
	rec = e.do(f.actors[developer], http.MethodGet, "/api/v1/orgs/"+f.org+"/secrets", "")
	e.mustStatus(rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), "new-value-abcdef") || strings.Contains(rec.Body.String(), testSecretValue) {
		t.Fatal("list contains a value")
	}
	list := decode[gen.SecretList](t, rec)
	if len(list.Items) != 1 || list.Items[0].Name != "DEPLOY_TOKEN" || list.Items[0].ValueVersion != 2 {
		t.Fatalf("list = %+v", list)
	}

	// A project secret of the same name is separate.
	projPath := "/api/v1/orgs/" + f.org + "/projects/" + f.project + "/secrets/DEPLOY_TOKEN"
	e.mustStatus(e.do(root, http.MethodPut, projPath, `{"value":"project-value"}`), http.StatusCreated)
	rec = e.do(root, http.MethodGet, "/api/v1/orgs/"+f.org+"/projects/"+f.project+"/secrets", "")
	if l := decode[gen.SecretList](t, rec); len(l.Items) != 1 || l.Items[0].Scope != "project" || l.Items[0].ProjectSlugs != nil {
		t.Fatalf("project list = %s", rec.Body)
	}

	// Delete, then it is gone.
	e.mustStatus(e.do(root, http.MethodDelete, path, ""), http.StatusNoContent)
	e.mustStatus(e.do(root, http.MethodDelete, path, ""), http.StatusNotFound)

	// Every write was audited without the value, and the chain holds.
	events, err := e.st.ListAuditChain(t.Context(), f.orgID)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, ev := range events {
		if strings.HasPrefix(ev.Action, "secrets:") {
			actions = append(actions, ev.Action)
		}
		if strings.Contains(fmt.Sprint(ev.Details), testSecretValue) || strings.Contains(fmt.Sprint(ev.Details), "new-value") {
			t.Fatalf("audit event %s contains a value", ev.Action)
		}
	}
	if got := strings.Join(actions, ","); got != "secrets:create,secrets:update,secrets:create,secrets:delete" {
		t.Fatalf("audited %s", got)
	}
	if err := e.recorder.VerifyChain(t.Context(), f.orgID); err != nil {
		t.Fatal(err)
	}
}

func TestSecrets_ShortValueWarns(t *testing.T) {
	f := newFixture(t)
	rec := f.env.do(f.actors[owner], http.MethodPut, "/api/v1/orgs/"+f.org+"/secrets/PIN", `{"value":"123"}`)
	f.env.mustStatus(rec, http.StatusCreated)
	w := decode[gen.SecretWritten](t, rec)
	if w.Secret.Masked || len(w.Warnings) != 1 || w.Warnings[0] != secretsvc.WarningNotMasked {
		t.Fatalf("written = %+v", w)
	}
}

func TestSecrets_Validation(t *testing.T) {
	f := newFixture(t)
	e, root := f.env, f.actors[owner]
	org := "/api/v1/orgs/" + f.org
	v := `{"value":"` + testSecretValue + `"`
	for name, tc := range map[string]struct{ path, body, field string }{
		"reserved name":       {org + "/secrets/PATH", v + `}`, "secretName"},
		"reserved lowercase":  {org + "/secrets/path", v + `}`, "secretName"},
		"loader prefix":       {org + "/secrets/LD_PRELOAD", v + `}`, "secretName"},
		"loader mixed case":   {org + "/secrets/Ld_Preload", v + `}`, "secretName"},
		"kiln prefix":         {org + "/secrets/KILN_TOKEN", v + `}`, "secretName"},
		"bad name":            {org + "/secrets/1TOKEN", v + `}`, "secretName"},
		"empty value":         {org + "/secrets/TOKEN", `{"value":""}`, "body"},
		"no value":            {org + "/secrets/TOKEN", `{"branches":["main"]}`, "body"},
		"NUL":                 {org + "/secrets/TOKEN", `{"value":"abc\u0000def"}`, "value"},
		"bad branch":          {org + "/secrets/TOKEN", v + `,"branches":["ma*n"]}`, "branches"},
		"unknown project":     {org + "/secrets/TOKEN", v + `,"projectSlugs":["nope"]}`, "projectSlugs"},
		"all and list":        {org + "/secrets/TOKEN", v + `,"allProjects":true,"projectSlugs":["` + f.project + `"]}`, "projectSlugs"},
		"projects on project": {org + "/projects/" + f.project + "/secrets/TOKEN", v + `,"allProjects":true}`, "projectSlugs"},
		"unknown field":       {org + "/secrets/TOKEN", v + `,"echo":true}`, "body"},
		"too large":           {org + "/secrets/TOKEN", `{"value":"` + strings.Repeat("x", 64<<10+1) + `"}`, "body"},
	} {
		rec := e.do(root, http.MethodPut, tc.path, tc.body)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, body=%s", name, rec.Code, rec.Body)
			continue
		}
		body := rec.Body.String()
		if strings.Contains(body, testSecretValue) {
			t.Errorf("%s: problem echoes the value", name)
		}
		if p := decode[gen.Problem](t, rec); p.Errors == nil || len(*p.Errors) == 0 || (*p.Errors)[0].Field != tc.field {
			t.Errorf("%s: problem = %s, want field %s", name, body, tc.field)
		}
	}
	// Other orgs' projects are unknown too: not in an allow-list, and not as
	// a project-secret path.
	outsiderOrg := decode[gen.OrgList](t, e.do(f.actors[outsider], http.MethodGet, "/api/v1/orgs", "")).Items[0].Slug
	e.mustStatus(e.do(f.actors[outsider], http.MethodPost, "/api/v1/orgs/"+outsiderOrg+"/projects", `{"slug":"theirs","name":"T"}`), http.StatusCreated)
	e.mustStatus(e.do(root, http.MethodPut, org+"/secrets/TOKEN", v+`,"projectSlugs":["theirs"]}`), http.StatusUnprocessableEntity)
	e.mustStatus(e.do(root, http.MethodPut, org+"/projects/theirs/secrets/TOKEN", v+`}`), http.StatusNotFound)
	e.mustStatus(e.do(root, http.MethodGet, org+"/projects/theirs/secrets", ""), http.StatusNotFound)
}

// Without a key provider, secrets cannot be written but can be listed and
// deleted.
func TestSecrets_NotConfigured(t *testing.T) {
	f := newFixture(t)
	e := f.env
	svc := secretsvc.NewService(e.st, authz.NewAuthorizer(e.st), e.recorder, nil, ids.NewGenerator(nil), nil)
	h, _, err := api.NewHandler(api.Deps{Log: logging.Discard(), IDs: ids.NewGenerator(nil), Authn: e.authn, Secrets: svc, Options: api.Options{
		MaxBodyBytes: 1 << 20, RateLimits: api.RateLimits{PerIP: 1e6, AuthPerIP: 1e6, AuthFailuresPerIP: 1e6, PerPrincipal: 1e6},
	}})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	rec := e.do(f.actors[owner], http.MethodPut, "/api/v1/orgs/"+f.org+"/secrets/TOKEN", `{"value":"`+testSecretValue+`"}`)
	e.mustStatus(rec, http.StatusServiceUnavailable)
	if !strings.Contains(rec.Body.String(), "urn:kiln:problem:unavailable") {
		t.Fatalf("body = %s", rec.Body)
	}
	e.mustStatus(e.do(f.actors[owner], http.MethodGet, "/api/v1/orgs/"+f.org+"/secrets", ""), http.StatusOK)
	// Authorization still comes first: an outsider sees 404, not 503.
	e.mustStatus(e.do(f.actors[outsider], http.MethodPut, "/api/v1/orgs/"+f.org+"/secrets/TOKEN", `{"value":"`+testSecretValue+`"}`), http.StatusNotFound)
}

// A deleted and recreated secret restarts at value version 1, so an old
// ciphertext must not open in the new row even at the same version (T-62).
func TestSecrets_RecreatedSecretRejectsOldCiphertext(t *testing.T) {
	f := newFixture(t)
	e, root := f.env, f.actors[owner]
	path := "/api/v1/orgs/" + f.org + "/secrets/DEPLOY_TOKEN"
	e.mustStatus(e.do(root, http.MethodPut, path, `{"value":"first-value-1"}`), http.StatusCreated)
	e.mustStatus(e.do(root, http.MethodPut, path, `{"value":"first-value-2"}`, withHeader("If-Match", `"1"`)), http.StatusOK)
	old, err := e.st.GetSealedSecret(t.Context(), f.orgID, "", "DEPLOY_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	e.mustStatus(e.do(root, http.MethodDelete, path, ""), http.StatusNoContent)
	e.mustStatus(e.do(root, http.MethodPut, path, `{"value":"second-value-1"}`), http.StatusCreated)
	e.mustStatus(e.do(root, http.MethodPut, path, `{"value":"second-value-2"}`, withHeader("If-Match", `"1"`)), http.StatusOK)
	cur, err := e.st.GetSealedSecret(t.Context(), f.orgID, "", "DEPLOY_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if cur.Secret.ID == old.Secret.ID || cur.Secret.ValueVersion != old.Secret.ValueVersion || cur.DEKVersion != old.DEKVersion {
		t.Fatalf("setup: old %s v%d, new %s v%d", old.Secret.ID, old.Secret.ValueVersion, cur.Secret.ID, cur.Secret.ValueVersion)
	}
	dk, err := e.st.GetDataKey(t.Context(), f.orgID, cur.DEKVersion)
	if err != nil {
		t.Fatal(err)
	}
	dek, err := e.keyring.DataKey(t.Context(), f.orgID, dk.Version, secrets.WrappedKey{KeyID: dk.KeyID, Ciphertext: dk.Wrapped})
	if err != nil {
		t.Fatal(err)
	}
	aad := secrets.AAD{OrgID: f.orgID, ScopeKind: secrets.ScopeOrg, ScopeID: f.orgID, Name: "DEPLOY_TOKEN", SecretID: cur.Secret.ID, DEKVersion: cur.DEKVersion, ValueVersion: cur.Secret.ValueVersion}
	if pt, err := secrets.Open(dek, cur.Ciphertext, aad); err != nil || string(pt) != "second-value-2" {
		t.Fatalf("current value does not open: %v", err)
	}
	if _, err := secrets.Open(dek, old.Ciphertext, aad); err == nil {
		t.Fatal("old incarnation's ciphertext opened in the recreated row")
	}
}
