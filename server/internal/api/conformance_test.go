// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/yamatrireddy/kilnci/server/internal/auth"
	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/service/orgs"
	"github.com/yamatrireddy/kilnci/server/internal/service/runners"
	"github.com/yamatrireddy/kilnci/server/internal/service/runs"
)

// Stubs satisfy the service interfaces so every route registers.
type stubAuth struct{}

func (stubAuth) StartLogin(context.Context, auth.StartLoginRequest) (auth.StartLoginResult, error) {
	return auth.StartLoginResult{}, nil
}
func (stubAuth) CompleteLogin(context.Context, auth.CompleteLoginRequest) (auth.CompleteLoginResult, error) {
	return auth.CompleteLoginResult{}, nil
}
func (stubAuth) ExchangeToken(context.Context, auth.TokenRequest) (auth.TokenPair, error) {
	return auth.TokenPair{}, nil
}
func (stubAuth) Session(context.Context) (auth.SessionInfo, error) { return auth.SessionInfo{}, nil }
func (stubAuth) Logout(context.Context) error                      { return nil }
func (stubAuth) CreateAPIToken(context.Context, string, []string, int) (string, domain.APIToken, error) {
	return "", domain.APIToken{}, nil
}
func (stubAuth) ListAPITokens(context.Context) ([]domain.APIToken, error) { return nil, nil }
func (stubAuth) RevokeAPIToken(context.Context, string) error             { return nil }

type stubOrgs struct{ orgs.Service }

func (stubOrgs) ListOrgs(context.Context, orgs.PageRequest) (orgs.Page[domain.OrgWithRole], error) {
	return orgs.Page[domain.OrgWithRole]{}, nil
}

type stubRuns struct{ runs.Service }

type stubRunners struct{ runners.Service }

// TestRoutesMatchSpec enforces CLAUDE.md invariant 1 and the deny-by-default
// rule: every OpenAPI operation is routed with exactly its x-kiln-permission,
// and no route exists that the spec does not declare.
func TestRoutesMatchSpec(t *testing.T) {
	d := testDeps(t, nil)
	d.Auth, d.Orgs, d.Runs, d.Runners = stubAuth{}, &stubOrgs{}, &stubRuns{}, &stubRunners{}
	_, rt, err := NewHandler(d)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := loadSpec()
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]authz.Action{}
	for path, item := range spec.Paths.Map() {
		for method, op := range item.Operations() {
			perm, _ := op.Extensions["x-kiln-permission"].(string)
			if perm == "" {
				t.Errorf("%s %s: missing x-kiln-permission", method, path)
			}
			if !authz.Known(authz.Action(perm)) {
				t.Errorf("%s %s: x-kiln-permission %q is not an authz action", method, path, perm)
			}
			isOpen := op.Security != nil && len(*op.Security) == 0
			if isOpen != (perm == string(authz.PermissionPublic) || perm == string(authz.PermissionPreAuth)) {
				t.Errorf("%s %s: `security: []` must be used exactly for public/preauth operations", method, path)
			}
			want[strings.ToUpper(method)+" "+path] = authz.Action(perm)
		}
	}
	got := map[string]authz.Action{}
	for _, r := range rt.Routes() {
		got[r.Method+" "+r.Pattern] = r.Permission
	}

	keys := func(m map[string]authz.Action) []string {
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return ks
	}
	for _, k := range keys(want) {
		if g, ok := got[k]; !ok {
			t.Errorf("spec operation %s is not routed", k)
		} else if g != want[k] {
			t.Errorf("%s: routed with %q, spec says %q", k, g, want[k])
		}
	}
	for _, k := range keys(got) {
		if _, ok := want[k]; !ok {
			t.Errorf("route %s is not in the OpenAPI spec", k)
		}
	}
}
