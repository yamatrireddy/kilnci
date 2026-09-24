// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
)

type fakeMembers map[string]domain.Role // key: orgID+"/"+userID

func (f fakeMembers) GetMembershipRole(_ context.Context, orgID, userID string) (domain.Role, error) {
	if orgID == "broken" {
		return "", errors.New("db down")
	}
	r, ok := f[orgID+"/"+userID]
	if !ok {
		return "", domain.ErrNotFound
	}
	return r, nil
}

func TestCheck_RoleMatrix(t *testing.T) {
	members := fakeMembers{
		"org1/owner": domain.RoleOwner, "org1/admin": domain.RoleAdmin,
		"org1/dev": domain.RoleDeveloper, "org1/viewer": domain.RoleViewer,
		"org2/outsider": domain.RoleOwner,
	}
	az := NewAuthorizer(members)
	user := func(id string) *Principal { return &Principal{Kind: KindUser, UserID: id} }

	// want[action][user] = expected error (nil = allowed)
	type row struct {
		action Action
		want   map[string]error
	}
	rows := []row{
		{ActionOrgsRead, map[string]error{"owner": nil, "admin": nil, "dev": nil, "viewer": nil, "outsider": domain.ErrNotFound}},
		{ActionProjectsList, map[string]error{"owner": nil, "admin": nil, "dev": nil, "viewer": nil, "outsider": domain.ErrNotFound}},
		{ActionProjectsCreate, map[string]error{"owner": nil, "admin": nil, "dev": domain.ErrForbidden, "viewer": domain.ErrForbidden, "outsider": domain.ErrNotFound}},
		{ActionMembersManage, map[string]error{"owner": nil, "admin": nil, "dev": domain.ErrForbidden, "viewer": domain.ErrForbidden, "outsider": domain.ErrNotFound}},
		{ActionAuditRead, map[string]error{"owner": nil, "admin": nil, "dev": domain.ErrForbidden, "viewer": domain.ErrForbidden, "outsider": domain.ErrNotFound}},
	}
	for _, r := range rows {
		for u, want := range r.want {
			err := az.Check(context.Background(), user(u), r.action, Resource{OrgID: "org1"})
			if !errors.Is(err, want) || (want == nil && err != nil) {
				t.Errorf("%s by %s: err = %v, want %v", r.action, u, err, want)
			}
		}
	}
}

func TestCheck_DenyByDefault(t *testing.T) {
	az := NewAuthorizer(fakeMembers{"org1/u": domain.RoleOwner})
	owner := &Principal{Kind: KindUser, UserID: "u"}
	tests := []struct {
		name string
		p    *Principal
		a    Action
		res  Resource
		want error
	}{
		{"nil principal", nil, ActionOrgsRead, Resource{OrgID: "org1"}, domain.ErrUnauthenticated},
		{"principal without user", &Principal{Kind: KindUser}, ActionOrgsRead, Resource{OrgID: "org1"}, domain.ErrUnauthenticated},
		{"undeclared action", owner, "orgs:delete", Resource{OrgID: "org1"}, domain.ErrForbidden},
		{"pseudo permission is not an action", owner, PermissionPublic, Resource{OrgID: "org1"}, domain.ErrForbidden},
		{"runner principal", &Principal{Kind: KindRunner, UserID: "u"}, ActionOrgsRead, Resource{OrgID: "org1"}, domain.ErrForbidden},
		{"system principal", &Principal{Kind: KindSystem, UserID: "u"}, ActionOrgsRead, Resource{OrgID: "org1"}, domain.ErrForbidden},
		{"org action without org", owner, ActionOrgsRead, Resource{}, domain.ErrForbidden},
		{"unknown role in store", &Principal{Kind: KindUser, UserID: "weird"}, ActionOrgsRead, Resource{OrgID: "org1"}, domain.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := az.Check(context.Background(), tt.p, tt.a, tt.res); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestCheck_StoreErrorIsNotAuthorization(t *testing.T) {
	az := NewAuthorizer(fakeMembers{})
	err := az.Check(context.Background(), &Principal{Kind: KindUser, UserID: "u"}, ActionOrgsRead, Resource{OrgID: "broken"})
	if err == nil || errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("store failure must surface as an internal error, got %v", err)
	}
}

func TestCheck_APITokenScopes(t *testing.T) {
	az := NewAuthorizer(fakeMembers{"org1/u": domain.RoleOwner})
	tok := &Principal{Kind: KindAPIToken, UserID: "u", Scopes: []Action{ActionProjectsList}}
	if err := az.Check(context.Background(), tok, ActionProjectsList, Resource{OrgID: "org1"}); err != nil {
		t.Fatalf("in-scope action denied: %v", err)
	}
	if err := az.Check(context.Background(), tok, ActionProjectsCreate, Resource{OrgID: "org1"}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("out-of-scope action: %v", err)
	}
	// A token's role is still bounded by its owner's membership.
	stranger := &Principal{Kind: KindAPIToken, UserID: "nobody", Scopes: []Action{ActionProjectsList}}
	if err := az.Check(context.Background(), stranger, ActionProjectsList, Resource{OrgID: "org1"}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("token for non-member: %v", err)
	}
	// An empty (non-nil) scope list allows nothing.
	none := &Principal{Kind: KindAPIToken, UserID: "u", Scopes: []Action{}}
	if err := az.Check(context.Background(), none, ActionProjectsList, Resource{OrgID: "org1"}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("empty scopes: %v", err)
	}
}

func TestCheck_InstanceAdminAndSelfOnly(t *testing.T) {
	az := NewAuthorizer(fakeMembers{})
	admin := &Principal{Kind: KindUser, UserID: "a", InstanceAdmin: true}
	plain := &Principal{Kind: KindUser, UserID: "b"}
	adminToken := &Principal{Kind: KindAPIToken, UserID: "a", InstanceAdmin: true}

	if err := az.Check(context.Background(), admin, ActionOrgsCreate, Resource{}); err != nil {
		t.Fatalf("instance admin create org: %v", err)
	}
	if err := az.Check(context.Background(), plain, ActionOrgsCreate, Resource{}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("plain user create org: %v", err)
	}
	if err := az.Check(context.Background(), adminToken, ActionOrgsCreate, Resource{}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("API token must not create orgs even for an admin: %v", err)
	}
	if err := az.Check(context.Background(), plain, ActionTokensDelete, Resource{OwnerUserID: "b"}); err != nil {
		t.Fatalf("own token: %v", err)
	}
	if err := az.Check(context.Background(), plain, ActionTokensDelete, Resource{OwnerUserID: "a"}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("someone else's token must be not-found: %v", err)
	}
}

func TestPolicy_EveryActionIsKnownAndRoleAllowsIsConsistent(t *testing.T) {
	for _, a := range Actions() {
		if !Known(a) {
			t.Errorf("%s not Known", a)
		}
	}
	if !Known(PermissionPublic) || !Known(PermissionPreAuth) || Known("nope:nope") {
		t.Fatal("Known() wrong for pseudo/unknown")
	}
	if !RoleAllows(domain.RoleAdmin, ActionProjectsCreate) || RoleAllows(domain.RoleDeveloper, ActionProjectsCreate) {
		t.Fatal("RoleAllows disagrees with policy")
	}
	if RoleAllows(domain.RoleOwner, ActionOrgsCreate) || RoleAllows(domain.RoleOwner, "nope") {
		t.Fatal("RoleAllows must be false for instance-admin, self-only, and unknown actions")
	}
}

func TestPrincipalContext(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("empty context has principal")
	}
	p := &Principal{UserID: "u"}
	got, ok := FromContext(WithPrincipal(context.Background(), p))
	if !ok || got != p {
		t.Fatal("principal round trip failed")
	}
	if (*Principal)(nil).AllowsAction(ActionOrgsRead) {
		t.Fatal("nil principal allows actions")
	}
}
