// SPDX-License-Identifier: Apache-2.0

//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/store"
	"github.com/yamatrireddy/kilnci/server/internal/store/storetest"
)

var gen = ids.NewGenerator(nil)

func mkUser(t *testing.T, s *store.Store) domain.User {
	t.Helper()
	u, err := s.CreateUser(t.Context(), domain.User{
		ID: gen.New(), Issuer: "https://idp.test", Subject: storetest.Unique("sub"),
		Email: storetest.Unique("u") + "@example.test", DisplayName: "Test User", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func mkOrg(t *testing.T, s *store.Store, owner domain.User) domain.Org {
	t.Helper()
	ctx := t.Context()
	o, err := s.CreateOrg(ctx, domain.Org{ID: gen.New(), Slug: storetest.Unique("org"), Name: "Org", CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := s.AddMembership(ctx, domain.Membership{OrgID: o.ID, UserID: owner.ID, Role: domain.RoleOwner}, time.Now()); err != nil {
		t.Fatalf("add membership: %v", err)
	}
	return o
}

func TestStore_OrgLookupIsScopedToMembers(t *testing.T) {
	s := storetest.New(t)
	ctx := t.Context()
	alice, mallory := mkUser(t, s), mkUser(t, s)
	org := mkOrg(t, s, alice)

	got, err := s.GetOrgForMember(ctx, org.Slug, alice.ID)
	if err != nil || got.ID != org.ID || got.Role != domain.RoleOwner {
		t.Fatalf("member lookup = %+v, %v", got, err)
	}
	if _, err := s.GetOrgForMember(ctx, org.Slug, mallory.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("non-member lookup err = %v, want ErrNotFound", err)
	}
	if _, err := s.GetOrgForMember(ctx, "no-such-org", alice.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing org err = %v, want ErrNotFound", err)
	}
	orgs, err := s.ListOrgsForMember(ctx, mallory.ID, "", 100)
	if err != nil || len(orgs) != 0 {
		t.Fatalf("non-member sees orgs: %v %v", orgs, err)
	}
}

func TestStore_ProjectsAreScopedByOrg(t *testing.T) {
	s := storetest.New(t)
	ctx := t.Context()
	a, b := mkOrg(t, s, mkUser(t, s)), mkOrg(t, s, mkUser(t, s))
	p, err := s.CreateProject(ctx, domain.Project{ID: gen.New(), OrgID: a.ID, Slug: "web", Name: "Web", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetProject(ctx, b.ID, p.Slug); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-org project lookup err = %v, want ErrNotFound", err)
	}
	// Same slug in another org is fine; duplicate within an org conflicts.
	if _, err := s.CreateProject(ctx, domain.Project{ID: gen.New(), OrgID: b.ID, Slug: "web", Name: "Web", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("same slug in other org: %v", err)
	}
	if _, err := s.CreateProject(ctx, domain.Project{ID: gen.New(), OrgID: a.ID, Slug: "web", Name: "Web", CreatedAt: time.Now()}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate slug err = %v, want ErrConflict", err)
	}
}

func TestStore_Pagination(t *testing.T) {
	s := storetest.New(t)
	ctx := t.Context()
	org := mkOrg(t, s, mkUser(t, s))
	for range 5 {
		if _, err := s.CreateProject(ctx, domain.Project{ID: gen.New(), OrgID: org.ID, Slug: storetest.Unique("p"), Name: "P", CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	page1, err := s.ListProjects(ctx, org.ID, "", 3)
	if err != nil || len(page1) != 3 {
		t.Fatalf("page1 = %d, %v", len(page1), err)
	}
	page2, err := s.ListProjects(ctx, org.ID, page1[2].ID, 3)
	if err != nil || len(page2) != 2 || page2[0].ID <= page1[2].ID {
		t.Fatalf("page2 = %+v, %v", page2, err)
	}
}

func TestStore_InTx_RollsBackOnError(t *testing.T) {
	s := storetest.New(t)
	ctx := t.Context()
	slug := storetest.Unique("rollback")
	owner := mkUser(t, s)
	boom := errors.New("boom")
	err := s.InTx(ctx, func(ctx context.Context) error {
		o, err := s.CreateOrg(ctx, domain.Org{ID: gen.New(), Slug: slug, Name: "X", CreatedAt: time.Now()})
		if err != nil {
			return err
		}
		if err := s.AddMembership(ctx, domain.Membership{OrgID: o.ID, UserID: owner.ID, Role: domain.RoleOwner}, time.Now()); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("InTx err = %v", err)
	}
	if _, err := s.GetOrgForMember(ctx, slug, owner.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("rolled-back org visible: %v", err)
	}
}

func TestStore_MembershipMutations(t *testing.T) {
	s := storetest.New(t)
	ctx := t.Context()
	owner, dev := mkUser(t, s), mkUser(t, s)
	org := mkOrg(t, s, owner)

	if err := s.AddMembership(ctx, domain.Membership{OrgID: org.ID, UserID: dev.ID, Role: domain.RoleDeveloper}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMembership(ctx, domain.Membership{OrgID: org.ID, UserID: dev.ID, Role: domain.RoleViewer}, time.Now()); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate membership err = %v", err)
	}
	if err := s.AddMembership(ctx, domain.Membership{OrgID: org.ID, UserID: dev.ID, Role: "god"}, time.Now()); err == nil {
		t.Fatal("invalid role accepted by database")
	}
	if err := s.UpdateMembershipRole(ctx, domain.Membership{OrgID: org.ID, UserID: dev.ID, Role: domain.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.GetMembershipRole(ctx, org.ID, dev.ID); r != domain.RoleAdmin {
		t.Fatalf("role = %q", r)
	}
	members, err := s.ListMembers(ctx, org.ID, "", 100)
	if err != nil || len(members) != 2 {
		t.Fatalf("members = %+v, %v", members, err)
	}
	if err := s.InTx(ctx, func(ctx context.Context) error {
		owners, err := s.LockOwners(ctx, org.ID)
		if err != nil || len(owners) != 1 || owners[0] != owner.ID {
			t.Errorf("owners = %v, %v", owners, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteMembership(ctx, org.ID, dev.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteMembership(ctx, org.ID, dev.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("second delete err = %v", err)
	}
	if err := s.UpdateMembershipRole(ctx, domain.Membership{OrgID: org.ID, UserID: dev.ID, Role: domain.RoleViewer}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("update non-member err = %v", err)
	}
}

func TestStore_UsersAndInstanceAdminIsGrantOnly(t *testing.T) {
	s := storetest.New(t)
	ctx := t.Context()
	u := mkUser(t, s)
	if _, err := s.CreateUser(ctx, domain.User{ID: gen.New(), Issuer: u.Issuer, Subject: u.Subject, Email: "x@example.test", DisplayName: "x", CreatedAt: time.Now()}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate identity err = %v", err)
	}
	up, err := s.UpdateUserProfile(ctx, u.ID, u.Email, "New Name", true)
	if err != nil || !up.InstanceAdmin || up.DisplayName != "New Name" {
		t.Fatalf("grant admin = %+v, %v", up, err)
	}
	up, err = s.UpdateUserProfile(ctx, u.ID, u.Email, "New Name", false)
	if err != nil || !up.InstanceAdmin {
		t.Fatalf("instance admin was revoked by a profile refresh: %+v, %v", up, err)
	}
	byEmail, err := s.GetUserByEmail(ctx, "  "+u.Email)
	if err == nil {
		t.Fatalf("email lookup should be exact (modulo case), got %+v", byEmail)
	}
	if got, err := s.GetUserByOIDC(ctx, u.Issuer, u.Subject); err != nil || got.ID != u.ID {
		t.Fatalf("by oidc = %+v, %v", got, err)
	}
}

func TestStore_SingleUseCredentials(t *testing.T) {
	s := storetest.New(t)
	ctx := t.Context()
	now := time.Now().UTC()
	u := mkUser(t, s)

	stateHash := []byte(storetest.Unique("state"))
	if err := s.CreateLoginState(ctx, domain.LoginState{StateHash: stateHash, Client: domain.LoginClientWeb, Nonce: "n", IDPCodeVerifier: "v", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeLoginState(ctx, stateHash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeLoginState(ctx, stateHash); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("login state reused: %v", err)
	}

	codeHash := []byte(storetest.Unique("code"))
	if err := s.CreateDesktopAuthCode(ctx, domain.DesktopAuthCode{CodeHash: codeHash, UserID: u.ID, CodeChallenge: "c", RedirectURI: "http://127.0.0.1:1/callback", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseDesktopAuthCode(ctx, codeHash, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseDesktopAuthCode(ctx, codeHash, now); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("auth code reused: %v", err)
	}
}

func TestStore_AuditLogIsAppendOnly(t *testing.T) {
	s := storetest.New(t)
	ctx := t.Context()
	org := mkOrg(t, s, mkUser(t, s))
	e := domain.AuditEvent{
		ID: gen.New(), ChainKey: org.ID, Seq: 1, OrgID: org.ID, OccurredAt: time.Now().UTC(), ActorKind: "user", ActorID: "u",
		Action: "members:manage", TargetType: "membership", TargetID: "x", Result: domain.AuditSuccess,
		RequestID: "r", SourceIP: "203.0.113.1", UserAgent: "test", Details: map[string]string{"role": "admin"},
		PrevHash: make([]byte, 32), Hash: make([]byte, 32),
	}
	if err := s.InsertAuditEvent(ctx, e); err != nil {
		t.Fatal(err)
	}
	dup := e
	dup.ID = gen.New()
	if err := s.InsertAuditEvent(ctx, dup); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate chain seq err = %v, want ErrConflict", err)
	}
	head, err := s.GetAuditChainHead(ctx, org.ID)
	if err != nil || head.Seq != 1 {
		t.Fatalf("head = %+v, %v", head, err)
	}
	if empty, err := s.GetAuditChainHead(ctx, "no-such-chain"); err != nil || empty.Seq != 0 {
		t.Fatalf("empty head = %+v, %v", empty, err)
	}
	events, err := s.ListAuditEvents(ctx, org.ID, "", 10)
	if err != nil || len(events) != 1 || events[0].Details["role"] != "admin" {
		t.Fatalf("events = %+v, %v", events, err)
	}
	if err := s.TryTamperAuditLog(ctx); err == nil {
		t.Fatal("UPDATE or DELETE on audit_events succeeded; table must be append-only")
	}
}
