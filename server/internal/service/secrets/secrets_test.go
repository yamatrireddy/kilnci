// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/secrets"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/service/paging"
	"github.com/yamatrireddy/kilnci/server/internal/store"
)

// Test-only value; not a real credential.
const testValue = "fake-value-0123456789"

// fakeStore is an in-memory Store for one org ("org1") with one project.
type fakeStore struct {
	calls     []string
	dataKeys  []store.DataKey
	secrets   map[string]store.SealedSecret // by projectID + "/" + name
	notKnown  int64
	gotKeyIDs []string
	count     int64
	// loseRace makes InsertFirstDataKey report that another writer won,
	// with winner stored as the active key.
	loseRace  bool
	winner    store.DataKey
	updateErr error
}

func newFakeStore() *fakeStore { return &fakeStore{secrets: map[string]store.SealedSecret{}} }

func (f *fakeStore) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func (f *fakeStore) GetOrgForMember(_ context.Context, slug, userID string) (domain.OrgWithRole, error) {
	if slug != "acme" || userID != "u1" {
		return domain.OrgWithRole{}, domain.ErrNotFound
	}
	return domain.OrgWithRole{Org: domain.Org{ID: "org1", Slug: "acme"}, Role: domain.RoleAdmin}, nil
}

func (f *fakeStore) GetProject(_ context.Context, orgID, slug string) (domain.Project, error) {
	if orgID != "org1" || slug != "web" {
		return domain.Project{}, domain.ErrNotFound
	}
	return domain.Project{ID: "proj1", OrgID: "org1", Slug: "web"}, nil
}

func (f *fakeStore) GetActiveDataKey(_ context.Context, orgID string) (store.DataKey, error) {
	f.calls = append(f.calls, "GetActiveDataKey")
	for _, k := range f.dataKeys {
		if k.OrgID == orgID && k.Active {
			return k, nil
		}
	}
	return store.DataKey{}, domain.ErrNotFound
}

func (f *fakeStore) InsertFirstDataKey(_ context.Context, k store.DataKey) (bool, error) {
	f.calls = append(f.calls, "InsertFirstDataKey")
	if f.loseRace {
		f.dataKeys = append(f.dataKeys, f.winner)
		return false, nil
	}
	k.Version, k.Active = 1, true
	f.dataKeys = append(f.dataKeys, k)
	return true, nil
}

func (f *fakeStore) CountDataKeysNotWrappedBy(_ context.Context, keyIDs []string) (int64, error) {
	f.gotKeyIDs = keyIDs
	return f.notKnown, nil
}

func (f *fakeStore) CountSecrets(context.Context, string, string) (int64, error) {
	f.calls = append(f.calls, "CountSecrets")
	return f.count, nil
}

func (f *fakeStore) LockSecretScope(context.Context, string, string) error {
	f.calls = append(f.calls, "LockSecretScope")
	return nil
}

func (f *fakeStore) LockSecret(_ context.Context, _, projectID, name string) (store.LockedSecret, error) {
	w, ok := f.secrets[projectID+"/"+name]
	if !ok {
		return store.LockedSecret{}, domain.ErrNotFound
	}
	return store.LockedSecret{Secret: w.Secret, DEKVersion: w.DEKVersion}, nil
}

func (f *fakeStore) InsertSecret(_ context.Context, w store.SealedSecret) error {
	f.secrets[w.Secret.ProjectID+"/"+w.Secret.Name] = w
	return nil
}

func (f *fakeStore) UpdateSecret(_ context.Context, w store.SealedSecret) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.secrets[w.Secret.ProjectID+"/"+w.Secret.Name] = w
	return nil
}

func (f *fakeStore) ListSecrets(context.Context, string, string, string, int32) ([]domain.Secret, error) {
	return nil, nil
}

func (f *fakeStore) DeleteSecret(_ context.Context, _, projectID, name string) error {
	delete(f.secrets, projectID+"/"+name)
	return nil
}

func (f *fakeStore) ProjectSlugsByID(context.Context, string, []string) (map[string]string, error) {
	return map[string]string{"proj1": "web"}, nil
}

func (f *fakeStore) ProjectIDsBySlug(_ context.Context, _ string, slugs []string) (map[string]string, error) {
	out := map[string]string{}
	for _, s := range slugs {
		if s == "web" {
			out[s] = "proj1"
		}
	}
	return out, nil
}

// fakeKeyring hands out random DEKs "wrapped" as themselves, and records
// the plaintext keys it returned so tests can check they were cleared.
type fakeKeyring struct {
	issued [][]byte
	keys   map[string][]byte // wrapped ciphertext -> key
}

func (k *fakeKeyring) NewDataKey(context.Context, string) ([]byte, secrets.WrappedKey, error) {
	dek, err := secrets.NewDEK()
	if err != nil {
		return nil, secrets.WrappedKey{}, err //nolint:wrapcheck // test
	}
	wrapped := []byte(fmt.Sprintf("w%d", len(k.keys)))
	if k.keys == nil {
		k.keys = map[string][]byte{}
	}
	k.keys[string(wrapped)] = bytes.Clone(dek)
	k.issued = append(k.issued, dek)
	return dek, secrets.WrappedKey{KeyID: "local:test", Ciphertext: wrapped}, nil
}

func (k *fakeKeyring) DataKey(_ context.Context, _ string, _ int32, wk secrets.WrappedKey) ([]byte, error) {
	dek, ok := k.keys[string(wk.Ciphertext)]
	if !ok {
		return nil, secrets.ErrDecrypt
	}
	return bytes.Clone(dek), nil
}

type allowAll struct{ deny bool }

func (a allowAll) Check(context.Context, *authz.Principal, authz.Action, authz.Resource) error {
	if a.deny {
		return domain.ErrForbidden
	}
	return nil
}

type recordingAuditor struct{ entries []audit.Entry }

func (r *recordingAuditor) Record(_ context.Context, e audit.Entry) error {
	r.entries = append(r.entries, e)
	return nil
}

func testCtx() context.Context {
	return authz.WithPrincipal(context.Background(), &authz.Principal{Kind: authz.KindUser, UserID: "u1"})
}

func newTestService(st *fakeStore, kr Keyring, deny bool) (*Service, *recordingAuditor) {
	a := &recordingAuditor{}
	now := func() time.Time { return time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC) }
	return NewService(st, allowAll{deny: deny}, a, kr, ids.NewGenerator(nil), now), a
}

func version(v int64) *int64 { return &v }

func TestPut_CreateSealsBoundToRow(t *testing.T) {
	st, kr := newFakeStore(), &fakeKeyring{}
	svc, a := newTestService(st, kr, false)
	w, err := svc.Put(testCtx(), Target{OrgSlug: "acme"}, "DEPLOY_TOKEN", Input{Value: testValue, ProjectSlugs: []string{"web"}})
	if err != nil {
		t.Fatal(err)
	}
	if !w.Created || w.Secret.ValueVersion != 1 || len(w.Warnings) != 0 || len(w.Secret.ProjectSlugs) != 1 {
		t.Fatalf("written = %+v", w)
	}
	row := st.secrets["/DEPLOY_TOKEN"]
	if bytes.Contains(row.Ciphertext, []byte(testValue)) {
		t.Fatal("stored plaintext")
	}
	dek := kr.keys["w0"]
	if pt, err := secrets.Open(dek, row.Ciphertext, aadFor(row.Secret, row.DEKVersion)); err != nil || string(pt) != testValue {
		t.Fatalf("open: %v", err)
	}
	other := row.Secret
	other.ID = "someone-else"
	if _, err := secrets.Open(dek, row.Ciphertext, aadFor(other, row.DEKVersion)); err == nil {
		t.Fatal("ciphertext opened under another row ID")
	}
	// The per-scope lock is taken before the count.
	if got := strings.Join(st.calls, ","); !strings.Contains(got, "LockSecretScope,CountSecrets") {
		t.Fatalf("calls = %s", got)
	}
	if len(a.entries) != 1 || a.entries[0].Action != "secrets:create" || strings.Contains(fmt.Sprint(a.entries[0].Details), testValue) {
		t.Fatalf("audit = %+v", a.entries)
	}
	// The plaintext DEK handed out was cleared after use.
	if !bytes.Equal(kr.issued[0], make([]byte, secrets.KeySize)) {
		t.Fatal("data key not cleared")
	}
}

func TestPut_Preconditions(t *testing.T) {
	st := newFakeStore()
	svc, _ := newTestService(st, &fakeKeyring{}, false)
	ctx, tgt := testCtx(), Target{OrgSlug: "acme"}
	if _, err := svc.Put(ctx, tgt, "TOKEN", Input{Value: testValue, IfMatch: version(1)}); !errors.Is(err, domain.ErrPreconditionFailed) {
		t.Fatalf("If-Match on create: %v", err)
	}
	if _, err := svc.Put(ctx, tgt, "TOKEN", Input{Value: testValue}); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		ifMatch *int64
		want    error
	}{
		"missing": {nil, domain.ErrPreconditionRequired},
		"stale":   {version(0), domain.ErrPreconditionFailed},
		"ahead":   {version(2), domain.ErrPreconditionFailed},
	} {
		if _, err := svc.Put(ctx, tgt, "TOKEN", Input{Value: "other-value", IfMatch: tc.ifMatch}); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	w, err := svc.Put(ctx, tgt, "TOKEN", Input{Value: "other-value", IfMatch: version(1)})
	if err != nil || w.Created || w.Secret.ValueVersion != 2 {
		t.Fatalf("replace: %+v, %v", w, err)
	}
	// A lost update race (the store's version guard) is a conflict.
	st.updateErr = fmt.Errorf("update secret: %w", domain.ErrConflict)
	if _, err := svc.Put(ctx, tgt, "TOKEN", Input{Value: "third-value", IfMatch: version(2)}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("guard: %v", err)
	}
}

func TestPut_ScopeLimit(t *testing.T) {
	st := newFakeStore()
	st.count = domain.MaxSecretsPerScope
	svc, _ := newTestService(st, &fakeKeyring{}, false)
	if _, err := svc.Put(testCtx(), Target{OrgSlug: "acme", ProjectSlug: "web"}, "TOKEN", Input{Value: testValue}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("err = %v", err)
	}
	if len(st.secrets) != 0 {
		t.Fatal("secret stored over the limit")
	}
}

func TestPut_ShortValueWarns(t *testing.T) {
	svc, _ := newTestService(newFakeStore(), &fakeKeyring{}, false)
	w, err := svc.Put(testCtx(), Target{OrgSlug: "acme"}, "PIN", Input{Value: "123"})
	if err != nil || w.Secret.Masked || len(w.Warnings) != 1 || w.Warnings[0] != WarningNotMasked {
		t.Fatalf("written = %+v, %v", w, err)
	}
}

func TestPut_AuthorizationBeforeConfiguration(t *testing.T) {
	ctx := testCtx()
	for name, tc := range map[string]struct {
		svc  *Service
		tgt  Target
		want error
	}{
		"not a member":     {first(newTestService(newFakeStore(), nil, false)), Target{OrgSlug: "other"}, domain.ErrNotFound},
		"forbidden":        {first(newTestService(newFakeStore(), nil, true)), Target{OrgSlug: "acme"}, domain.ErrForbidden},
		"unknown project":  {first(newTestService(newFakeStore(), nil, false)), Target{OrgSlug: "acme", ProjectSlug: "nope"}, domain.ErrNotFound},
		"no keyring":       {first(newTestService(newFakeStore(), nil, false)), Target{OrgSlug: "acme"}, domain.ErrUnavailable},
		"no principal":     {first(newTestService(newFakeStore(), &fakeKeyring{}, false)), Target{OrgSlug: "acme"}, domain.ErrUnauthenticated},
		"bad org slug":     {first(newTestService(newFakeStore(), &fakeKeyring{}, false)), Target{OrgSlug: "../x"}, domain.ErrNotFound},
		"bad project slug": {first(newTestService(newFakeStore(), &fakeKeyring{}, false)), Target{OrgSlug: "acme", ProjectSlug: "../x"}, domain.ErrNotFound},
	} {
		c := ctx
		if name == "no principal" {
			c = context.Background()
		}
		if _, err := tc.svc.Put(c, tc.tgt, "TOKEN", Input{Value: testValue}); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
}

func first[A, B any](a A, _ B) A { return a }

func TestActiveDataKey_LostRaceUsesWinner(t *testing.T) {
	st, kr := newFakeStore(), &fakeKeyring{}
	winnerKey, wk, err := kr.NewDataKey(context.Background(), "org1")
	if err != nil {
		t.Fatal(err)
	}
	winnerKey = bytes.Clone(winnerKey)
	st.loseRace = true
	st.winner = store.DataKey{OrgID: "org1", Version: 1, KeyID: wk.KeyID, Wrapped: wk.Ciphertext, Active: true}
	svc, _ := newTestService(st, kr, false)
	dek, v, err := svc.activeDataKey(context.Background(), "org1")
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 || !bytes.Equal(dek, winnerKey) {
		t.Fatal("did not use the winner's key")
	}
	if !bytes.Equal(kr.issued[1], make([]byte, secrets.KeySize)) {
		t.Fatal("loser's key not cleared")
	}
	if got := strings.Join(st.calls, ","); got != "GetActiveDataKey,InsertFirstDataKey,GetActiveDataKey" {
		t.Fatalf("calls = %s", got)
	}
}

func TestDelete_WorksWithoutKeyringAndAudits(t *testing.T) {
	st := newFakeStore()
	st.secrets["proj1/TOKEN"] = store.SealedSecret{Secret: domain.Secret{ID: "s1", OrgID: "org1", ProjectID: "proj1", Name: "TOKEN"}}
	svc, a := newTestService(st, nil, false)
	tgt := Target{OrgSlug: "acme", ProjectSlug: "web"}
	if err := svc.Delete(testCtx(), tgt, "TOKEN"); err != nil {
		t.Fatal(err)
	}
	if len(st.secrets) != 0 || len(a.entries) != 1 || a.entries[0].Action != "secrets:delete" || a.entries[0].TargetID != "s1" {
		t.Fatalf("secrets = %v, audit = %+v", st.secrets, a.entries)
	}
	if err := svc.Delete(testCtx(), tgt, "TOKEN"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if err := svc.Delete(testCtx(), tgt, "not a name"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("invalid name: %v", err)
	}
	denied, _ := newTestService(newFakeStore(), nil, true)
	if err := denied.Delete(testCtx(), tgt, "TOKEN"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("denied: %v", err)
	}
}

func TestVerifyDataKeys(t *testing.T) {
	for name, tc := range map[string]struct {
		unknown int64
		wantErr bool
	}{
		"all known":   {0, false},
		"one unknown": {1, true},
	} {
		st := newFakeStore()
		st.notKnown = tc.unknown
		svc, _ := newTestService(st, &fakeKeyring{}, false)
		err := svc.VerifyDataKeys(context.Background(), []string{"local:abc"})
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(st.gotKeyIDs) != 1 || st.gotKeyIDs[0] != "local:abc" {
			t.Errorf("%s: key IDs = %v", name, st.gotKeyIDs)
		}
	}
}

func TestPut_Validation(t *testing.T) {
	many := make([]string, domain.MaxSecretProjects+1)
	for i := range many {
		many[i] = fmt.Sprintf("p%d", i)
	}
	org, proj := Target{OrgSlug: "acme"}, Target{OrgSlug: "acme", ProjectSlug: "web"}
	for name, tc := range map[string]struct {
		tgt       Target
		secret    string
		in        Input
		wantField string
	}{
		"reserved name":     {org, "LD_PRELOAD", Input{Value: testValue}, "secretName"},
		"empty value":       {org, "TOKEN", Input{}, "value"},
		"bad branch":        {org, "TOKEN", Input{Value: testValue, Branches: []string{"refs/heads/main"}}, "branches"},
		"projects on proj":  {proj, "TOKEN", Input{Value: testValue, ProjectSlugs: []string{"web"}}, "projectSlugs"},
		"all on proj":       {proj, "TOKEN", Input{Value: testValue, AllProjects: true}, "projectSlugs"},
		"all and list":      {org, "TOKEN", Input{Value: testValue, AllProjects: true, ProjectSlugs: []string{"web"}}, "projectSlugs"},
		"too many projects": {org, "TOKEN", Input{Value: testValue, ProjectSlugs: many}, "projectSlugs"},
		"invalid slug":      {org, "TOKEN", Input{Value: testValue, ProjectSlugs: []string{"../x"}}, "projectSlugs"},
		"unknown project":   {org, "TOKEN", Input{Value: testValue, ProjectSlugs: []string{"api"}}, "projectSlugs"},
	} {
		st := newFakeStore()
		svc, a := newTestService(st, &fakeKeyring{}, false)
		_, err := svc.Put(testCtx(), tc.tgt, tc.secret, tc.in)
		var ve *domain.ValidationError
		if !errors.As(err, &ve) || ve.Fields[0].Field != tc.wantField {
			t.Errorf("%s: err = %v, want field %s", name, err, tc.wantField)
		}
		if len(st.secrets) != 0 || len(a.entries) != 0 {
			t.Errorf("%s: wrote or audited despite invalid input", name)
		}
		if err != nil && strings.Contains(err.Error(), testValue) {
			t.Errorf("%s: error echoes the value", name)
		}
	}
}

func TestPut_ProjectSecretAndDuplicateSlugs(t *testing.T) {
	st := newFakeStore()
	svc, a := newTestService(st, &fakeKeyring{}, false)
	w, err := svc.Put(testCtx(), Target{OrgSlug: "acme", ProjectSlug: "web"}, "TOKEN", Input{Value: testValue, Branches: []string{"main"}})
	if err != nil || w.Secret.Scope() != domain.SecretScopeProject || a.entries[0].Details["project_id"] != "proj1" {
		t.Fatalf("project secret: %+v, %v", w, err)
	}
	w, err = svc.Put(testCtx(), Target{OrgSlug: "acme"}, "TOKEN", Input{Value: testValue, ProjectSlugs: []string{"web", "web"}, AllowUnprotected: true})
	if err != nil || len(w.Secret.ProjectIDs) != 1 || len(w.Warnings) != 1 {
		t.Fatalf("org secret: %+v, %v", w, err)
	}
}

func TestList(t *testing.T) {
	st := &listStore{fakeStore: newFakeStore()}
	svc, _ := newTestService(st.fakeStore, nil, false)
	svc.store = st
	page, err := svc.List(testCtx(), Target{OrgSlug: "acme"}, pagingRequest(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.NextCursor == "" || len(page.Items[0].ProjectSlugs) != 1 || page.Items[0].ProjectSlugs[0] != "web" {
		t.Fatalf("page = %+v", page)
	}
	denied, _ := newTestService(newFakeStore(), nil, true)
	if _, err := denied.List(testCtx(), Target{OrgSlug: "acme"}, pagingRequest(1)); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("denied: %v", err)
	}
}

// listStore returns two org secrets, one allowed in a deleted project.
type listStore struct{ *fakeStore }

func (l *listStore) ListSecrets(_ context.Context, _, _, _ string, limit int32) ([]domain.Secret, error) {
	xs := []domain.Secret{
		{ID: "01", OrgID: "org1", Name: "A", ProjectIDs: []string{"proj1", "deleted"}},
		{ID: "02", OrgID: "org1", Name: "B"},
	}
	return xs[:min(int(limit), len(xs))], nil
}

func pagingRequest(limit int) paging.Request { return paging.Request{Limit: limit} }
