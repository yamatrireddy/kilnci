// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/platform/reqmeta"
	"github.com/yamatrireddy/kilnci/server/internal/store"
)

// memStore is an in-memory Store for unit tests.
type memStore struct {
	chains map[string][]domain.AuditEvent
	failAt string
	locked []string
	inTx   int
}

func newMem() *memStore { return &memStore{chains: map[string][]domain.AuditEvent{}} }

func (m *memStore) InTx(ctx context.Context, fn func(context.Context) error) error {
	m.inTx++
	return fn(ctx)
}

func (m *memStore) LockAuditChain(_ context.Context, key string) error {
	m.locked = append(m.locked, key)
	if m.failAt == "lock" {
		return errors.New("lock failed")
	}
	return nil
}

func (m *memStore) GetAuditChainHead(_ context.Context, key string) (store.AuditChainHead, error) {
	c := m.chains[key]
	if len(c) == 0 {
		return store.AuditChainHead{}, nil
	}
	last := c[len(c)-1]
	return store.AuditChainHead{Seq: last.Seq, Hash: last.Hash}, nil
}

func (m *memStore) InsertAuditEvent(_ context.Context, e domain.AuditEvent) error {
	if m.failAt == "insert" {
		return errors.New("insert failed")
	}
	m.chains[e.ChainKey] = append(m.chains[e.ChainKey], e)
	return nil
}

func (m *memStore) ListAuditChain(_ context.Context, key string) ([]domain.AuditEvent, error) {
	return m.chains[key], nil
}

func TestRecorder_BuildsVerifiableChainWithContext(t *testing.T) {
	m := newMem()
	clock := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	r := NewRecorder(m, ids.NewGenerator(nil), func() time.Time { return clock })
	ctx := logging.WithRequestID(context.Background(), "req-1")
	ctx = reqmeta.With(ctx, reqmeta.Meta{ClientIP: "203.0.113.5", UserAgent: "kiln-test"})
	ctx = authz.WithPrincipal(ctx, &authz.Principal{Kind: authz.KindUser, UserID: "u1", CredentialID: "sess-1"})

	for i := range 3 {
		if err := r.Record(ctx, Entry{OrgID: "org1", Action: "members:manage", TargetType: "membership", TargetID: string(rune('a' + i))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Record(ctx, Entry{ActorKind: "system", ActorID: "gc", Action: "cleanup", Result: domain.AuditDenied}); err != nil {
		t.Fatal(err)
	}

	chain := m.chains["org1"]
	if len(chain) != 3 {
		t.Fatalf("chain length %d", len(chain))
	}
	e := chain[0]
	if e.ActorKind != "user" || e.ActorID != "u1" || e.RequestID != "req-1" || e.SourceIP != "203.0.113.5" ||
		e.UserAgent != "kiln-test" || e.Details["credential_id"] != "sess-1" || e.Result != domain.AuditSuccess {
		t.Fatalf("event fields wrong: %+v", e)
	}
	if e.OccurredAt.Nanosecond()%1000 != 0 {
		t.Fatal("timestamp not truncated to database precision")
	}
	if err := r.VerifyChain(ctx, "org1"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	inst := m.chains[""]
	if len(inst) != 1 || inst[0].ActorKind != "system" || inst[0].Result != domain.AuditDenied {
		t.Fatalf("instance chain = %+v", inst)
	}
	if m.locked[0] != "org1" {
		t.Fatal("chain not locked before append")
	}
}

func TestVerify_DetectsTampering(t *testing.T) {
	m := newMem()
	r := NewRecorder(m, ids.NewGenerator(nil), nil)
	for range 3 {
		if err := r.Record(context.Background(), Entry{OrgID: "o", Action: "x", TargetType: "t", TargetID: "1"}); err != nil {
			t.Fatal(err)
		}
	}
	good := m.chains["o"]
	clone := func() []domain.AuditEvent { return append([]domain.AuditEvent(nil), good...) }

	modified := clone()
	modified[1].Action = "something-else"
	deleted := []domain.AuditEvent{good[0], good[2]}
	reordered := []domain.AuditEvent{good[1], good[0], good[2]}
	rehashedWithoutChain := clone()
	rehashedWithoutChain[1].TargetID = "forged"
	rehashedWithoutChain[1].Hash = Hash(rehashedWithoutChain[1]) // attacker recomputes one hash

	for name, chain := range map[string][]domain.AuditEvent{
		"modified": modified, "deleted": deleted, "reordered": reordered, "rehashed": rehashedWithoutChain,
	} {
		if err := Verify(chain); err == nil {
			t.Errorf("%s chain verified", name)
		}
	}
	if err := Verify(good); err != nil {
		t.Fatalf("good chain: %v", err)
	}
}

func TestRecorder_PropagatesStoreErrors(t *testing.T) {
	for _, at := range []string{"lock", "insert"} {
		m := newMem()
		m.failAt = at
		r := NewRecorder(m, ids.NewGenerator(nil), nil)
		if err := r.Record(context.Background(), Entry{Action: "x"}); err == nil {
			t.Errorf("%s failure swallowed", at)
		}
	}
}

func TestRecorder_AnonymousActor(t *testing.T) {
	m := newMem()
	r := NewRecorder(m, ids.NewGenerator(nil), nil)
	if err := r.Record(context.Background(), Entry{Action: "auth:login", Result: domain.AuditDenied}); err != nil {
		t.Fatal(err)
	}
	if e := m.chains[""][0]; e.ActorKind != "anonymous" {
		t.Fatalf("actor = %q", e.ActorKind)
	}
}
