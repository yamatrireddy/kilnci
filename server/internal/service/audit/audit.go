// SPDX-License-Identifier: Apache-2.0

// Package audit records privileged actions in the append-only, hash-chained
// audit log (security-standards §12, threat T-11/T-46).
//
// Each org has its own chain (instance-level events use the "" chain). An
// event's hash is SHA-256 over its canonical encoding, which includes the
// previous event's hash, so any edit, deletion, or reordering breaks Verify.
// The database also rejects UPDATE/DELETE on the table.
package audit

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/platform/reqmeta"
	"github.com/yamatrireddy/kilnci/server/internal/store"
)

var tracer = otel.Tracer("github.com/yamatrireddy/kilnci/server/internal/service/audit")

// Store is the persistence the recorder needs.
type Store interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
	LockAuditChain(ctx context.Context, chainKey string) error
	GetAuditChainHead(ctx context.Context, chainKey string) (store.AuditChainHead, error)
	InsertAuditEvent(ctx context.Context, e domain.AuditEvent) error
	ListAuditChain(ctx context.Context, chainKey string) ([]domain.AuditEvent, error)
}

// Recorder appends audit events.
type Recorder struct {
	store Store
	ids   *ids.Generator
	now   func() time.Time
}

// NewRecorder returns a Recorder. now may be nil (time.Now).
func NewRecorder(s Store, gen *ids.Generator, now func() time.Time) *Recorder {
	if now == nil {
		now = time.Now
	}
	return &Recorder{store: s, ids: gen, now: now}
}

// Entry describes an action to record. Actor defaults to the principal in
// the context; request ID, client IP, and user agent come from the context.
type Entry struct {
	OrgID      string
	Actor      *authz.Principal
	ActorKind  string // overrides Actor, e.g. "system"
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	Result     domain.AuditResult
	Details    map[string]string
}

// Record appends e. Call it inside the same transaction as the change it
// records so the two commit or roll back together.
func (r *Recorder) Record(ctx context.Context, e Entry) error {
	ctx, span := tracer.Start(ctx, "audit.Record")
	defer span.End()

	ev := domain.AuditEvent{
		ID:         r.ids.New(),
		ChainKey:   e.OrgID,
		OrgID:      e.OrgID,
		OccurredAt: r.now().UTC().Truncate(time.Microsecond), // database precision
		ActorKind:  e.ActorKind,
		ActorID:    e.ActorID,
		Action:     e.Action,
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		Result:     e.Result,
		RequestID:  logging.RequestID(ctx),
		Details:    e.Details,
	}
	if ev.Result == "" {
		ev.Result = domain.AuditSuccess
	}
	if ev.Details == nil {
		ev.Details = map[string]string{}
	}
	if ev.ActorKind == "" {
		p := e.Actor
		if p == nil {
			p, _ = authz.FromContext(ctx)
		}
		if p != nil {
			ev.ActorKind, ev.ActorID = string(p.Kind), p.UserID
			if p.CredentialID != "" {
				ev.Details["credential_id"] = p.CredentialID
			}
		} else {
			ev.ActorKind, ev.ActorID = "anonymous", ""
		}
	}
	meta := reqmeta.From(ctx)
	ev.SourceIP, ev.UserAgent = meta.ClientIP, meta.UserAgent

	return r.store.InTx(ctx, func(ctx context.Context) error {
		if err := r.store.LockAuditChain(ctx, ev.ChainKey); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		head, err := r.store.GetAuditChainHead(ctx, ev.ChainKey)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		ev.Seq = head.Seq + 1
		ev.PrevHash = head.Hash
		if ev.PrevHash == nil {
			ev.PrevHash = make([]byte, sha256.Size)
		}
		ev.Hash = Hash(ev)
		return r.store.InsertAuditEvent(ctx, ev) //nolint:wrapcheck // store errors are contextual
	})
}

// canonical is the hashed form of an event. Field order is fixed by the struct
// and map keys are sorted by encoding/json, so the encoding is deterministic.
type canonical struct {
	ID         string            `json:"id"`
	ChainKey   string            `json:"chainKey"`
	Seq        int64             `json:"seq"`
	OrgID      string            `json:"orgId"`
	OccurredAt string            `json:"occurredAt"`
	ActorKind  string            `json:"actorKind"`
	ActorID    string            `json:"actorId"`
	Action     string            `json:"action"`
	TargetType string            `json:"targetType"`
	TargetID   string            `json:"targetId"`
	Result     string            `json:"result"`
	RequestID  string            `json:"requestId"`
	SourceIP   string            `json:"sourceIp"`
	UserAgent  string            `json:"userAgent"`
	Details    map[string]string `json:"details"`
	PrevHash   []byte            `json:"prevHash"`
}

// Hash computes an event's chained hash (ignoring e.Hash).
func Hash(e domain.AuditEvent) []byte {
	details := e.Details
	if details == nil {
		details = map[string]string{}
	}
	b, _ := json.Marshal(canonical{
		ID: e.ID, ChainKey: e.ChainKey, Seq: e.Seq, OrgID: e.OrgID,
		OccurredAt: e.OccurredAt.UTC().Format(time.RFC3339Nano),
		ActorKind:  e.ActorKind, ActorID: e.ActorID, Action: e.Action, TargetType: e.TargetType,
		TargetID: e.TargetID, Result: string(e.Result), RequestID: e.RequestID, SourceIP: e.SourceIP,
		UserAgent: e.UserAgent, Details: details, PrevHash: e.PrevHash,
	})
	sum := sha256.Sum256(b)
	return sum[:]
}

// Verify recomputes a chain and returns an error at the first broken link.
func Verify(events []domain.AuditEvent) error {
	prev := make([]byte, sha256.Size)
	for i, e := range events {
		if e.Seq != int64(i)+1 {
			return fmt.Errorf("audit chain gap at seq %d (event %s)", e.Seq, e.ID)
		}
		if subtle.ConstantTimeCompare(e.PrevHash, prev) != 1 {
			return fmt.Errorf("audit chain broken before seq %d (event %s)", e.Seq, e.ID)
		}
		if subtle.ConstantTimeCompare(Hash(e), e.Hash) != 1 {
			return fmt.Errorf("audit event seq %d (event %s) was modified", e.Seq, e.ID)
		}
		prev = e.Hash
	}
	return nil
}

// VerifyChain loads and verifies one chain.
func (r *Recorder) VerifyChain(ctx context.Context, chainKey string) error {
	events, err := r.store.ListAuditChain(ctx, chainKey)
	if err != nil {
		return err //nolint:wrapcheck // store errors are contextual
	}
	return Verify(events)
}
