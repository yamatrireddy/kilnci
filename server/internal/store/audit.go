// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/store/db"
)

// AuditChainHead is the latest link of an audit chain.
type AuditChainHead struct {
	Seq  int64
	Hash []byte
}

// LockAuditChain serializes appends to chainKey until the transaction ends.
// It must be called inside InTx.
func (s *Store) LockAuditChain(ctx context.Context, chainKey string) error {
	return mapErr("lock audit chain", s.q(ctx).LockAuditChain(ctx, chainKey))
}

// GetAuditChainHead returns the chain's last link, or a zero head for an
// empty chain.
func (s *Store) GetAuditChainHead(ctx context.Context, chainKey string) (AuditChainHead, error) {
	r, err := s.q(ctx).GetAuditChainHead(ctx, chainKey)
	if err := mapErr("get audit chain head", err); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return AuditChainHead{}, nil
		}
		return AuditChainHead{}, err
	}
	return AuditChainHead{Seq: r.Seq, Hash: r.Hash}, nil
}

// InsertAuditEvent appends a fully formed (hashed) event.
func (s *Store) InsertAuditEvent(ctx context.Context, e domain.AuditEvent) error {
	details, err := json.Marshal(e.Details)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}
	var orgID *string
	if e.OrgID != "" {
		orgID = &e.OrgID
	}
	return mapErr("insert audit event", s.q(ctx).InsertAuditEvent(ctx, db.InsertAuditEventParams{
		ID: e.ID, ChainKey: e.ChainKey, Seq: e.Seq, OrgID: orgID, OccurredAt: e.OccurredAt,
		ActorKind: e.ActorKind, ActorID: e.ActorID, Action: e.Action, TargetType: e.TargetType,
		TargetID: e.TargetID, Result: string(e.Result), RequestID: e.RequestID, SourceIp: e.SourceIP,
		UserAgent: e.UserAgent, Details: details, PrevHash: e.PrevHash, Hash: e.Hash,
	}))
}

func toAuditEvent(r db.AuditEvent) (domain.AuditEvent, error) {
	var details map[string]string
	if err := json.Unmarshal(r.Details, &details); err != nil {
		return domain.AuditEvent{}, fmt.Errorf("decode audit details: %w", err)
	}
	e := domain.AuditEvent{
		ID: r.ID, ChainKey: r.ChainKey, Seq: r.Seq, OccurredAt: r.OccurredAt, ActorKind: r.ActorKind,
		ActorID: r.ActorID, Action: r.Action, TargetType: r.TargetType, TargetID: r.TargetID,
		Result: domain.AuditResult(r.Result), RequestID: r.RequestID, SourceIP: r.SourceIp,
		UserAgent: r.UserAgent, Details: details, PrevHash: r.PrevHash, Hash: r.Hash,
	}
	if r.OrgID != nil {
		e.OrgID = *r.OrgID
	}
	return e, nil
}

// ListAuditEvents lists orgID's events newest first, before beforeID if set.
func (s *Store) ListAuditEvents(ctx context.Context, orgID, beforeID string, limit int32) ([]domain.AuditEvent, error) {
	rows, err := s.q(ctx).ListAuditEvents(ctx, db.ListAuditEventsParams{OrgID: &orgID, BeforeID: beforeID, MaxRows: limit})
	if err != nil {
		return nil, mapErr("list audit events", err)
	}
	return toAuditEvents(rows)
}

// ListAuditChain returns a whole chain in order, for verification.
func (s *Store) ListAuditChain(ctx context.Context, chainKey string) ([]domain.AuditEvent, error) {
	rows, err := s.q(ctx).ListAuditChain(ctx, chainKey)
	if err != nil {
		return nil, mapErr("list audit chain", err)
	}
	return toAuditEvents(rows)
}

func toAuditEvents(rows []db.AuditEvent) ([]domain.AuditEvent, error) {
	out := make([]domain.AuditEvent, len(rows))
	for i, r := range rows {
		e, err := toAuditEvent(r)
		if err != nil {
			return nil, err
		}
		out[i] = e
	}
	return out, nil
}
