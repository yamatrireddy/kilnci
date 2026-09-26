// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/store/db"
)

func toRunner(r db.Runner) domain.Runner {
	return domain.Runner{
		ID: r.ID, OrgID: r.OrgID, Name: r.Name, Labels: r.Labels, Trusted: r.Trusted, Version: r.Version,
		Capacity: int(r.Capacity), CertSerial: r.CertSerial, CertDER: r.CertDer, CertSPKIHash: r.CertSpkiSha256,
		PrevCertSerial: deref(r.PrevCertSerial), CertRenewedAt: r.CertRenewedAt,
		CertExpiresAt: r.CertExpiresAt, CreatedBy: deref(r.CreatedBy), CreatedAt: r.CreatedAt,
		LastSeenAt: r.LastSeenAt, RevokedAt: r.RevokedAt,
	}
}

// CreateRunnerRegistrationToken stores a token's hash and metadata.
func (s *Store) CreateRunnerRegistrationToken(ctx context.Context, t domain.RunnerRegistrationToken, hash []byte) error {
	return mapErr("create runner registration token", s.q(ctx).CreateRunnerRegistrationToken(ctx, db.CreateRunnerRegistrationTokenParams{
		ID: t.ID, OrgID: t.OrgID, TokenHash: hash, Labels: nonNil(t.Labels), Trusted: t.Trusted,
		CreatedBy: nilIfEmpty(t.CreatedBy), CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
	}))
}

// ClaimRunnerRegistrationToken finds an unused, unexpired token by hash and
// locks it until the transaction ends; domain.ErrNotFound otherwise.
func (s *Store) ClaimRunnerRegistrationToken(ctx context.Context, hash []byte, now time.Time) (domain.RunnerRegistrationToken, error) {
	r, err := s.q(ctx).ClaimRunnerRegistrationToken(ctx, db.ClaimRunnerRegistrationTokenParams{TokenHash: hash, Now: now})
	if err != nil {
		return domain.RunnerRegistrationToken{}, mapErr("claim runner registration token", err)
	}
	return domain.RunnerRegistrationToken{ID: r.ID, OrgID: r.OrgID, Labels: r.Labels, Trusted: r.Trusted, CreatedBy: deref(r.CreatedBy)}, nil
}

// MarkRunnerRegistrationTokenUsed consumes a token; domain.ErrConflict if
// it was already used.
func (s *Store) MarkRunnerRegistrationTokenUsed(ctx context.Context, id, runnerID string, now time.Time) error {
	n, err := s.q(ctx).MarkRunnerRegistrationTokenUsed(ctx, db.MarkRunnerRegistrationTokenUsedParams{ID: id, RunnerID: &runnerID, Now: &now})
	if err == nil && n == 0 {
		return fmt.Errorf("mark registration token used: %w", domain.ErrConflict)
	}
	return mapErr("mark registration token used", err)
}

// CountActiveRunnerRegistrationTokens counts an org's unused, unexpired tokens.
func (s *Store) CountActiveRunnerRegistrationTokens(ctx context.Context, orgID string, now time.Time) (int64, error) {
	n, err := s.q(ctx).CountActiveRunnerRegistrationTokens(ctx, db.CountActiveRunnerRegistrationTokensParams{OrgID: orgID, ExpiresAt: now})
	return n, mapErr("count runner registration tokens", err)
}

// DeleteExpiredRunnerRegistrationTokens removes unused expired tokens.
func (s *Store) DeleteExpiredRunnerRegistrationTokens(ctx context.Context, now time.Time) (int64, error) {
	n, err := s.q(ctx).DeleteExpiredRunnerRegistrationTokens(ctx, now)
	return n, mapErr("delete expired runner registration tokens", err)
}

// CreateRunner inserts a runner.
func (s *Store) CreateRunner(ctx context.Context, r domain.Runner) error {
	return mapErr("create runner", s.q(ctx).CreateRunner(ctx, db.CreateRunnerParams{
		ID: r.ID, OrgID: r.OrgID, Name: r.Name, Labels: nonNil(r.Labels), Trusted: r.Trusted, Version: r.Version,
		CertSerial: r.CertSerial, CertDer: r.CertDER, CertSpkiSha256: r.CertSPKIHash, CertRenewedAt: r.CertRenewedAt,
		CertExpiresAt: r.CertExpiresAt, CreatedBy: nilIfEmpty(r.CreatedBy), CreatedAt: r.CreatedAt, LastSeenAt: r.LastSeenAt,
	}))
}

// GetRunner returns a runner of an org.
func (s *Store) GetRunner(ctx context.Context, orgID, id string) (domain.Runner, error) {
	r, err := s.q(ctx).GetRunner(ctx, db.GetRunnerParams{OrgID: orgID, ID: id})
	return toRunner(r), mapErr("get runner", err)
}

// LockRunner returns a runner and locks it until the transaction ends.
func (s *Store) LockRunner(ctx context.Context, orgID, id string) (domain.Runner, error) {
	r, err := s.q(ctx).LockRunner(ctx, db.LockRunnerParams{OrgID: orgID, ID: id})
	return toRunner(r), mapErr("lock runner", err)
}

// ListRunners lists an org's runners ordered by ID after afterID.
func (s *Store) ListRunners(ctx context.Context, orgID, afterID string, limit int32) ([]domain.Runner, error) {
	rows, err := s.q(ctx).ListRunners(ctx, db.ListRunnersParams{OrgID: orgID, AfterID: afterID, MaxRows: limit})
	if err != nil {
		return nil, mapErr("list runners", err)
	}
	out := make([]domain.Runner, len(rows))
	for i, r := range rows {
		out[i] = toRunner(r)
	}
	return out, nil
}

// CertRotation replaces a runner's current certificate serial.
type CertRotation struct {
	OrgID, RunnerID          string
	CurrentSerial, NewSerial string
	CertDER, SPKIHash        []byte
	Now, ExpiresAt           time.Time
}

// RotateRunnerCertificate applies c if the runner is live and still on
// c.CurrentSerial; domain.ErrConflict otherwise.
func (s *Store) RotateRunnerCertificate(ctx context.Context, c CertRotation) error {
	n, err := s.q(ctx).RotateRunnerCertificate(ctx, db.RotateRunnerCertificateParams{
		NewSerial: c.NewSerial, CertDer: c.CertDER, CertSpkiSha256: c.SPKIHash, Now: c.Now, ExpiresAt: c.ExpiresAt,
		OrgID: c.OrgID, ID: c.RunnerID, CurrentSerial: c.CurrentSerial,
	})
	if err == nil && n == 0 {
		return fmt.Errorf("rotate runner certificate: %w", domain.ErrConflict)
	}
	return mapErr("rotate runner certificate", err)
}

// RevokeRunner revokes a live runner; domain.ErrNotFound if there is none.
func (s *Store) RevokeRunner(ctx context.Context, orgID, id string, now time.Time) error {
	n, err := s.q(ctx).RevokeRunner(ctx, db.RevokeRunnerParams{OrgID: orgID, ID: id, Now: &now})
	if err == nil && n == 0 {
		return fmt.Errorf("revoke runner: %w", domain.ErrNotFound)
	}
	return mapErr("revoke runner", err)
}

// TouchRunner records runner activity (throttled to once a minute).
func (s *Store) TouchRunner(ctx context.Context, orgID, id string, now time.Time) error {
	return mapErr("touch runner", s.q(ctx).TouchRunner(ctx, db.TouchRunnerParams{OrgID: orgID, ID: id, Now: &now}))
}
