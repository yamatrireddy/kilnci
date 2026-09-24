// SPDX-License-Identifier: Apache-2.0

//go:build integration

package store

import (
	"context"
	"errors"
)

// TryTamperAuditLog attempts an UPDATE and a DELETE on audit_events and
// returns nil only if either succeeded. Test-only: it proves the append-only
// trigger holds. The SQL is constant (never built from input).
func (s *Store) TryTamperAuditLog(ctx context.Context) error {
	_, updErr := s.pool.Exec(ctx, "UPDATE audit_events SET action = 'tampered'")
	_, delErr := s.pool.Exec(ctx, "DELETE FROM audit_events")
	if updErr != nil && delErr != nil {
		return errors.Join(updErr, delErr)
	}
	return nil
}
