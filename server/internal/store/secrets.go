// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/store/db"
)

// DataKey is an org's wrapped data-encryption key (ADR-0009 §1).
type DataKey struct {
	OrgID     string
	Version   int32
	KeyID     string
	Wrapped   []byte
	Active    bool
	CreatedAt time.Time
}

// SealedSecret is a secret row as written: metadata plus the ciphertext and
// the DEK version that sealed it.
type SealedSecret struct {
	Secret     domain.Secret
	DEKVersion int32
	Ciphertext []byte
}

// LockedSecret is a secret's metadata plus the DEK version, read under a
// row lock for replacement.
type LockedSecret struct {
	Secret     domain.Secret
	DEKVersion int32
}

func secretFrom(id, orgID string, projectID *string, name string, valueVersion int64, masked bool, branches []string,
	allowUnprotected, allProjects bool, projectIDs []string, createdBy, updatedBy *string, createdAt, updatedAt time.Time,
) domain.Secret {
	return domain.Secret{
		ID: id, OrgID: orgID, ProjectID: deref(projectID), Name: name, ValueVersion: valueVersion, Masked: masked,
		Branches: branches, AllowUnprotected: allowUnprotected, AllProjects: allProjects, ProjectIDs: projectIDs,
		CreatedBy: deref(createdBy), UpdatedBy: deref(updatedBy), CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
}

// GetActiveDataKey returns an org's active DEK; domain.ErrNotFound if the
// org has none yet.
func (s *Store) GetActiveDataKey(ctx context.Context, orgID string) (DataKey, error) {
	r, err := s.q(ctx).GetActiveSecretDataKey(ctx, orgID)
	return DataKey(r), mapErr("get active data key", err)
}

// GetDataKey returns one version of an org's DEK.
func (s *Store) GetDataKey(ctx context.Context, orgID string, version int32) (DataKey, error) {
	r, err := s.q(ctx).GetSecretDataKey(ctx, db.GetSecretDataKeyParams{OrgID: orgID, Version: version})
	return DataKey(r), mapErr("get data key", err)
}

// InsertFirstDataKey stores an org's first DEK (version 1, active). It
// reports false when another writer created it first.
func (s *Store) InsertFirstDataKey(ctx context.Context, k DataKey) (bool, error) {
	n, err := s.q(ctx).InsertFirstSecretDataKey(ctx, db.InsertFirstSecretDataKeyParams{
		OrgID: k.OrgID, KeyID: k.KeyID, Wrapped: k.Wrapped, CreatedAt: k.CreatedAt,
	})
	return n == 1, mapErr("insert data key", err)
}

// CountDataKeysNotWrappedBy counts DEKs (across all orgs) whose key ID is
// not in keyIDs, for the startup check that every DEK can be unwrapped.
func (s *Store) CountDataKeysNotWrappedBy(ctx context.Context, keyIDs []string) (int64, error) {
	n, err := s.q(ctx).CountSecretDataKeysNotWrappedBy(ctx, keyIDs)
	return n, mapErr("count data keys", err)
}

// CountSecrets counts the secrets in a scope (projectID "" = org scope).
func (s *Store) CountSecrets(ctx context.Context, orgID, projectID string) (int64, error) {
	n, err := s.q(ctx).CountSecretsInScope(ctx, db.CountSecretsInScopeParams{OrgID: orgID, ProjectID: nilIfEmpty(projectID)})
	return n, mapErr("count secrets", err)
}

// LockSecretScope serializes secret creation in a scope (projectID "" =
// org scope) until the transaction ends. It must be called inside InTx.
func (s *Store) LockSecretScope(ctx context.Context, orgID, projectID string) error {
	return mapErr("lock secret scope", s.q(ctx).LockSecretScope(ctx, orgID+"/"+projectID))
}

// LockSecret reads a secret by name for update.
func (s *Store) LockSecret(ctx context.Context, orgID, projectID, name string) (LockedSecret, error) {
	r, err := s.q(ctx).LockSecret(ctx, db.LockSecretParams{OrgID: orgID, ProjectID: nilIfEmpty(projectID), Name: name})
	if err != nil {
		return LockedSecret{}, mapErr("lock secret", err)
	}
	return LockedSecret{
		Secret: secretFrom(r.ID, r.OrgID, r.ProjectID, r.Name, r.ValueVersion, r.Masked, r.Branches, r.AllowUnprotected,
			r.AllProjects, r.ProjectIds, r.CreatedBy, r.UpdatedBy, r.CreatedAt, r.UpdatedAt),
		DEKVersion: r.DekVersion,
	}, nil
}

// InsertSecret creates a secret; domain.ErrConflict if the name is taken.
func (s *Store) InsertSecret(ctx context.Context, w SealedSecret) error {
	m := w.Secret
	return mapErr("insert secret", s.q(ctx).InsertSecret(ctx, db.InsertSecretParams{
		ID: m.ID, OrgID: m.OrgID, ProjectID: nilIfEmpty(m.ProjectID), Name: m.Name, DekVersion: w.DEKVersion,
		ValueVersion: m.ValueVersion, Ciphertext: w.Ciphertext, Masked: m.Masked, Branches: nonNil(m.Branches),
		AllowUnprotected: m.AllowUnprotected, AllProjects: m.AllProjects, ProjectIds: nonNil(m.ProjectIDs),
		CreatedBy: nilIfEmpty(m.CreatedBy), UpdatedBy: nilIfEmpty(m.UpdatedBy), CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
	}))
}

// UpdateSecret replaces a secret's value and restrictions. The new value
// version must be exactly one more than the stored one, so concurrent
// writers cannot both succeed.
func (s *Store) UpdateSecret(ctx context.Context, w SealedSecret) error {
	m := w.Secret
	n, err := s.q(ctx).UpdateSecret(ctx, db.UpdateSecretParams{
		DekVersion: w.DEKVersion, ValueVersion: m.ValueVersion, Ciphertext: w.Ciphertext, Masked: m.Masked,
		Branches: nonNil(m.Branches), AllowUnprotected: m.AllowUnprotected, AllProjects: m.AllProjects,
		ProjectIds: nonNil(m.ProjectIDs), UpdatedBy: nilIfEmpty(m.UpdatedBy), UpdatedAt: m.UpdatedAt, OrgID: m.OrgID, ID: m.ID,
	})
	if err == nil && n == 0 {
		return fmt.Errorf("update secret: %w", domain.ErrConflict)
	}
	return mapErr("update secret", err)
}

// ListSecrets returns a page of a scope's secrets ordered by ID.
func (s *Store) ListSecrets(ctx context.Context, orgID, projectID, afterID string, limit int32) ([]domain.Secret, error) {
	rows, err := s.q(ctx).ListSecrets(ctx, db.ListSecretsParams{OrgID: orgID, ProjectID: nilIfEmpty(projectID), AfterID: afterID, MaxRows: limit})
	if err != nil {
		return nil, mapErr("list secrets", err)
	}
	out := make([]domain.Secret, len(rows))
	for i, r := range rows {
		out[i] = secretFrom(r.ID, r.OrgID, r.ProjectID, r.Name, r.ValueVersion, r.Masked, r.Branches, r.AllowUnprotected,
			r.AllProjects, r.ProjectIds, r.CreatedBy, r.UpdatedBy, r.CreatedAt, r.UpdatedAt)
	}
	return out, nil
}

// DeleteSecret deletes a secret by name; domain.ErrNotFound if absent.
func (s *Store) DeleteSecret(ctx context.Context, orgID, projectID, name string) error {
	n, err := s.q(ctx).DeleteSecret(ctx, db.DeleteSecretParams{OrgID: orgID, ProjectID: nilIfEmpty(projectID), Name: name})
	if err == nil && n == 0 {
		return fmt.Errorf("delete secret: %w", domain.ErrNotFound)
	}
	return mapErr("delete secret", err)
}

// ProjectSlugsByID maps project IDs of an org to slugs; unknown IDs (for
// example deleted projects) are absent from the result.
func (s *Store) ProjectSlugsByID(ctx context.Context, orgID string, projectIDs []string) (map[string]string, error) {
	rows, err := s.q(ctx).GetProjectSlugsByID(ctx, db.GetProjectSlugsByIDParams{OrgID: orgID, Ids: nonNil(projectIDs)})
	if err != nil {
		return nil, mapErr("project slugs", err)
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.ID] = r.Slug
	}
	return out, nil
}

// ProjectIDsBySlug maps project slugs of an org to IDs; unknown slugs are
// absent from the result.
func (s *Store) ProjectIDsBySlug(ctx context.Context, orgID string, slugs []string) (map[string]string, error) {
	rows, err := s.q(ctx).GetProjectIDsBySlug(ctx, db.GetProjectIDsBySlugParams{OrgID: orgID, Slugs: nonNil(slugs)})
	if err != nil {
		return nil, mapErr("project ids", err)
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.Slug] = r.ID
	}
	return out, nil
}

// GetSealedSecret returns a secret with its ciphertext, for decryption when
// building a lease. It is never exposed through the API.
func (s *Store) GetSealedSecret(ctx context.Context, orgID, projectID, name string) (SealedSecret, error) {
	r, err := s.q(ctx).GetSealedSecret(ctx, db.GetSealedSecretParams{OrgID: orgID, ProjectID: nilIfEmpty(projectID), Name: name})
	if err != nil {
		return SealedSecret{}, mapErr("get sealed secret", err)
	}
	return SealedSecret{
		Secret: secretFrom(r.ID, r.OrgID, r.ProjectID, r.Name, r.ValueVersion, r.Masked, r.Branches, r.AllowUnprotected,
			r.AllProjects, r.ProjectIds, r.CreatedBy, r.UpdatedBy, r.CreatedAt, r.UpdatedAt),
		DEKVersion: r.DekVersion, Ciphertext: r.Ciphertext,
	}, nil
}
