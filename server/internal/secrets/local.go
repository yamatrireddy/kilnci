// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrUnknownKey is returned (wrapped) when a wrapped DEK names a KEK the
// provider does not hold, e.g. after the previous master key was removed
// too early.
var ErrUnknownKey = errors.New("data key was wrapped by an unknown key-encryption key")

// LocalWrapper wraps DEKs with AES-256-GCM under a master key held in
// memory (ADR-0009 §2, provider "local").
type LocalWrapper struct {
	current  localKey
	previous *localKey
}

// localKey holds subkeys derived from a master key with HKDF-SHA256, so the
// master key itself is never used directly by two primitives.
type localKey struct {
	id  string
	key []byte // AES-256-GCM wrapping key
}

func newLocalKey(k []byte) (localKey, error) {
	if len(k) != KeySize {
		return localKey{}, fmt.Errorf("master key must be %d bytes", KeySize)
	}
	wrapKey, err := hkdf.Key(sha256.New, k, nil, "kiln-kek-wrap-v1", KeySize)
	if err != nil {
		return localKey{}, fmt.Errorf("derive wrapping key: %w", err)
	}
	idKey, err := hkdf.Key(sha256.New, k, nil, "kiln-kek-id-v1", KeySize)
	if err != nil {
		return localKey{}, fmt.Errorf("derive key ID: %w", err)
	}
	return localKey{id: "local:" + hex.EncodeToString(idKey[:8]), key: wrapKey}, nil
}

// NewLocalWrapper returns a wrapper for the 32-byte master key current.
// previous, if non-nil, is used only to unwrap DEKs during rotation.
func NewLocalWrapper(current, previous []byte) (*LocalWrapper, error) {
	c, err := newLocalKey(current)
	if err != nil {
		return nil, err
	}
	w := &LocalWrapper{current: c}
	if previous != nil {
		p, err := newLocalKey(previous)
		if err != nil {
			return nil, fmt.Errorf("previous %w", err)
		}
		if p.id != c.id {
			w.previous = &p
		}
	}
	return w, nil
}

// dekAAD binds a wrapped DEK to its org.
func dekAAD(orgID string) []byte {
	return appendNetstring([]byte("kiln-dek-v1|"), orgID)
}

// Wrap implements KeyWrapper.
func (w *LocalWrapper) Wrap(_ context.Context, orgID string, dek []byte) (WrappedKey, error) {
	if orgID == "" {
		return WrappedKey{}, errors.New("wrap data key: org ID is required")
	}
	if len(dek) != KeySize {
		return WrappedKey{}, fmt.Errorf("data key must be %d bytes", KeySize)
	}
	ct, err := seal(w.current.key, dek, dekAAD(orgID))
	if err != nil {
		return WrappedKey{}, fmt.Errorf("wrap data key: %w", err)
	}
	return WrappedKey{KeyID: w.current.id, Ciphertext: ct}, nil
}

// Unwrap implements KeyWrapper.
func (w *LocalWrapper) Unwrap(_ context.Context, orgID string, wk WrappedKey) ([]byte, error) {
	if orgID == "" {
		return nil, errors.New("unwrap data key: org ID is required")
	}
	k, err := w.keyFor(wk.KeyID)
	if err != nil {
		return nil, err
	}
	dek, err := open(k, wk.Ciphertext, dekAAD(orgID))
	if err != nil {
		return nil, fmt.Errorf("unwrap data key: %w", err)
	}
	if len(dek) != KeySize {
		return nil, fmt.Errorf("unwrap data key: %w", ErrDecrypt)
	}
	return dek, nil
}

// Rewrap implements KeyWrapper.
func (w *LocalWrapper) Rewrap(ctx context.Context, orgID string, wk WrappedKey) (WrappedKey, error) {
	if wk.KeyID == w.current.id {
		return wk, nil
	}
	dek, err := w.Unwrap(ctx, orgID, wk)
	if err != nil {
		return WrappedKey{}, err
	}
	defer clear(dek)
	return w.Wrap(ctx, orgID, dek)
}

func (w *LocalWrapper) keyFor(id string) ([]byte, error) {
	switch {
	case id == w.current.id:
		return w.current.key, nil
	case w.previous != nil && id == w.previous.id:
		return w.previous.key, nil
	default:
		return nil, ErrUnknownKey
	}
}
