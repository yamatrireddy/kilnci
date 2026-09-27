// SPDX-License-Identifier: Apache-2.0

package secrets

import "context"

// WrappedKey is a DEK encrypted by a KEK. KeyID names the KEK (or KEK
// version) that wrapped it, without revealing anything about the key.
type WrappedKey struct {
	KeyID      string
	Ciphertext []byte
}

// KeyWrapper wraps and unwraps DEKs with a key-encryption key held outside
// the database. Every call binds the DEK to orgID, so a DEK wrapped for one
// org cannot be unwrapped as another's.
type KeyWrapper interface {
	// Wrap encrypts dek under the current KEK.
	Wrap(ctx context.Context, orgID string, dek []byte) (WrappedKey, error)
	// Unwrap decrypts w, which may have been wrapped by a previous KEK the
	// provider still knows.
	Unwrap(ctx context.Context, orgID string, w WrappedKey) ([]byte, error)
	// Rewrap returns w wrapped under the current KEK (unchanged if it
	// already is), for KEK rotation.
	Rewrap(ctx context.Context, orgID string, w WrappedKey) (WrappedKey, error)
}
