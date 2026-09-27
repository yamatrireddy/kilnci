// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

const (
	// DefaultDEKCacheTTL bounds how long a plaintext DEK stays in memory
	// (ADR-0009 §1).
	DefaultDEKCacheTTL = 5 * time.Minute
	maxCachedDEKs      = 1024
)

// Keyring creates and unwraps org DEKs through a KeyWrapper, caching
// plaintext DEKs briefly so leases do not call the KEK provider every time.
// Secret values are never cached. It is safe for concurrent use.
type Keyring struct {
	wrapper KeyWrapper
	ttl     time.Duration
	now     func() time.Time

	mu    sync.Mutex
	cache map[cacheKey]cachedDEK
}

// cacheKey includes a hash of the wrapped key, so a rewrapped or replaced
// DEK row never hits a stale entry.
type cacheKey struct {
	orgID   string
	version int32
	wrapped [sha256.Size]byte
}

type cachedDEK struct {
	dek     []byte
	expires time.Time
}

// NewKeyring returns a Keyring over w. A ttl of zero means
// DefaultDEKCacheTTL; a negative ttl disables caching.
func NewKeyring(w KeyWrapper, ttl time.Duration) *Keyring {
	if ttl == 0 {
		ttl = DefaultDEKCacheTTL
	}
	return &Keyring{wrapper: w, ttl: ttl, now: time.Now, cache: map[cacheKey]cachedDEK{}}
}

// Wrapper returns the underlying KeyWrapper, for rotation.
func (k *Keyring) Wrapper() KeyWrapper { return k.wrapper }

// NewDataKey generates a DEK for orgID and wraps it. The caller stores the
// wrapped form and uses the plaintext only for the current operation.
func (k *Keyring) NewDataKey(ctx context.Context, orgID string) ([]byte, WrappedKey, error) {
	dek, err := NewDEK()
	if err != nil {
		return nil, WrappedKey{}, err
	}
	wk, err := k.wrapper.Wrap(ctx, orgID, dek)
	if err != nil {
		clear(dek)
		return nil, WrappedKey{}, fmt.Errorf("wrap data key: %w", err)
	}
	return dek, wk, nil
}

// DataKey returns the plaintext of an org's wrapped DEK. The returned slice
// is the caller's own copy.
func (k *Keyring) DataKey(ctx context.Context, orgID string, version int32, wk WrappedKey) ([]byte, error) {
	ck := cacheKey{orgID: orgID, version: version, wrapped: sha256.Sum256(append([]byte(wk.KeyID+"\x00"), wk.Ciphertext...))}
	if k.ttl > 0 {
		k.mu.Lock()
		e, ok := k.cache[ck]
		if ok && k.now().Before(e.expires) {
			out := append([]byte(nil), e.dek...)
			k.mu.Unlock()
			return out, nil
		}
		k.mu.Unlock()
	}
	dek, err := k.wrapper.Unwrap(ctx, orgID, wk)
	if err != nil {
		return nil, fmt.Errorf("unwrap data key: %w", err)
	}
	if k.ttl > 0 {
		k.put(ck, dek)
	}
	return dek, nil
}

func (k *Keyring) put(ck cacheKey, dek []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if len(k.cache) >= maxCachedDEKs {
		for key, e := range k.cache {
			if !now.Before(e.expires) {
				clear(e.dek)
				delete(k.cache, key)
			}
		}
		if len(k.cache) >= maxCachedDEKs {
			k.flushLocked()
		}
	}
	k.cache[ck] = cachedDEK{dek: append([]byte(nil), dek...), expires: now.Add(k.ttl)}
}

// Flush drops every cached DEK, e.g. after rotation.
func (k *Keyring) Flush() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.flushLocked()
}

func (k *Keyring) flushLocked() {
	for key, e := range k.cache {
		clear(e.dek)
		delete(k.cache, key)
	}
}
