// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type countingWrapper struct {
	KeyWrapper
	unwraps atomic.Int32
	fail    bool
}

func (c *countingWrapper) Unwrap(ctx context.Context, orgID string, w WrappedKey) ([]byte, error) {
	c.unwraps.Add(1)
	if c.fail {
		return nil, errors.New("provider down")
	}
	return c.KeyWrapper.Unwrap(ctx, orgID, w)
}

func newTestKeyring(t *testing.T, ttl time.Duration) (*Keyring, *countingWrapper, *time.Time) {
	t.Helper()
	lw, err := NewLocalWrapper(testKey(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	cw := &countingWrapper{KeyWrapper: lw}
	k := NewKeyring(cw, ttl)
	now := time.Unix(1_000_000, 0)
	k.now = func() time.Time { return now }
	return k, cw, &now
}

func TestKeyring_CachesBrieflyAndReturnsCopies(t *testing.T) {
	ctx := context.Background()
	k, cw, now := newTestKeyring(t, time.Minute)
	dek, wk, err := k.NewDataKey(ctx, "org1")
	if err != nil {
		t.Fatal(err)
	}
	a, err := k.DataKey(ctx, "org1", 1, wk)
	if err != nil || !bytes.Equal(a, dek) {
		t.Fatalf("DataKey: %v", err)
	}
	clear(a) // the caller's copy is theirs to wipe
	b, _ := k.DataKey(ctx, "org1", 1, wk)
	if !bytes.Equal(b, dek) {
		t.Fatal("wiping a returned DEK corrupted the cache")
	}
	if n := cw.unwraps.Load(); n != 1 {
		t.Fatalf("unwraps = %d, want 1 (cached)", n)
	}
	*now = now.Add(time.Minute)
	if _, err := k.DataKey(ctx, "org1", 1, wk); err != nil {
		t.Fatal(err)
	}
	if n := cw.unwraps.Load(); n != 2 {
		t.Fatalf("unwraps = %d, want 2 (expired)", n)
	}
	// Another org or version is a separate entry, and still bound to its org.
	if _, err := k.DataKey(ctx, "org2", 1, wk); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("other org: err = %v, want ErrDecrypt", err)
	}
	k.Flush()
	if _, err := k.DataKey(ctx, "org1", 1, wk); err != nil {
		t.Fatal(err)
	}
	if n := cw.unwraps.Load(); n != 4 {
		t.Fatalf("unwraps = %d, want 4 after flush", n)
	}
}

func TestKeyring_DisabledCacheAndErrors(t *testing.T) {
	ctx := context.Background()
	k, cw, _ := newTestKeyring(t, -1)
	_, wk, _ := k.NewDataKey(ctx, "org1")
	for range 3 {
		if _, err := k.DataKey(ctx, "org1", 1, wk); err != nil {
			t.Fatal(err)
		}
	}
	if n := cw.unwraps.Load(); n != 3 {
		t.Fatalf("unwraps = %d, want 3 with caching off", n)
	}
	cw.fail = true
	if _, err := k.DataKey(ctx, "org1", 1, wk); err == nil {
		t.Fatal("provider failure not reported")
	}
}

func TestKeyring_BoundedCache(t *testing.T) {
	ctx := context.Background()
	k, _, _ := newTestKeyring(t, time.Hour)
	_, wk, _ := k.NewDataKey(ctx, "org1")
	for v := range int32(maxCachedDEKs + 10) {
		// Different versions miss the cache but reuse one wrapped key.
		k.put(cacheKey{orgID: "org1", version: v}, make([]byte, KeySize))
	}
	if _, err := k.DataKey(ctx, "org1", 1, wk); err != nil {
		t.Fatal(err)
	}
	k.mu.Lock()
	n := len(k.cache)
	k.mu.Unlock()
	if n > maxCachedDEKs {
		t.Fatalf("cache holds %d entries, max %d", n, maxCachedDEKs)
	}
}
