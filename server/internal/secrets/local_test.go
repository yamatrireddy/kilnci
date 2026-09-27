// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestLocalWrapper_WrapUnwrap(t *testing.T) {
	ctx := context.Background()
	kek := testKey(t)
	w, err := NewLocalWrapper(kek, nil)
	if err != nil {
		t.Fatal(err)
	}
	dek := testKey(t)
	wk, err := w.Wrap(ctx, "org1", dek)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(wk.KeyID, "local:") || strings.Contains(wk.KeyID, hex.EncodeToString(kek[:8])) {
		t.Fatalf("key ID %q must be a fingerprint, not key material", wk.KeyID)
	}
	if bytes.Contains(wk.Ciphertext, dek) {
		t.Fatal("wrapped key contains the plaintext DEK")
	}
	got, err := w.Unwrap(ctx, "org1", wk)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap = %v, %v", got, err)
	}
	// A DEK wrapped for one org does not unwrap as another's (T-62).
	if _, err := w.Unwrap(ctx, "org2", wk); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("other org: err = %v, want ErrDecrypt", err)
	}
	if _, err := w.Wrap(ctx, "org1", dek[:16]); err == nil {
		t.Fatal("short DEK wrapped")
	}
	if _, err := w.Wrap(ctx, "", dek); err == nil {
		t.Fatal("DEK wrapped without an org")
	}
	if _, err := w.Unwrap(ctx, "", wk); err == nil {
		t.Fatal("DEK unwrapped without an org")
	}
}

func TestLocalWrapper_Rotation(t *testing.T) {
	ctx := context.Background()
	oldKEK, newKEK := testKey(t), testKey(t)
	old, _ := NewLocalWrapper(oldKEK, nil)
	dek := testKey(t)
	wk, _ := old.Wrap(ctx, "org1", dek)

	// Without the previous key, the old DEK is unknown.
	bare, _ := NewLocalWrapper(newKEK, nil)
	if _, err := bare.Unwrap(ctx, "org1", wk); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}

	rotating, err := NewLocalWrapper(newKEK, oldKEK)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rotating.Unwrap(ctx, "org1", wk); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap with previous key = %v", err)
	}
	re, err := rotating.Rewrap(ctx, "org1", wk)
	if err != nil {
		t.Fatal(err)
	}
	if re.KeyID == wk.KeyID {
		t.Fatal("rewrap kept the old key ID")
	}
	if got, err := bare.Unwrap(ctx, "org1", re); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("rewrapped DEK does not open under the new key alone: %v", err)
	}
	// Rewrapping an already-current DEK is a no-op.
	again, err := rotating.Rewrap(ctx, "org1", re)
	if err != nil || !bytes.Equal(again.Ciphertext, re.Ciphertext) {
		t.Fatalf("rewrap of current DEK changed it: %v", err)
	}
	// Rewrap binds to the org too.
	if _, err := rotating.Rewrap(ctx, "org2", wk); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("rewrap for other org: err = %v, want ErrDecrypt", err)
	}
}

func TestNewLocalWrapper_RejectsBadKeys(t *testing.T) {
	if _, err := NewLocalWrapper(make([]byte, 16), nil); err == nil {
		t.Fatal("16-byte master key accepted")
	}
	if _, err := NewLocalWrapper(testKey(t), make([]byte, 8)); err == nil {
		t.Fatal("8-byte previous key accepted")
	}
	// The same key as current and previous is harmless.
	k := testKey(t)
	w, err := NewLocalWrapper(k, k)
	if err != nil || w.previous != nil {
		t.Fatalf("identical previous key: %v, previous=%v", err, w.previous)
	}
}

// The key ID and wrapping key are HKDF subkeys, not the master key itself:
// a known-answer test pins the derivation so it cannot drift silently.
func TestLocalKey_DerivationKnownAnswer(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, KeySize)
	k, err := newLocalKey(master)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k.key, master) {
		t.Fatal("wrapping key is the master key")
	}
	if k.id != wantLocalKeyID {
		t.Fatalf("key ID = %q, want %q", k.id, wantLocalKeyID)
	}
}

const wantLocalKeyID = "local:e313d524fcdf09e9"
