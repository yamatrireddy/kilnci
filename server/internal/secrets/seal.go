// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
)

// KeySize is the size of every KEK and DEK: AES-256.
const KeySize = 32

// ErrDecrypt is returned (wrapped) when a ciphertext does not open: wrong
// key, wrong additional data, or tampering. It never says which.
var ErrDecrypt = errors.New("secret ciphertext does not open")

// sealVersion prefixes every sealed value so the format can change later.
const sealVersion byte = 1

// Scope kinds a secret can belong to.
const (
	ScopeOrg     = "org"
	ScopeProject = "project"
)

// AAD is the context a secret value is bound to. Opening a value under any
// other context fails (T-62).
type AAD struct {
	OrgID string
	// ScopeKind is ScopeOrg or ScopeProject; ScopeID is the org ID or the
	// project ID accordingly.
	ScopeKind string
	ScopeID   string
	Name      string
	// SecretID is the secret row's unique ID. A deleted and recreated
	// secret gets a new ID, so ciphertexts of the old one cannot be
	// restored into the new row even though its value version restarts.
	SecretID string
	// DEKVersion is the org data key version that sealed the value.
	DEKVersion int32
	// ValueVersion increases on every write of the secret, so an older
	// ciphertext of the same secret cannot be restored in place.
	ValueVersion int64
}

func (a AAD) validate() error {
	if a.OrgID == "" || a.ScopeID == "" || a.Name == "" || a.SecretID == "" || a.DEKVersion < 1 || a.ValueVersion < 1 ||
		(a.ScopeKind != ScopeOrg && a.ScopeKind != ScopeProject) {
		return errors.New("secret context is incomplete")
	}
	return nil
}

// bytes encodes the AAD unambiguously: a domain label, then each field as
// a netstring ("<len>:<bytes>,"), so no two distinct AADs share an encoding.
func (a AAD) bytes() []byte {
	b := []byte("kiln-secret-v1|")
	for _, f := range []string{a.OrgID, a.ScopeKind, a.ScopeID, a.Name, a.SecretID} {
		b = appendNetstring(b, f)
	}
	b = appendNetstring(b, strconv.FormatInt(int64(a.DEKVersion), 10))
	return appendNetstring(b, strconv.FormatInt(a.ValueVersion, 10))
}

func appendNetstring(b []byte, s string) []byte {
	b = strconv.AppendInt(b, int64(len(s)), 10)
	b = append(b, ':')
	b = append(b, s...)
	return append(b, ',')
}

// Seal encrypts plaintext under dek with AES-256-GCM and a fresh random
// nonce. The result is version || nonce || ciphertext+tag.
func Seal(dek, plaintext []byte, aad AAD) ([]byte, error) {
	if err := aad.validate(); err != nil {
		return nil, err
	}
	return seal(dek, plaintext, aad.bytes())
}

// Open reverses Seal. Any mismatch returns an error wrapping ErrDecrypt.
func Open(dek, sealed []byte, aad AAD) ([]byte, error) {
	if err := aad.validate(); err != nil {
		return nil, err
	}
	return open(dek, sealed, aad.bytes())
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return gcm, nil
}

func seal(key, plaintext, additional []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, sealVersion)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, additional), nil
}

func open(key, sealed, additional []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < 1+gcm.NonceSize()+gcm.Overhead() || sealed[0] != sealVersion {
		return nil, ErrDecrypt
	}
	nonce := sealed[1 : 1+gcm.NonceSize()]
	pt, err := gcm.Open(nil, nonce, sealed[1+gcm.NonceSize():], additional)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// NewDEK returns a fresh random data-encryption key.
func NewDEK() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("generate data key: %w", err)
	}
	return k, nil
}
