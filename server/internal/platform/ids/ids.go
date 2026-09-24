// SPDX-License-Identifier: Apache-2.0

// Package ids generates and validates Kiln's opaque resource IDs.
//
// IDs are ULIDs: 48 bits of millisecond timestamp followed by 80 bits from
// crypto/rand, encoded as 26 characters of Crockford base32. They sort by
// creation time, which keeps B-tree inserts cheap, and are unguessable enough
// that enumeration is impractical. Authorization never relies on that, though:
// every lookup is still scoped by org and checked by authz.
package ids

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

const (
	alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// Length is the length of an encoded ID.
	Length = 26
)

// Generator creates IDs. Inject it (rather than calling a package function) so
// tests can supply a deterministic clock.
type Generator struct {
	now func() time.Time
}

// NewGenerator returns a Generator using now as its clock. A nil now uses time.Now.
func NewGenerator(now func() time.Time) *Generator {
	if now == nil {
		now = time.Now
	}
	return &Generator{now: now}
}

// New returns a fresh ID.
func (g *Generator) New() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(g.now().UnixMilli())<<16) //nolint:gosec // timestamps are positive
	// crypto/rand.Read never returns an error on supported platforms (Go 1.24+).
	_, _ = rand.Read(b[6:])
	return encode(b)
}

func encode(b [16]byte) string {
	// 128 bits -> 26 base32 chars; the first char carries only 3 bits.
	var out [Length]byte
	hi := binary.BigEndian.Uint64(b[:8])
	lo := binary.BigEndian.Uint64(b[8:])
	for i := Length - 1; i >= 0; i-- {
		out[i] = alphabet[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:])
}

// Valid reports whether s is a syntactically valid ID. Use it to reject
// malformed path parameters before they reach the store.
func Valid(s string) bool {
	if len(s) != Length || s[0] > '7' {
		return false
	}
	for i := range len(s) {
		if !isAlphabet(s[i]) {
			return false
		}
	}
	return true
}

func isAlphabet(c byte) bool {
	for i := range len(alphabet) {
		if alphabet[i] == c {
			return true
		}
	}
	return false
}
