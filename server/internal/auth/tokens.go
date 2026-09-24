// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// Token prefixes make leaked credentials recognizable to secret scanners
// (security-standards §3) and let the authenticator route a bearer token to
// the right lookup without trying each table.
const (
	PrefixAPIToken     = "kiln_pat_"
	PrefixAccessToken  = "kiln_at_"
	PrefixRefreshToken = "kiln_rt_"
	PrefixSession      = "kiln_sess_"
	PrefixDesktopCode  = "kiln_code_"
)

const secretBytes = 32 // 256 bits

// newSecret returns prefix + 256 random bits (base64url) and its SHA-256 hash.
func newSecret(prefix string) (token string, hash []byte) {
	b := make([]byte, secretBytes)
	// crypto/rand.Read never returns an error on supported platforms (Go 1.24+).
	_, _ = rand.Read(b)
	token = prefix + base64.RawURLEncoding.EncodeToString(b)
	return token, hashToken(token)
}

// randomString returns 256 random bits, base64url encoded (43 characters).
func randomString() string {
	b := make([]byte, secretBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken is the at-rest form of a high-entropy token. A fast hash is
// appropriate because the input has 256 bits of entropy (no password
// stretching is needed) and lookups happen on every request.
func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// wellFormed reports whether token has the prefix and a 43-char base64url body.
func wellFormed(token, prefix string) bool {
	body, ok := strings.CutPrefix(token, prefix)
	if !ok || len(body) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(body)
	return err == nil
}

// pkceS256 is the RFC 7636 S256 code challenge of verifier.
func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// csrfToken derives the synchronizer token for a session. Only a holder of
// the HttpOnly session cookie can compute it, so it needs no storage.
func csrfToken(sessionToken string) string {
	m := hmac.New(sha256.New, []byte(sessionToken))
	m.Write([]byte("kiln-csrf-v1"))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// equalConstantTime compares two strings without leaking where they differ.
func equalConstantTime(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
