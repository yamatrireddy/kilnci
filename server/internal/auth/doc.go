// SPDX-License-Identifier: Apache-2.0

// Package auth implements authentication for Kiln (ADR-0003): the OIDC login
// flows for web and desktop, browser sessions with CSRF protection, desktop
// access/refresh tokens with rotation and reuse detection, personal API
// tokens, and the request Authenticator used by the HTTP router.
//
// Every credential is 256 bits from crypto/rand with a recognizable prefix,
// and only its SHA-256 hash is stored. Comparisons of client-supplied secrets
// with expected values are constant-time.
package auth
