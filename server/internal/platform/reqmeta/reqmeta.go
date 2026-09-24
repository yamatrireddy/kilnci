// SPDX-License-Identifier: Apache-2.0

// Package reqmeta carries transport-derived request metadata (client IP, user
// agent) through the context so services can record it in audit events
// without depending on net/http.
package reqmeta

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Meta is request metadata.
type Meta struct {
	ClientIP  string
	UserAgent string
	// RateKey groups addresses for rate limiting (IPv6 by /64).
	RateKey string
}

type key struct{}

const maxUserAgent = 256

// With returns ctx carrying m. The user agent is truncated and stripped of
// control characters because it is attacker-controlled.
func With(ctx context.Context, m Meta) context.Context {
	m.UserAgent = sanitize(m.UserAgent)
	return context.WithValue(ctx, key{}, m)
}

// From returns the metadata in ctx (zero value if none).
func From(ctx context.Context) Meta {
	m, _ := ctx.Value(key{}).(Meta)
	return m
}

// sanitize returns valid UTF-8 without control characters, at most
// maxUserAgent bytes, cut on a rune boundary (a split rune would make the
// database reject the audit row, silently dropping the event).
func sanitize(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	if len(s) <= maxUserAgent {
		return s
	}
	cut := maxUserAgent
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
