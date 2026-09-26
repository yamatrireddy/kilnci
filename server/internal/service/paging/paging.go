// SPDX-License-Identifier: Apache-2.0

// Package paging implements the API's opaque cursor pagination for services:
// cursors are base64url-encoded ULIDs, limits are clamped to 1..100, and a
// page is fetched with limit+1 rows to know whether another page exists.
package paging

import (
	"encoding/base64"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
)

// Page is one page of results.
type Page[T any] struct {
	Items      []T
	NextCursor string
}

// Request selects a page. Cursor is opaque; Limit is clamped to 1..100.
type Request struct {
	Cursor string
	Limit  int
}

const (
	defaultLimit = 50
	maxLimit     = 100
)

// Parse returns the ID the cursor points at ("" for the first page) and the
// clamped limit. A malformed cursor is a validation error.
func (pr Request) Parse() (id string, limit int32, err error) {
	limit = defaultLimit
	if pr.Limit > 0 {
		limit = int32(min(pr.Limit, maxLimit)) //nolint:gosec // bounded above
	}
	if pr.Cursor == "" {
		return "", limit, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(pr.Cursor)
	if err != nil || !ids.Valid(string(b)) {
		return "", 0, domain.NewValidationError("cursor", "is not a valid cursor")
	}
	return string(b), limit, nil
}

// Build trims a limit+1 result to limit and computes the next cursor.
func Build[T any](items []T, limit int32, idOf func(T) string) Page[T] {
	if len(items) <= int(limit) {
		return Page[T]{Items: items}
	}
	items = items[:limit]
	return Page[T]{Items: items, NextCursor: base64.RawURLEncoding.EncodeToString([]byte(idOf(items[len(items)-1])))}
}
