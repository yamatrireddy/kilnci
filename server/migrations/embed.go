// SPDX-License-Identifier: Apache-2.0

// Package migrations embeds the goose SQL migrations so the server binary can
// apply them at startup (single-binary mode, CLAUDE.md invariant 7).
package migrations

import "embed"

// FS holds every migration file.
//
//go:embed *.sql
var FS embed.FS
