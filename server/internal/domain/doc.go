// SPDX-License-Identifier: Apache-2.0

// Package domain holds Kiln's entities, value objects, and domain errors.
//
// It is the innermost layer: it imports only the standard library, performs no
// I/O, and knows nothing about HTTP, SQL, or configuration. depguard enforces
// this (see .golangci.yml).
package domain
