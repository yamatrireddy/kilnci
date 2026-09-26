// SPDX-License-Identifier: Apache-2.0

// Package client is the kiln CLI's minimal HTTP client for the Kiln API
// (docs/api/openapi.yaml). It sends a bearer token, never follows redirects
// (so the token is only ever sent to the configured server), bounds every
// call with a timeout, and caps how much of a response it reads.
package client
