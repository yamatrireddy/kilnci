// SPDX-License-Identifier: Apache-2.0

// Package config resolves the kiln CLI's server URL and credentials from
// flags and the environment. It is the only CLI package that reads the
// environment (coding-standards §5), and it never includes a token in an
// error message.
package config
