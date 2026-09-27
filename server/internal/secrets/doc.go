// SPDX-License-Identifier: Apache-2.0

// Package secrets implements envelope encryption for pipeline secrets
// (ADR-0009; security-standards §7).
//
// A key-encryption key (KEK) held outside the database, by a KeyWrapper
// (a local master key or Vault Transit), wraps one data-encryption key (DEK)
// per org and version. Each secret value is sealed with AES-256-GCM under its
// org's DEK, with additional data binding the ciphertext to its org, scope,
// name, and DEK version, so a row cannot be moved or swapped (T-62).
//
// The package holds no plaintext value beyond the call that produced it and
// caches plaintext DEKs only briefly (Keyring). It uses only the standard
// library's crypto.
package secrets
