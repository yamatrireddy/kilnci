// SPDX-License-Identifier: Apache-2.0

//go:build windows

package identity

import "io/fs"

// checkStateDirAccess is a no-op on Windows: access is governed by ACLs,
// which Go's file modes do not reflect. Operators must restrict the state
// directory's ACL to the runner's account themselves.
func checkStateDirAccess(string, fs.FileInfo) error { return nil }
