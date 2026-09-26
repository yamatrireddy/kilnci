// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package identity

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkStateDirAccess requires the state directory to be owned by the
// effective user and closed to group and others, so no other local user
// can read the private key or swap files in the directory.
func checkStateDirAccess(dir string, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("state dir %s: cannot determine its owner", dir)
	}
	if int64(st.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("state dir %s is owned by uid %d, not by this user (uid %d)", dir, st.Uid, os.Geteuid())
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("state dir %s has mode %#o; it must not be accessible to group or others (chmod 700 it)", dir, perm)
	}
	return nil
}
