// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/moby/moby/client"
)

// DefaultDiskLimitBytes caps each job container's writable layer and the
// job's workspace volume unless the operator sets another limit.
const DefaultDiskLimitBytes int64 = 10 << 30

// MinDiskLimitBytes is the smallest limit ParseDiskLimit accepts; smaller
// limits would fail every job.
const MinDiskLimitBytes int64 = 64 << 20

// errDiskLimitUnsupported means the Docker daemon cannot enforce the job
// disk limit. Jobs then fail rather than run without one.
var errDiskLimitUnsupported = errors.New("docker storage cannot enforce the job disk limit")

// Preflight checks, before any job is accepted, that the Docker daemon can
// enforce the configured limits, so a misconfigured runner fails at startup
// with a clear error rather than failing every job.
func (e *Executor) Preflight(ctx context.Context) error {
	return e.checkDiskLimitSupport(ctx)
}

// checkDiskLimitSupport verifies that the daemon enforces size limits.
//
// The limit is applied as HostConfig.StorageOpt size (container writable
// layer) and the local volume driver's size option (workspace). Both need
// the overlay2 storage driver with the Docker data root on XFS mounted with
// pquota: dockerd rejects them on other filesystems, which fails the job
// closed. The containerd image store, however, silently ignores StorageOpt,
// so the storage driver is checked here instead of trusting the daemon.
func (e *Executor) checkDiskLimitSupport(ctx context.Context) error {
	if e.opts.DisableDiskLimit {
		return nil
	}
	res, err := e.api.Info(ctx, client.InfoOptions{})
	if err != nil {
		return fmt.Errorf("docker info: %w", err)
	}
	info := res.Info
	if info.Driver != "overlay2" {
		return fmt.Errorf("%w: storage driver is %q, need overlay2 on XFS with pquota "+
			"(or run with --job-disk-limit=off to accept unlimited job disk use)", errDiskLimitUnsupported, info.Driver)
	}
	for _, kv := range info.DriverStatus {
		if kv[0] == "Backing Filesystem" && kv[1] != "xfs" {
			return fmt.Errorf("%w: overlay2 backing filesystem is %q, need XFS with pquota "+
				"(or run with --job-disk-limit=off to accept unlimited job disk use)", errDiskLimitUnsupported, kv[1])
		}
	}
	return nil
}

// storageOpt returns the per-container storage options enforcing the limit.
func (e *Executor) storageOpt() map[string]string {
	if e.opts.DisableDiskLimit {
		return nil
	}
	return map[string]string{"size": strconv.FormatInt(e.opts.DiskLimitBytes, 10)}
}

// volumeOpts returns the workspace volume's driver options enforcing the
// limit (local driver, XFS project quota).
func (e *Executor) volumeOpts() map[string]string {
	return e.storageOpt()
}

// ParseDiskLimit parses the --job-disk-limit flag: "off" disables the
// limit; otherwise a positive size in bytes with an optional binary unit
// suffix (k, m, g, t; optionally followed by "i" and/or "b", any case), so
// "10G", "10GiB" and "10737418240" are equal.
func ParseDiskLimit(s string) (limit int64, disabled bool, err error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "off" {
		return 0, true, nil
	}
	num := strings.TrimRight(s, "kmgtib")
	unit := strings.TrimSuffix(s[len(num):], "b")
	if unit != "" && unit != "i" {
		unit = strings.TrimSuffix(unit, "i") // "gi" -> "g"; a bare "i" stays invalid
	}
	shift := map[string]uint{"": 0, "k": 10, "m": 20, "g": 30, "t": 40}
	sh, ok := shift[unit]
	n, perr := strconv.ParseUint(num, 10, 63)
	if !ok || perr != nil || n == 0 || n > (1<<62)>>sh || int64(n)<<sh < MinDiskLimitBytes {
		return 0, false, fmt.Errorf("invalid disk limit %q: want a size of at least 64M such as 10G, or off", s)
	}
	return int64(n) << sh, false, nil
}
