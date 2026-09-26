// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateDir_Rejected(t *testing.T) {
	ca := newTestCA(t)
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr string
	}{
		{
			name: "group and world readable",
			setup: func(t *testing.T) string {
				dir := filepath.Join(t.TempDir(), "state")
				mkdir(t, dir, 0o755)
				return dir
			},
			wantErr: "mode 0755",
		},
		{
			name: "group writable",
			setup: func(t *testing.T) string {
				dir := filepath.Join(t.TempDir(), "state")
				mkdir(t, dir, 0o720)
				return dir
			},
			wantErr: "mode 0720",
		},
		{
			name: "symlink to a private dir",
			setup: func(t *testing.T) string {
				base := t.TempDir()
				real := filepath.Join(base, "real")
				mkdir(t, real, 0o700)
				link := filepath.Join(base, "state")
				if err := os.Symlink(real, link); err != nil {
					t.Fatal(err)
				}
				return link
			},
			wantErr: "not a symlink",
		},
		{
			name: "a file",
			setup: func(t *testing.T) string {
				f := filepath.Join(t.TempDir(), "state")
				if err := os.WriteFile(f, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				return f
			},
			wantErr: "state dir",
		},
		{
			name: "owned by another user",
			setup: func(t *testing.T) string {
				if os.Geteuid() != 0 {
					t.Skip("needs root to chown")
				}
				dir := filepath.Join(t.TempDir(), "state")
				mkdir(t, dir, 0o700)
				if err := os.Chown(dir, 65534, 65534); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			wantErr: "owned by uid 65534",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setup(t)
			_, err := Register(t.Context(), ca, dir, "h:1", ca.pem, "kiln_rrt_good", "r", "1")
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Register = %v, want error containing %q", err, tt.wantErr)
			}
			if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_RejectsLoosenedStateDir(t *testing.T) {
	ca := newTestCA(t)
	id, dir := register(t, ca)
	_ = id.Close()
	setMode(t, dir, 0o750)
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "mode 0750") {
		t.Fatalf("Load = %v", err)
	}
}

func TestWriteFile_ReplacesStaleTempFile(t *testing.T) {
	ca := newTestCA(t)
	dir := filepath.Join(t.TempDir(), "state")
	mkdir(t, dir, 0o700)
	stale := filepath.Join(dir, keyFile+".tmp")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	setMode(t, stale, 0o644) // a leftover from an older version or umask
	id, err := Register(t.Context(), ca, dir, "h:1", ca.pem, "kiln_rrt_good", "r", "1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id.Close() }()
	fi, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %#o, want 0600", fi.Mode().Perm())
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale temp file left behind: %v", err)
	}
}

// mkdir creates dir with exactly mode, regardless of the umask.
func mkdir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	setMode(t, dir, mode)
}

// setMode gives a test fixture a deliberately loose mode.
func setMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
