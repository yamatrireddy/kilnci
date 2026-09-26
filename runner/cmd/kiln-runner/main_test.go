// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestReadOperatorInput(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "input")
	if err := os.WriteFile(file, []byte("from-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		path  string
		stdin string
		want  string
	}{
		{"stdin", "-", "from-stdin", "from-stdin"},
		{"stdin capped at 256 bytes", "-", strings.Repeat("a", 300), strings.Repeat("a", 256)},
		{"file", file, "ignored", "from-file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readOperatorInput(tc.path, strings.NewReader(tc.stdin))
			if err != nil {
				t.Fatalf("readOperatorInput: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %d bytes, want %d", len(got), len(tc.want))
			}
		})
	}
}

func TestReadOperatorInput_Errors(t *testing.T) {
	sentinel := errors.New("boom")
	if _, err := readOperatorInput("-", errReader{sentinel}); !errors.Is(err, sentinel) {
		t.Fatalf("stdin error = %v, want wrapped sentinel", err)
	}
	if _, err := readOperatorInput(filepath.Join(t.TempDir(), "missing"), nil); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file error = %v, want ErrNotExist", err)
	}
}
