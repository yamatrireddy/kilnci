// SPDX-License-Identifier: Apache-2.0

package objstore

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
)

func TestValidKey(t *testing.T) {
	good := []string{"orgs/01abc/runs/02def/jobs/03ghi/00000001", "a", "a-b_c/d"}
	bad := []string{"", "/abs", "../x", "a/../b", "a//b", "a/", "A/b", "a/b.txt", "a\\b", "a/./b", "a b", "a/\x00"}
	for _, k := range good {
		if !ValidKey(k) {
			t.Errorf("ValidKey(%q) = false", k)
		}
	}
	for _, k := range bad {
		if ValidKey(k) {
			t.Errorf("ValidKey(%q) = true", k)
		}
	}
}

func TestFS_PutGetReplace(t *testing.T) {
	ctx := context.Background()
	s, err := NewFS(filepath.Join(t.TempDir(), "logs"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "orgs/o1/jobs/j1/0", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "orgs/o1/jobs/j1/0", []byte("world")); err != nil {
		t.Fatal(err)
	}
	r, err := s.Get(ctx, "orgs/o1/jobs/j1/0")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	_ = r.Close()
	if string(b) != "world" {
		t.Fatalf("got %q", b)
	}
	if _, err := s.Get(ctx, "orgs/o1/jobs/j1/1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v", err)
	}
	for _, k := range []string{"../escape", "/etc/passwd", "a/../../b"} {
		if err := s.Put(ctx, k, nil); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Put(%q) = %v", k, err)
		}
		if _, err := s.Get(ctx, k); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Get(%q) = %v", k, err)
		}
	}
}

func TestNewS3_RequiresHardenedTransport(t *testing.T) {
	if _, err := NewS3(S3Options{Endpoint: "s3.example.com", Bucket: "b"}); err == nil {
		t.Fatal("S3 store built without a platform/httpclient transport")
	}
}
