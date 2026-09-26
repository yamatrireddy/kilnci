// SPDX-License-Identifier: Apache-2.0

// Package objstore stores immutable blobs (log chunks, later artifacts)
// outside PostgreSQL (invariant 4, ADR-0007).
//
// Keys are built by the server from its own IDs only; ValidKey rejects
// anything else (absolute paths, "..", unexpected characters) so a key can
// never escape the store's root. Backends: a local directory (default and
// --embedded) and S3-compatible storage through platform/httpclient so SSRF
// rules apply to the endpoint.
package objstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// ErrNotFound means no object exists under the key.
var ErrNotFound = errors.New("object not found")

// ErrInvalidKey means a key is not a server-built key.
var ErrInvalidKey = errors.New("invalid object key")

// Store is a blob store.
type Store interface {
	// Put writes data under key, replacing any existing object.
	Put(ctx context.Context, key string, data []byte) error
	// Get opens the object under key; ErrNotFound if missing.
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	// Ping checks that the store is reachable (for /readyz).
	Ping(ctx context.Context) error
}

var keyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*$`)

// ValidKey reports whether key is a well-formed relative key: lowercase
// segments of [a-z0-9_-] separated by single slashes, no dots at all.
func ValidKey(key string) bool {
	return len(key) <= 512 && keyPattern.MatchString(key)
}

// FS stores objects as files under a root directory.
type FS struct {
	root *os.Root
}

// NewFS opens (creating if needed, mode 0700) dir as a store.
func NewFS(dir string) (*FS, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("open log store: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open log store: %w", err)
	}
	return &FS{root: root}, nil
}

// Close releases the directory handle.
func (s *FS) Close() error { return s.root.Close() } //nolint:wrapcheck // trivial

// Put writes data atomically (temp file + rename) under key.
func (s *FS) Put(_ context.Context, key string, data []byte) error {
	if !ValidKey(key) {
		return ErrInvalidKey
	}
	dir := path.Dir(key)
	if err := s.root.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("put object: %w", err)
	}
	tmp := key + "-tmp"
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("put object: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("put object: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("put object: %w", err)
	}
	if err := s.root.Rename(tmp, key); err != nil {
		return fmt.Errorf("put object: %w", err)
	}
	return nil
}

// Get opens the object under key.
func (s *FS) Get(_ context.Context, key string) (io.ReadCloser, error) {
	if !ValidKey(key) {
		return nil, ErrInvalidKey
	}
	f, err := s.root.Open(key)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get object: %w", err)
	}
	return f, nil
}

// Ping checks the root is still accessible.
func (s *FS) Ping(context.Context) error {
	if _, err := s.root.Stat("."); err != nil {
		return fmt.Errorf("log store: %w", err)
	}
	return nil
}

// S3Options configures an S3-compatible store.
type S3Options struct {
	Endpoint  string // host[:port]
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	UseTLS    bool
	// Transport must come from platform/httpclient (SSRF protection).
	Transport http.RoundTripper
	// Prefix is prepended to every key (e.g. "kiln").
	Prefix string
}

// S3 stores objects in an S3-compatible bucket. The bucket must be private;
// Kiln streams objects itself and never hands out URLs (ADR-0007 §2).
type S3 struct {
	client *minio.Client
	bucket string
	prefix string
}

// NewS3 returns an S3 store. It does not create the bucket.
func NewS3(o S3Options) (*S3, error) {
	if o.Transport == nil {
		return nil, errors.New("s3 store: a transport from platform/httpclient is required")
	}
	c, err := minio.New(o.Endpoint, &minio.Options{
		Creds:     credentials.NewStaticV4(o.AccessKey, o.SecretKey, ""),
		Secure:    o.UseTLS,
		Region:    o.Region,
		Transport: o.Transport,
	})
	if err != nil {
		// Never include options: they hold credentials.
		return nil, errors.New("s3 store: invalid endpoint configuration")
	}
	prefix := strings.Trim(o.Prefix, "/")
	if prefix != "" && !ValidKey(prefix) {
		return nil, errors.New("s3 store: prefix must be lowercase letters, digits, - and _ separated by /")
	}
	return &S3{client: c, bucket: o.Bucket, prefix: prefix}, nil
}

func (s *S3) key(k string) string {
	if s.prefix == "" {
		return k
	}
	return s.prefix + "/" + k
}

// Put uploads data under key.
func (s *S3) Put(ctx context.Context, key string, data []byte) error {
	if !ValidKey(key) {
		return ErrInvalidKey
	}
	_, err := s.client.PutObject(ctx, s.bucket, s.key(key), bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("put object: %w", err)
	}
	return nil
}

// Get downloads the object under key.
func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if !ValidKey(key) {
		return nil, ErrInvalidKey
	}
	obj, err := s.client.GetObject(ctx, s.bucket, s.key(key), minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("get object: %w", err)
	}
	if _, err := obj.Stat(); err != nil {
		_ = obj.Close()
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get object: %w", err)
	}
	return obj, nil
}

// Ping checks the bucket exists and is reachable.
func (s *S3) Ping(ctx context.Context) error {
	ok, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("log store: %w", err)
	}
	if !ok {
		return errors.New("log store: bucket does not exist")
	}
	return nil
}
