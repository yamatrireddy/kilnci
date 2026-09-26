// SPDX-License-Identifier: Apache-2.0

//go:build integration

package objstore

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/yamatrireddy/kilnci/server/internal/platform/httpclient"
)

// s3Identities is a test-only identity for the throwaway gateway.
const s3Identities = `{"identities":[{"name":"test","credentials":[{"accessKey":"test","secretKey":"test-only"}],"actions":["Admin","Read","Write","List"]}]}`

// seaweedImage provides an S3-compatible gateway for tests (pinned).
const seaweedImage = "chrislusf/seaweedfs@sha256:ce9e796f1fe6f06968f4c04bdaf8f678dad9c8acdfef3d244133d71bfa6bf882"

func TestS3_PutGetThroughHardenedClient(t *testing.T) {
	ctx := t.Context()
	ctr, err := testcontainers.Run(ctx, seaweedImage,
		testcontainers.WithCmd("server", "-s3", "-s3.port=8333", "-dir=/data", "-s3.config=/etc/seaweedfs/s3.json"),
		testcontainers.WithFiles(testcontainers.ContainerFile{
			Reader:            strings.NewReader(s3Identities),
			ContainerFilePath: "/etc/seaweedfs/s3.json",
			FileMode:          0o644,
		}),
		testcontainers.WithExposedPorts("8333/tcp"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("8333/tcp").WithStartupTimeout(2*time.Minute)),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(ctr) })
	endpoint, err := ctr.PortEndpoint(ctx, "8333/tcp", "")
	if err != nil {
		t.Fatal(err)
	}

	// The SSRF-safe client blocks loopback unless an admin allows it.
	blocked := httpclient.New(httpclient.Options{})
	s, err := NewS3(S3Options{Endpoint: endpoint, Bucket: "kiln", AccessKey: "test", SecretKey: "test-only", Transport: blocked.Transport})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "a/b", []byte("x")); err == nil || !errors.Is(err, httpclient.ErrBlockedDestination) {
		t.Fatalf("loopback S3 reached without allow-listing: %v", err)
	}

	allowed := httpclient.New(httpclient.Options{AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}})
	s, err = NewS3(S3Options{Endpoint: endpoint, Bucket: "kiln", AccessKey: "test", SecretKey: "test-only", Transport: allowed.Transport, Prefix: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	var lastErr error
	for range 30 { // the gateway may accept connections before it serves
		if lastErr = s.client.MakeBucket(ctx, "kiln", minio.MakeBucketOptions{}); lastErr == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if lastErr != nil {
		t.Fatalf("make bucket: %v", lastErr)
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "orgs/o/jobs/j/00000000", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	rc, err := s.Get(ctx, "orgs/o/jobs/j/00000000")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "hello" {
		t.Fatalf("got %q", b)
	}
	if _, err := s.Get(ctx, "orgs/o/jobs/j/00000001"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing object = %v", err)
	}
	if err := s.Put(context.Background(), "../escape", nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("bad key = %v", err)
	}
}
