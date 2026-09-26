// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runnerv1 "github.com/yamatrireddy/kilnci/proto/gen/go/kiln/runner/v1"
)

// Upload tuning (ADR-0007 §1: chunks are at most 256 KiB).
const (
	flushBytes    = 64 << 10
	maxChunkBytes = 256 << 10
	flushInterval = time.Second
)

type logClient interface {
	AppendLogs(ctx context.Context, req *runnerv1.AppendLogsRequest, opts ...grpc.CallOption) (*runnerv1.AppendLogsResponse, error)
}

// uploader batches masked output into numbered chunks and sends them in
// order. It never blocks the job on the network for long: Write only
// buffers, and a background loop flushes. It is an io.Writer.
type uploader struct {
	client  logClient
	jobID   string
	leaseID []byte
	log     *slog.Logger

	mu      sync.Mutex
	buf     []byte
	seq     uint32
	stopped bool // truncated by the server or lease lost
	kick    chan struct{}
	done    chan struct{}
	quit    chan struct{}
}

func newUploader(ctx context.Context, c logClient, jobID string, leaseID []byte, log *slog.Logger) *uploader {
	u := &uploader{client: c, jobID: jobID, leaseID: leaseID, log: log,
		kick: make(chan struct{}, 1), done: make(chan struct{}), quit: make(chan struct{})}
	// Uploads outlive job cancellation: output written before a cancel is
	// still delivered, bounded by per-call timeouts.
	go u.loop(context.WithoutCancel(ctx))
	return u
}

// maxBuffered bounds memory if the server is unreachable: older output is
// kept, newer output beyond this is dropped (the server caps logs anyway).
const maxBuffered = 8 << 20

func (u *uploader) Write(p []byte) (int, error) {
	u.mu.Lock()
	if !u.stopped && len(u.buf) < maxBuffered {
		room := maxBuffered - len(u.buf)
		u.buf = append(u.buf, p[:min(len(p), room)]...)
	}
	full := len(u.buf) >= flushBytes
	u.mu.Unlock()
	if full {
		select {
		case u.kick <- struct{}{}:
		default:
		}
	}
	return len(p), nil
}

func (u *uploader) loop(ctx context.Context) {
	defer close(u.done)
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for {
		select {
		case <-u.quit:
			u.flush(ctx, true)
			return
		case <-t.C:
		case <-u.kick:
		}
		u.flush(ctx, false)
	}
}

// flush sends buffered output in chunks of at most maxChunkBytes. With all
// set, it retries until everything is sent or the upload stops.
func (u *uploader) flush(ctx context.Context, all bool) {
	for attempt := 0; ; {
		u.mu.Lock()
		if u.stopped || len(u.buf) == 0 {
			u.mu.Unlock()
			return
		}
		n := min(len(u.buf), maxChunkBytes)
		chunk := append([]byte(nil), u.buf[:n]...)
		seq := u.seq
		u.mu.Unlock()

		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		resp, err := u.client.AppendLogs(cctx, &runnerv1.AppendLogsRequest{
			ProtocolVersion: protocolVersion, JobId: u.jobID, LeaseId: u.leaseID, Seq: seq, Data: chunk,
		})
		cancel()
		switch c := status.Code(err); {
		case err == nil:
			u.mu.Lock()
			u.buf = u.buf[n:]
			u.seq++
			if resp.GetTruncated() {
				u.stopped = true
			}
			u.mu.Unlock()
			attempt = 0
			if !all && len(u.buf) < flushBytes {
				return
			}
		case c == codes.NotFound || c == codes.Unauthenticated || c == codes.InvalidArgument || c == codes.Aborted:
			// Lease lost or the chunk was refused: nothing more can be sent.
			u.log.Warn("log upload stopped", "error", err)
			u.mu.Lock()
			u.stopped = true
			u.mu.Unlock()
			return
		default:
			attempt++
			if !all || attempt > 5 {
				return // retried on the next tick (or given up at the end)
			}
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
}

// Close flushes everything still buffered and stops the loop.
func (u *uploader) Close(ctx context.Context) {
	close(u.quit)
	select {
	case <-u.done:
	case <-ctx.Done():
	}
}
