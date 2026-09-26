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

// Gap markers are written into the log where output was lost, so the
// stored record shows the gap instead of silently skipping it. Each is
// written once per contiguous loss.
const (
	markerBufferFull   = "\n[kiln: output dropped: upload buffer full]\n"
	markerUploadFailed = "\n[kiln: output dropped: upload failed]\n"
)

// finalAttempts bounds how often the final flush retries one chunk.
const finalAttempts = 5

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

	sleep func(time.Duration) // retry backoff; replaced in tests

	mu      sync.Mutex
	buf     []byte
	seq     uint32
	stopped bool // truncated by the server, lease lost, or upload given up
	inGap   bool // output is being dropped and the gap is already marked
	kick    chan struct{}
	done    chan struct{}
	quit    chan struct{}
}

func newUploader(ctx context.Context, c logClient, jobID string, leaseID []byte, log *slog.Logger) *uploader {
	u := makeUploader(c, jobID, leaseID, log)
	u.start(ctx)
	return u
}

// makeUploader returns an uploader whose loop is not yet running.
func makeUploader(c logClient, jobID string, leaseID []byte, log *slog.Logger) *uploader {
	return &uploader{client: c, jobID: jobID, leaseID: leaseID, log: log, sleep: time.Sleep,
		kick: make(chan struct{}, 1), done: make(chan struct{}), quit: make(chan struct{})}
}

// start runs the upload loop. Uploads outlive job cancellation: output
// written before a cancel is still delivered, bounded by per-call timeouts.
func (u *uploader) start(ctx context.Context) {
	go u.loop(context.WithoutCancel(ctx))
}

// maxBuffered bounds memory if the server is unreachable: older output is
// kept, newer output beyond this is dropped (the server caps logs anyway)
// and replaced by one gap marker, which may exceed the bound by its length.
const maxBuffered = 8 << 20

func (u *uploader) Write(p []byte) (int, error) {
	u.mu.Lock()
	if !u.stopped {
		n := min(len(p), max(0, maxBuffered-len(u.buf)))
		if n > 0 {
			u.buf = append(u.buf, p[:n]...)
			u.inGap = false
		}
		if n < len(p) && !u.inGap {
			u.buf = append(u.buf, markerBufferFull...)
			u.inGap = true
			u.log.Warn("job output dropped: log upload buffer full", "buffered_bytes", len(u.buf))
		}
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
// set (the final flush), it retries each chunk up to finalAttempts times;
// a chunk that still fails is dropped and replaced by a gap marker, and if
// the next chunk fails too the upload gives up.
func (u *uploader) flush(ctx context.Context, all bool) {
	droppedLast := false
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
			attempt, droppedLast = 0, false
			if !all && len(u.buf) < flushBytes {
				return
			}
		case c == codes.Aborted && droppedLast:
			// The chunk given up on was stored after all (its calls failed
			// only after the server committed it), so the marker that
			// replaced it conflicts. Nothing was lost: drop the marker and
			// send the rest after it.
			u.mu.Lock()
			u.buf = u.buf[len(markerUploadFailed):]
			u.seq++
			u.mu.Unlock()
			u.log.Warn("log chunk thought lost was stored; continuing", "seq", seq)
			attempt, droppedLast = 0, false
		case c == codes.NotFound || c == codes.Unauthenticated || c == codes.InvalidArgument || c == codes.Aborted:
			// Lease lost or the chunk was refused (Aborted: the server holds
			// a conflicting chunk): nothing more can be sent, and the server
			// cannot be told. The gap is recorded here instead.
			u.mu.Lock()
			u.stopped = true
			lost := len(u.buf)
			u.buf = nil
			u.mu.Unlock()
			u.log.Warn("log upload stopped; remaining job output dropped",
				"code", c.String(), "seq", seq, "dropped_bytes", lost, "error", err)
			return
		default:
			attempt++
			if !all {
				return // retried on the next tick
			}
			if attempt <= finalAttempts {
				u.sleep(time.Duration(attempt) * time.Second)
				continue
			}
			u.mu.Lock()
			if droppedLast {
				// The server is not accepting anything: give up.
				lost := len(u.buf)
				u.stopped = true
				u.buf = nil
				u.mu.Unlock()
				u.log.Warn("log upload failed; remaining job output dropped", "seq", seq, "dropped_bytes", lost, "error", err)
				return
			}
			u.buf = append([]byte(markerUploadFailed), u.buf[n:]...)
			u.mu.Unlock()
			u.log.Warn("log upload failed; chunk dropped", "seq", seq, "dropped_bytes", n, "error", err)
			attempt, droppedLast = 0, true
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
