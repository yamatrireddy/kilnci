// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runnerv1 "github.com/yamatrireddy/kilnci/proto/gen/go/kiln/runner/v1"
)

// scriptedLogs is a log server whose answer to each chunk is decided by
// fail; accepted chunks must arrive with contiguous sequence numbers.
type scriptedLogs struct {
	mu     sync.Mutex
	gate   chan struct{} // if set, every call waits for it to close
	fail   func(data []byte) error
	chunks [][]byte
	calls  int
}

func (s *scriptedLogs) AppendLogs(ctx context.Context, req *runnerv1.AppendLogsRequest, _ ...grpc.CallOption) (*runnerv1.AppendLogsResponse, error) {
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return nil, status.Error(codes.DeadlineExceeded, "gate")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.fail != nil {
		if err := s.fail(req.GetData()); err != nil {
			return nil, err
		}
	}
	if int(req.GetSeq()) != len(s.chunks) {
		return nil, status.Error(codes.InvalidArgument, "out of order")
	}
	s.chunks = append(s.chunks, append([]byte(nil), req.GetData()...))
	return &runnerv1.AppendLogsResponse{}, nil
}

func (s *scriptedLogs) log() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(bytes.Join(s.chunks, nil))
}

// syncBuffer collects log output from the upload goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p) //nolint:wrapcheck // test sink
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func startTestUploader(t *testing.T, c logClient) (*uploader, *syncBuffer) {
	t.Helper()
	u, logs := makeUploaderUnstarted(t, c)
	u.start(t.Context())
	return u, logs
}

func TestUploader_BufferFullMarksGapOncePerEpisode(t *testing.T) {
	u := makeUploader(&scriptedLogs{}, "j", []byte{1}, testLogger()) // loop not started: nothing drains
	fill := strings.Repeat("a", maxBuffered-10)
	steps := []struct {
		name  string
		write string
		drain bool
	}{
		{name: "fills and overflows", write: fill + strings.Repeat("b", 20)},
		{name: "still full", write: "ccccc"},
		{name: "still full again", write: "ddddd"},
		{name: "drained", drain: true},
		{name: "accepted again", write: "eeeee"},
		{name: "overflows again", write: fill + "ffffffffffffffffffff"},
	}
	var sent strings.Builder
	for _, st := range steps {
		if st.drain {
			u.mu.Lock()
			sent.Write(u.buf)
			u.buf = nil
			u.mu.Unlock()
			continue
		}
		if n, err := u.Write([]byte(st.write)); err != nil || n != len(st.write) {
			t.Fatalf("%s: Write = %d, %v", st.name, n, err)
		}
	}
	sent.Write(u.buf)
	got := sent.String()
	if c := strings.Count(got, markerBufferFull); c != 2 {
		t.Fatalf("markers = %d, want one per episode (2)", c)
	}
	want := fill + "bbbbbbbbbb" + markerBufferFull + "eeeee" + fill + "fffff" + markerBufferFull
	if got != want {
		t.Fatalf("buffered output wrong: len %d, want %d; tail %q", len(got), len(want), got[max(0, len(got)-80):])
	}
}

func TestUploader_BufferFullMarkerReachesServer(t *testing.T) {
	srv := &scriptedLogs{gate: make(chan struct{})}
	u, logs := startTestUploader(t, srv)
	data := strings.Repeat("x", maxBuffered)
	_, _ = u.Write([]byte(data))
	_, _ = u.Write([]byte("lost"))
	close(srv.gate)
	u.Close(t.Context())
	if got := srv.log(); got != data+markerBufferFull {
		t.Fatalf("server log: len %d, tail %q", len(got), got[max(0, len(got)-60):])
	}
	if !strings.Contains(logs.String(), "buffer full") {
		t.Fatalf("drop not logged: %s", logs.String())
	}
}

func TestUploader_FinalFlushFailures(t *testing.T) {
	unavailable := status.Error(codes.Unavailable, "down")
	tests := []struct {
		name    string
		fail    func([]byte) error
		want    string
		wantLog string
	}{
		{
			name: "failed chunk is replaced by a marker",
			fail: func(d []byte) error {
				if bytes.HasPrefix(d, []byte("A")) {
					return unavailable
				}
				return nil
			},
			want:    markerUploadFailed + "BBBB",
			wantLog: "chunk dropped",
		},
		{
			name:    "server down gives up",
			fail:    func([]byte) error { return unavailable },
			want:    "",
			wantLog: "remaining job output dropped",
		},
		{
			name:    "aborted stops and is logged",
			fail:    func([]byte) error { return status.Error(codes.Aborted, "conflicting chunk") },
			want:    "",
			wantLog: "code=Aborted",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &scriptedLogs{fail: tt.fail}
			u, logs := makeUploaderUnstarted(t, srv)
			_, _ = u.Write([]byte(strings.Repeat("A", maxChunkBytes)))
			_, _ = u.Write([]byte("BBBB"))
			u.start(t.Context())
			u.Close(t.Context())
			if got := srv.log(); got != tt.want {
				t.Fatalf("server log = %q, want %q", got, tt.want)
			}
			if !strings.Contains(logs.String(), tt.wantLog) {
				t.Fatalf("log lacks %q: %s", tt.wantLog, logs.String())
			}
			if n, err := u.Write([]byte("after")); err != nil || n != 5 {
				t.Fatalf("Write after stop = %d, %v", n, err)
			}
		})
	}
}

// commitThenTimeout stores chunk 0 on the first call but answers every
// call carrying it with DeadlineExceeded, like a server that commits and
// then responds too late. A different chunk 0 conflicts, as on the server.
type commitThenTimeout struct {
	mu     sync.Mutex
	chunks [][]byte
}

func (s *commitThenTimeout) AppendLogs(_ context.Context, req *runnerv1.AppendLogsRequest, _ ...grpc.CallOption) (*runnerv1.AppendLogsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq, data := int(req.GetSeq()), req.GetData()
	if seq < len(s.chunks) {
		if !bytes.Equal(s.chunks[seq], data) {
			return nil, status.Error(codes.Aborted, "conflicting chunk")
		}
		if seq == 0 {
			return nil, status.Error(codes.DeadlineExceeded, "late")
		}
		return &runnerv1.AppendLogsResponse{}, nil
	}
	if seq != len(s.chunks) {
		return nil, status.Error(codes.InvalidArgument, "out of order")
	}
	s.chunks = append(s.chunks, append([]byte(nil), data...))
	if seq == 0 {
		return nil, status.Error(codes.DeadlineExceeded, "late")
	}
	return &runnerv1.AppendLogsResponse{}, nil
}

// TestUploader_ChunkStoredDespiteFailuresIsNotReplaced: when a chunk given
// up on had in fact been stored, the marker sent in its place conflicts;
// the uploader continues after it instead of stopping (security review).
func TestUploader_ChunkStoredDespiteFailuresIsNotReplaced(t *testing.T) {
	srv := &commitThenTimeout{}
	u, logs := makeUploaderUnstarted(t, srv)
	first := strings.Repeat("A", maxChunkBytes)
	_, _ = u.Write([]byte(first))
	_, _ = u.Write([]byte("BBBB"))
	u.start(t.Context())
	u.Close(t.Context())
	srv.mu.Lock()
	got := string(bytes.Join(srv.chunks, nil))
	srv.mu.Unlock()
	if got != first+"BBBB" {
		t.Fatalf("server log has %d bytes, suffix %q", len(got), got[max(0, len(got)-20):])
	}
	if !strings.Contains(logs.String(), "was stored; continuing") {
		t.Fatalf("log = %s", logs.String())
	}
}

// makeUploaderUnstarted buffers writes before the loop runs, so the final
// flush sees them all at once.
func makeUploaderUnstarted(t *testing.T, c logClient) (*uploader, *syncBuffer) {
	t.Helper()
	var logs syncBuffer
	u := makeUploader(c, "j", []byte{1}, slog.New(slog.NewTextHandler(&logs, nil)))
	u.sleep = func(time.Duration) {} // no real backoff in tests
	return u, &logs
}
