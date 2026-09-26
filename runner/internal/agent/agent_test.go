// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runnerv1 "github.com/yamatrireddy/kilnci/proto/gen/go/kiln/runner/v1"
	"github.com/yamatrireddy/kilnci/runner/executor"
	"github.com/yamatrireddy/kilnci/runner/internal/identity"
)

const secret = "ghs_supersecretinstallationtoken"

type fakeClient struct {
	mu         sync.Mutex
	jobs       []*runnerv1.Job
	chunks     map[uint32][]byte
	completed  []*runnerv1.CompleteJobRequest
	heartbeats int
	cancelAt   int  // heartbeat number that says cancel (0 = never)
	lostAt     int  // heartbeat number that says NotFound (0 = never)
	truncateAt int  // chunk seq answered with truncated (-1 = never)
	revoked    bool // Lease returns Unauthenticated once no jobs remain
}

func (f *fakeClient) RenewCertificate(context.Context, *runnerv1.RenewCertificateRequest, ...grpc.CallOption) (*runnerv1.RenewCertificateResponse, error) {
	return nil, errors.New("not used")
}

func (f *fakeClient) Lease(ctx context.Context, _ *runnerv1.LeaseRequest, _ ...grpc.CallOption) (*runnerv1.LeaseResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.jobs) == 0 {
		if f.revoked {
			return nil, status.Error(codes.Unauthenticated, "revoked")
		}
		return &runnerv1.LeaseResponse{}, nil
	}
	j := f.jobs[0]
	f.jobs = f.jobs[1:]
	return &runnerv1.LeaseResponse{Job: j}, nil
}

func (f *fakeClient) Heartbeat(context.Context, *runnerv1.HeartbeatRequest, ...grpc.CallOption) (*runnerv1.HeartbeatResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeats++
	if f.lostAt != 0 && f.heartbeats >= f.lostAt {
		return nil, status.Error(codes.NotFound, "lease not held")
	}
	return &runnerv1.HeartbeatResponse{
		LeaseExpiresAtUnixMs: time.Now().Add(300 * time.Millisecond).UnixMilli(),
		Cancel:               f.cancelAt != 0 && f.heartbeats >= f.cancelAt, CancelReason: "canceled",
	}, nil
}

func (f *fakeClient) CompleteJob(_ context.Context, req *runnerv1.CompleteJobRequest, _ ...grpc.CallOption) (*runnerv1.CompleteJobResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completed = append(f.completed, req)
	return &runnerv1.CompleteJobResponse{}, nil
}

func (f *fakeClient) AppendLogs(_ context.Context, req *runnerv1.AppendLogsRequest, _ ...grpc.CallOption) (*runnerv1.AppendLogsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.chunks == nil {
		f.chunks = map[uint32][]byte{}
	}
	if _, dup := f.chunks[req.GetSeq()]; dup || int(req.GetSeq()) != len(f.chunks) {
		return nil, status.Error(codes.InvalidArgument, "out of order")
	}
	f.chunks[req.GetSeq()] = append([]byte(nil), req.GetData()...)
	return &runnerv1.AppendLogsResponse{Truncated: f.truncateAt >= 0 && int(req.GetSeq()) >= f.truncateAt}, nil
}

func (f *fakeClient) log() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	for i := uint32(0); int(i) < len(f.chunks); i++ {
		b.Write(f.chunks[i])
	}
	return b.String()
}

type conn struct{ c *fakeClient }

func (c conn) Client() Client   { return c.c }
func (c conn) Reconnect() error { return nil }

type noRenew struct{}

func (noRenew) NeedsRenewal(time.Time) bool                   { return false }
func (noRenew) Renew(context.Context, identity.Renewer) error { return nil }

// fakeExec writes output (including the secret) and returns a scripted result.
type fakeExec struct {
	out  string
	res  executor.Result
	wait bool // block until canceled
	got  executor.Job
}

func (e *fakeExec) Run(ctx context.Context, job executor.Job, out io.Writer) (executor.Result, error) {
	e.got = job
	_, _ = io.WriteString(out, e.out)
	if e.wait {
		<-ctx.Done()
		return executor.Result{Outcome: executor.Canceled, ExitCode: -1, Reason: "canceled"}, nil
	}
	return e.res, nil
}

func job() *runnerv1.Job {
	return &runnerv1.Job{
		JobId: "01K6A7B8C9D0E1F2G3H4J5K6M7", LeaseId: []byte{1, 2, 3}, LeaseExpiresAtUnixMs: time.Now().Add(300 * time.Millisecond).UnixMilli(),
		Image: "alpine", Steps: []*runnerv1.Step{{Name: "s", Run: "true", TimeoutSeconds: 5}},
		Env: []*runnerv1.EnvVar{{Name: "A", Value: "b"}}, TimeoutSeconds: 60, Trusted: true,
		Checkout:   &runnerv1.Checkout{RepositoryUrl: "https://github.com/acme/app.git", CommitSha: strings.Repeat("a", 40), AuthorizationHeader: "basic " + secret},
		MaskValues: []string{"another-secret-value"},
	}
}

func runOnce(t *testing.T, fc *fakeClient, ex executor.Executor, opts Options) {
	t.Helper()
	fc.revoked = true // stop the loop once the queued job ran
	err := New(conn{fc}, noRenew{}, ex, opts).Run(t.Context())
	if err == nil || status.Code(errors.Unwrap(err)) != codes.Unauthenticated {
		t.Fatalf("Run = %v, want the revocation error", err)
	}
}

func TestAgent_RunsJobMasksOutputAndReports(t *testing.T) {
	fc := &fakeClient{jobs: []*runnerv1.Job{job()}, truncateAt: -1}
	ex := &fakeExec{
		out: "token=" + secret + " also another-secret-value\n",
		res: executor.Result{Outcome: executor.Failed, ExitCode: 2, Reason: `step "s" failed with exit code 2`},
	}
	runOnce(t, fc, ex, Options{EgressUnrestricted: true})
	logText := fc.log()
	if strings.Contains(logText, secret) || strings.Contains(logText, "another-secret-value") {
		t.Fatalf("secret reached the server: %q", logText)
	}
	if !strings.Contains(logText, "token=*** also ***") || !strings.Contains(logText, "WARNING: this runner does not restrict network egress") {
		t.Fatalf("log = %q", logText)
	}
	if len(fc.completed) != 1 || fc.completed[0].GetResult() != runnerv1.JobResult_JOB_RESULT_FAILED ||
		fc.completed[0].GetExitCode() != 2 || !strings.Contains(fc.completed[0].GetFailureReason(), "exit code 2") {
		t.Fatalf("completed = %+v", fc.completed)
	}
	if ex.got.Checkout.AuthorizationHeader != "basic "+secret || ex.got.Steps[0].Timeout != 5*time.Second || !ex.got.Trusted {
		t.Fatalf("executor job = %+v", ex.got)
	}
}

func TestAgent_ServerCancelStopsTheJob(t *testing.T) {
	fc := &fakeClient{jobs: []*runnerv1.Job{job()}, cancelAt: 1, truncateAt: -1}
	runOnce(t, fc, &fakeExec{wait: true}, Options{})
	if len(fc.completed) != 1 || fc.completed[0].GetResult() != runnerv1.JobResult_JOB_RESULT_CANCELED {
		t.Fatalf("completed = %+v", fc.completed)
	}
}

func TestAgent_LostLeaseIsNotReported(t *testing.T) {
	fc := &fakeClient{jobs: []*runnerv1.Job{job()}, lostAt: 1, truncateAt: -1}
	runOnce(t, fc, &fakeExec{wait: true}, Options{})
	if len(fc.completed) != 0 {
		t.Fatalf("reported a job whose lease was lost: %+v", fc.completed)
	}
}

func TestAgent_ExecutorErrorBecomesFailure(t *testing.T) {
	fc := &fakeClient{jobs: []*runnerv1.Job{job()}, truncateAt: -1}
	runOnce(t, fc, errExec{}, Options{})
	if len(fc.completed) != 1 || fc.completed[0].GetResult() != runnerv1.JobResult_JOB_RESULT_FAILED || fc.completed[0].ExitCode != nil {
		t.Fatalf("completed = %+v", fc.completed)
	}
}

type errExec struct{}

func (errExec) Run(context.Context, executor.Job, io.Writer) (executor.Result, error) {
	return executor.Result{}, errors.New("docker down: /var/run/docker.sock")
}

func TestUploader_ChunksInOrderAndStopsWhenTruncated(t *testing.T) {
	fc := &fakeClient{truncateAt: 2}
	u := newUploader(t.Context(), fc, "j", []byte{1}, testLogger())
	big := strings.Repeat("x", maxChunkBytes)
	for range 5 {
		_, _ = u.Write([]byte(big))
	}
	u.Close(t.Context())
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if len(fc.chunks) != 3 {
		t.Fatalf("sent %d chunks, want 3 (stop after truncation)", len(fc.chunks))
	}
	for i, c := range fc.chunks {
		if len(c) > maxChunkBytes {
			t.Fatalf("chunk %d too large", i)
		}
	}
}

func TestAgent_ShutdownIsNotAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := New(conn{&fakeClient{}}, noRenew{}, &fakeExec{}, Options{}).Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run after cancel = %v", err)
	}
}

func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestCredentialParts(t *testing.T) {
	// "x-access-token:ghs_abc123456789" in Basic form.
	h := "Basic eC1hY2Nlc3MtdG9rZW46Z2hzX2FiYzEyMzQ1Njc4OQ=="
	got := credentialParts(h)
	want := []string{h, "eC1hY2Nlc3MtdG9rZW46Z2hzX2FiYzEyMzQ1Njc4OQ==", "x-access-token:ghs_abc123456789", "ghs_abc123456789"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("credentialParts = %q", got)
	}
	if got := credentialParts("Bearer tok_1234567890"); len(got) != 2 || got[1] != "tok_1234567890" {
		t.Fatalf("bearer = %q", got)
	}
	if credentialParts("") != nil {
		t.Fatal("empty header produced masks")
	}
}
