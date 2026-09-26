// SPDX-License-Identifier: Apache-2.0

// Package agent is the runner's main loop: lease a job, execute it in the
// sandbox, stream its masked output, heartbeat, and report the result
// (ADR-0005). It always initiates calls; the server never connects to it.
package agent

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runnerv1 "github.com/yamatrireddy/kilnci/proto/gen/go/kiln/runner/v1"
	"github.com/yamatrireddy/kilnci/runner/executor"
	"github.com/yamatrireddy/kilnci/runner/internal/identity"
	"github.com/yamatrireddy/kilnci/runner/internal/mask"
)

// Client is the runner API.
type Client interface {
	RenewCertificate(ctx context.Context, req *runnerv1.RenewCertificateRequest, opts ...grpc.CallOption) (*runnerv1.RenewCertificateResponse, error)
	Lease(ctx context.Context, req *runnerv1.LeaseRequest, opts ...grpc.CallOption) (*runnerv1.LeaseResponse, error)
	Heartbeat(ctx context.Context, req *runnerv1.HeartbeatRequest, opts ...grpc.CallOption) (*runnerv1.HeartbeatResponse, error)
	CompleteJob(ctx context.Context, req *runnerv1.CompleteJobRequest, opts ...grpc.CallOption) (*runnerv1.CompleteJobResponse, error)
	AppendLogs(ctx context.Context, req *runnerv1.AppendLogsRequest, opts ...grpc.CallOption) (*runnerv1.AppendLogsResponse, error)
}

// Conn gives the agent a client and lets it reconnect after a certificate
// renewal (new TLS sessions present the new certificate).
type Conn interface {
	Client() Client
	Reconnect() error
}

// Identity is the runner's credential store.
type Identity interface {
	NeedsRenewal(now time.Time) bool
	Renew(ctx context.Context, c identity.Renewer) error
}

// Options configures the agent.
type Options struct {
	// EgressUnrestricted is set when the operator chose
	// --egress-policy=none; every job log then carries a warning (ADR-0006 §7).
	EgressUnrestricted bool
	// Backoff after errors talking to the server. Default 5s.
	ErrorBackoff time.Duration
	Log          *slog.Logger
	Now          func() time.Time
}

// Agent runs jobs one at a time.
type Agent struct {
	conn Conn
	id   Identity
	exec executor.Executor
	opts Options
}

// New returns an Agent.
func New(conn Conn, id Identity, exec executor.Executor, opts Options) *Agent {
	if opts.ErrorBackoff <= 0 {
		opts.ErrorBackoff = 5 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Agent{conn: conn, id: id, exec: exec, opts: opts}
}

const protocolVersion = identity.ProtocolVersion

// Run leases and executes jobs until ctx is done (it then returns an error
// wrapping context.Canceled). A revoked runner (Unauthenticated) stops with
// an error; other failures back off and retry.
func (a *Agent) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		if a.id.NeedsRenewal(a.opts.Now()) {
			if err := a.id.Renew(ctx, a.conn.Client()); err != nil {
				if status.Code(err) == codes.Unauthenticated {
					return fmt.Errorf("runner credentials were rejected (revoked?): %w", err)
				}
				a.opts.Log.WarnContext(ctx, "certificate renewal failed; will retry", "error", err)
			} else if err := a.conn.Reconnect(); err != nil {
				return fmt.Errorf("reconnect after renewal: %w", err)
			} else {
				a.opts.Log.InfoContext(ctx, "renewed runner certificate")
			}
		}
		lctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		resp, err := a.conn.Client().Lease(lctx, &runnerv1.LeaseRequest{ProtocolVersion: protocolVersion})
		cancel()
		if ctx.Err() != nil {
			return fmt.Errorf("shutting down: %w", context.Cause(ctx))
		}
		switch {
		case status.Code(err) == codes.Unauthenticated:
			return fmt.Errorf("runner credentials were rejected (revoked?): %w", err)
		case err != nil:
			a.opts.Log.WarnContext(ctx, "lease failed", "error", err)
			sleep(ctx, a.opts.ErrorBackoff)
			continue
		case resp.GetJob() == nil:
			continue
		}
		a.runJob(ctx, resp.GetJob())
	}
	return fmt.Errorf("shutting down: %w", context.Cause(ctx))
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

var (
	errLeaseLost = errors.New("lease lost")
	errCanceled  = errors.New("canceled by the server")
)

func toExecutorJob(j *runnerv1.Job) executor.Job {
	env := func(in []*runnerv1.EnvVar) []executor.EnvVar {
		out := make([]executor.EnvVar, len(in))
		for i, e := range in {
			out[i] = executor.EnvVar{Name: e.GetName(), Value: e.GetValue()}
		}
		return out
	}
	steps := make([]executor.Step, len(j.GetSteps()))
	for i, s := range j.GetSteps() {
		steps[i] = executor.Step{Name: s.GetName(), Run: s.GetRun(), Env: env(s.GetEnv()), Timeout: time.Duration(s.GetTimeoutSeconds()) * time.Second}
	}
	return executor.Job{
		ID: j.GetJobId(), Image: j.GetImage(), Steps: steps, Env: env(j.GetEnv()),
		Timeout: time.Duration(j.GetTimeoutSeconds()) * time.Second, Trusted: j.GetTrusted(),
		Checkout: executor.Checkout{
			RepositoryURL: j.GetCheckout().GetRepositoryUrl(), CommitSHA: j.GetCheckout().GetCommitSha(),
			AuthorizationHeader: j.GetCheckout().GetAuthorizationHeader(),
		},
	}
}

func (a *Agent) runJob(ctx context.Context, j *runnerv1.Job) {
	log := a.opts.Log.With("job_id", j.GetJobId())
	log.InfoContext(ctx, "running job", "image", j.GetImage())
	jobCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	up := newUploader(ctx, a.conn.Client(), j.GetJobId(), j.GetLeaseId(), log)
	masks := append([]string{}, j.GetMaskValues()...)
	masks = append(masks, credentialParts(j.GetCheckout().GetAuthorizationHeader())...)
	out := mask.New(up, masks)
	if a.opts.EgressUnrestricted {
		_, _ = out.Write([]byte("==> WARNING: this runner does not restrict network egress from jobs " +
			"(cloud metadata and private networks may be reachable).\n"))
	}

	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		a.heartbeat(jobCtx, j, cancel, log)
	}()

	res, err := a.exec.Run(jobCtx, toExecutorJob(j), out)
	if err != nil {
		log.ErrorContext(ctx, "executor failed", "error", err)
		res = executor.Result{Outcome: executor.Failed, ExitCode: -1, Reason: "the runner could not execute the job"}
	}
	_ = out.Close()
	up.Close(ctx)
	cause := context.Cause(jobCtx)
	cancel(nil)
	<-hbDone
	if errors.Is(cause, errLeaseLost) {
		log.WarnContext(ctx, "lease lost; not reporting a result")
		return
	}
	if errors.Is(cause, errCanceled) && res.Outcome != executor.Succeeded {
		res.Outcome = executor.Canceled
	}
	a.complete(ctx, j, res, log)
}

// credentialParts returns every form of an Authorization header value that
// could appear in output: the whole value, the credential after the scheme,
// and for Basic auth the decoded "user:password" and the password.
func credentialParts(header string) []string {
	if header == "" {
		return nil
	}
	parts := []string{header}
	scheme, cred, ok := strings.Cut(header, " ")
	if !ok {
		return parts
	}
	cred = strings.TrimSpace(cred)
	parts = append(parts, cred)
	if strings.EqualFold(scheme, "basic") {
		if dec, err := base64.StdEncoding.DecodeString(cred); err == nil {
			parts = append(parts, string(dec))
			if _, pw, ok := strings.Cut(string(dec), ":"); ok {
				parts = append(parts, pw)
			}
		}
	}
	return parts
}

// heartbeat renews the lease at a third of its remaining lifetime and
// cancels the job if the server asks or the lease is lost.
func (a *Agent) heartbeat(ctx context.Context, j *runnerv1.Job, cancel context.CancelCauseFunc, log *slog.Logger) {
	expires := time.UnixMilli(j.GetLeaseExpiresAtUnixMs())
	for {
		wait := max(time.Until(expires)/3, time.Second)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		hctx, hcancel := context.WithTimeout(ctx, 10*time.Second)
		resp, err := a.conn.Client().Heartbeat(hctx, &runnerv1.HeartbeatRequest{
			ProtocolVersion: protocolVersion, JobId: j.GetJobId(), LeaseId: j.GetLeaseId(),
		})
		hcancel()
		switch {
		case ctx.Err() != nil:
			return
		case status.Code(err) == codes.NotFound || status.Code(err) == codes.Unauthenticated:
			cancel(errLeaseLost)
			return
		case err != nil:
			// Transient: retry sooner; the lease survives a missed beat.
			log.WarnContext(ctx, "heartbeat failed", "error", err)
			expires = time.Now().Add(3 * time.Second)
			continue
		}
		expires = time.UnixMilli(resp.GetLeaseExpiresAtUnixMs())
		if resp.GetCancel() {
			log.InfoContext(ctx, "server asked to stop the job", "reason", resp.GetCancelReason())
			cancel(errCanceled)
			return
		}
	}
}

func (a *Agent) complete(ctx context.Context, j *runnerv1.Job, res executor.Result, log *slog.Logger) {
	req := &runnerv1.CompleteJobRequest{ProtocolVersion: protocolVersion, JobId: j.GetJobId(), LeaseId: j.GetLeaseId(), FailureReason: res.Reason}
	switch res.Outcome {
	case executor.Succeeded:
		req.Result = runnerv1.JobResult_JOB_RESULT_SUCCEEDED
	case executor.Canceled:
		req.Result = runnerv1.JobResult_JOB_RESULT_CANCELED
	default:
		req.Result = runnerv1.JobResult_JOB_RESULT_FAILED
	}
	if res.ExitCode >= 0 && res.ExitCode <= 255 {
		code := int32(res.ExitCode)
		req.ExitCode = &code
	}
	for attempt := range 5 {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		_, err := a.conn.Client().CompleteJob(cctx, req)
		cancel()
		if err == nil {
			log.InfoContext(ctx, "job finished", "result", req.GetResult().String())
			return
		}
		if c := status.Code(err); c == codes.NotFound || c == codes.InvalidArgument || c == codes.Unauthenticated {
			log.WarnContext(ctx, "server rejected the job result", "error", err)
			return
		}
		log.WarnContext(ctx, "reporting the job result failed; retrying", "error", err)
		sleep(ctx, time.Duration(attempt+1)*time.Second)
	}
}
