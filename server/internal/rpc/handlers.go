// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runnerv1 "github.com/yamatrireddy/kilnci/proto/gen/go/kiln/runner/v1"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/pki"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ratelimit"
	"github.com/yamatrireddy/kilnci/server/internal/scheduler"
	"github.com/yamatrireddy/kilnci/server/internal/service/runners"
)

// RunnerIdentity is what the transport needs from internal/service/runners.
type RunnerIdentity interface {
	Register(ctx context.Context, req runners.RegisterRequest) (runners.Registration, error)
	RenewCertificate(ctx context.Context, id pki.Identity, csrDER []byte) (pki.Issued, error)
	Authenticate(ctx context.Context, id pki.Identity) (scheduler.Runner, error)
}

// Scheduler is what the transport needs from internal/scheduler.
type Scheduler interface {
	Lease(ctx context.Context, r scheduler.Runner) (*scheduler.Lease, error)
	Heartbeat(ctx context.Context, r scheduler.Runner, jobID string, leaseID []byte) (scheduler.HeartbeatResult, error)
	Complete(ctx context.Context, r scheduler.Runner, jobID string, leaseID []byte, res scheduler.Result) error
	Release(ctx context.Context, r scheduler.Runner, jobID string, leaseID []byte) error
}

// LogSink stores job output (internal/service/logs).
type LogSink interface {
	Append(ctx context.Context, r scheduler.Runner, jobID string, leaseID []byte, seq int, data []byte) (bool, error)
	Notify(ctx context.Context, orgID, jobID string)
}

// Checkout says where a run's code comes from and with which short-lived
// credential (empty for public repositories).
type Checkout struct {
	RepositoryURL       string
	AuthorizationHeader string
}

// CheckoutProvider resolves a leased run's checkout (internal/vcs).
type CheckoutProvider interface {
	Checkout(ctx context.Context, run domain.Run) (Checkout, error)
}

type handlers struct {
	runnerv1.UnimplementedRunnerServiceServer
	log         *slog.Logger
	svc         Services
	opts        Options
	regLimit    *ratelimit.Keyed
	runnerLimit *ratelimit.Keyed
	polls       pollLimiter
}

func (h *handlers) Register(ctx context.Context, req *runnerv1.RegisterRequest) (*runnerv1.RegisterResponse, error) {
	reg, err := h.svc.Runners.Register(ctx, runners.RegisterRequest{
		Token: req.GetRegistrationToken(), CSRDER: req.GetCsrDer(), Name: req.GetName(), Version: req.GetVersion(),
	})
	if err != nil {
		return nil, h.toStatus(ctx, runnerv1.RunnerService_Register_FullMethodName, err)
	}
	return &runnerv1.RegisterResponse{RunnerId: reg.Runner.ID, CertificateDer: reg.CertificateDER, CaCertificateDer: reg.CADER}, nil
}

func (h *handlers) RenewCertificate(ctx context.Context, req *runnerv1.RenewCertificateRequest) (*runnerv1.RenewCertificateResponse, error) {
	id, _ := identityFrom(ctx)
	iss, err := h.svc.Runners.RenewCertificate(ctx, id, req.GetCsrDer())
	if err != nil {
		return nil, h.toStatus(ctx, runnerv1.RunnerService_RenewCertificate_FullMethodName, err)
	}
	return &runnerv1.RenewCertificateResponse{CertificateDer: iss.DER}, nil
}

// Lease long-polls the queue for up to LeaseWait, backing off between
// polls. Each runner may have at most maxPollsPerRunner polls in flight, so
// one runner credential cannot multiply database load.
func (h *handlers) Lease(ctx context.Context, _ *runnerv1.LeaseRequest) (*runnerv1.LeaseResponse, error) {
	runner, _ := runnerFrom(ctx)
	if !h.polls.acquire(runner.ID) {
		return nil, status.Error(codes.ResourceExhausted, "too many concurrent lease requests")
	}
	defer h.polls.release(runner.ID)
	deadline := time.NewTimer(h.opts.LeaseWait)
	defer deadline.Stop()
	wait := h.opts.LeasePoll
	for {
		lease, err := h.svc.Scheduler.Lease(ctx, runner)
		if err != nil {
			return nil, h.toStatus(ctx, runnerv1.RunnerService_Lease_FullMethodName, err)
		}
		if lease != nil {
			job, err := h.jobMessage(ctx, lease)
			if err == nil && ctx.Err() != nil {
				err = context.Cause(ctx)
			}
			if err != nil {
				// The runner never received this job: give it back without
				// spending an attempt.
				if rerr := h.svc.Scheduler.Release(context.WithoutCancel(ctx), runner, lease.Job.ID, lease.ID); rerr != nil {
					h.log.WarnContext(ctx, "release undelivered lease", "error", rerr)
				}
				return nil, h.toStatus(ctx, runnerv1.RunnerService_Lease_FullMethodName, err)
			}
			return &runnerv1.LeaseResponse{Job: job}, nil
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, status.Error(status.FromContextError(ctx.Err()).Code(), "canceled")
		case <-deadline.C:
			t.Stop()
			return &runnerv1.LeaseResponse{}, nil
		case <-t.C:
		}
		wait = min(wait*2, maxLeasePoll)
	}
}

// maxLeasePoll caps the backoff between queue checks in one Lease call.
const maxLeasePoll = 4 * time.Second

// maxPollsPerRunner bounds concurrent Lease calls per runner.
const maxPollsPerRunner = 2

// pollLimiter counts in-flight Lease calls per runner.
type pollLimiter struct {
	mu       sync.Mutex
	inFlight map[string]int
}

func (p *pollLimiter) acquire(runnerID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inFlight == nil {
		p.inFlight = map[string]int{}
	}
	if p.inFlight[runnerID] >= maxPollsPerRunner {
		return false
	}
	p.inFlight[runnerID]++
	return true
}

func (p *pollLimiter) release(runnerID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inFlight[runnerID]--; p.inFlight[runnerID] <= 0 {
		delete(p.inFlight, runnerID)
	}
}

// jobMessage builds what the runner needs. Event data (branch, PR number)
// is untrusted and reaches steps only as environment variables (T-24).
func (h *handlers) jobMessage(ctx context.Context, l *scheduler.Lease) (*runnerv1.Job, error) {
	env := make([]*runnerv1.EnvVar, 0, len(l.Job.Env)+10)
	for _, e := range l.Job.Env {
		env = append(env, &runnerv1.EnvVar{Name: e.Name, Value: e.Value})
	}
	pr := ""
	if l.Run.PRNumber > 0 {
		pr = strconv.Itoa(l.Run.PRNumber)
	}
	for _, kv := range [][2]string{
		{"CI", "true"},
		{"KILN_RUN_ID", l.Run.ID},
		{"KILN_JOB_ID", l.Job.ID},
		{"KILN_COMMIT_SHA", l.Run.CommitSHA},
		{"KILN_REF", l.Run.Ref},
		{"KILN_BRANCH", l.Run.Branch},
		{"KILN_EVENT", string(l.Run.Event)},
		{"KILN_PR_NUMBER", pr},
		{"KILN_IS_FORK", strconv.FormatBool(l.Run.IsFork)},
	} {
		env = append(env, &runnerv1.EnvVar{Name: kv[0], Value: kv[1]})
	}
	steps := make([]*runnerv1.Step, len(l.Job.Steps))
	for i, st := range l.Job.Steps {
		se := make([]*runnerv1.EnvVar, len(st.Env))
		for j, e := range st.Env {
			se[j] = &runnerv1.EnvVar{Name: e.Name, Value: e.Value}
		}
		steps[i] = &runnerv1.Step{Name: st.Name, Run: st.Run, Env: se, TimeoutSeconds: int64(st.Timeout / time.Second)}
	}
	job := &runnerv1.Job{
		JobId: l.Job.ID, LeaseId: l.ID, LeaseExpiresAtUnixMs: l.ExpiresAt.UnixMilli(), RunId: l.Run.ID,
		Name: l.Job.Name, Image: l.Job.Image, Steps: steps, Env: env,
		TimeoutSeconds: int64(l.Job.Timeout / time.Second), Trusted: l.Job.Trusted,
		Checkout: &runnerv1.Checkout{CommitSha: l.Run.CommitSHA},
	}
	if h.svc.Checkout != nil {
		co, err := h.svc.Checkout.Checkout(ctx, l.Run)
		if err != nil {
			return nil, err //nolint:wrapcheck // mapped by toStatus
		}
		job.Checkout.RepositoryUrl = co.RepositoryURL
		job.Checkout.AuthorizationHeader = co.AuthorizationHeader
		if co.AuthorizationHeader != "" {
			job.MaskValues = append(job.MaskValues, co.AuthorizationHeader)
		}
	}
	return job, nil
}

func (h *handlers) Heartbeat(ctx context.Context, req *runnerv1.HeartbeatRequest) (*runnerv1.HeartbeatResponse, error) {
	runner, _ := runnerFrom(ctx)
	res, err := h.svc.Scheduler.Heartbeat(ctx, runner, req.GetJobId(), req.GetLeaseId())
	if err != nil {
		return nil, h.toStatus(ctx, runnerv1.RunnerService_Heartbeat_FullMethodName, err)
	}
	return &runnerv1.HeartbeatResponse{LeaseExpiresAtUnixMs: res.ExpiresAt.UnixMilli(), Cancel: res.Cancel, CancelReason: res.Reason}, nil
}

func (h *handlers) CompleteJob(ctx context.Context, req *runnerv1.CompleteJobRequest) (*runnerv1.CompleteJobResponse, error) {
	runner, _ := runnerFrom(ctx)
	var st domain.JobStatus
	switch req.GetResult() {
	case runnerv1.JobResult_JOB_RESULT_SUCCEEDED:
		st = domain.JobSucceeded
	case runnerv1.JobResult_JOB_RESULT_FAILED:
		st = domain.JobFailed
	case runnerv1.JobResult_JOB_RESULT_CANCELED:
		st = domain.JobCanceled
	default:
		return nil, status.Error(codes.InvalidArgument, "result: must be succeeded, failed, or canceled")
	}
	res := scheduler.Result{Status: st, Reason: req.GetFailureReason()}
	if req.ExitCode != nil {
		c := int(req.GetExitCode())
		res.ExitCode = &c
	}
	if err := h.svc.Scheduler.Complete(ctx, runner, req.GetJobId(), req.GetLeaseId(), res); err != nil {
		return nil, h.toStatus(ctx, runnerv1.RunnerService_CompleteJob_FullMethodName, err)
	}
	// Wake live log readers so their streams end promptly.
	h.svc.Logs.Notify(ctx, runner.OrgID, req.GetJobId())
	return &runnerv1.CompleteJobResponse{}, nil
}

func (h *handlers) AppendLogs(ctx context.Context, req *runnerv1.AppendLogsRequest) (*runnerv1.AppendLogsResponse, error) {
	runner, _ := runnerFrom(ctx)
	truncated, err := h.svc.Logs.Append(ctx, runner, req.GetJobId(), req.GetLeaseId(), int(req.GetSeq()), req.GetData())
	if err != nil {
		return nil, h.toStatus(ctx, runnerv1.RunnerService_AppendLogs_FullMethodName, err)
	}
	return &runnerv1.AppendLogsResponse{Truncated: truncated}, nil
}
