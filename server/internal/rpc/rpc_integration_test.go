// SPDX-License-Identifier: Apache-2.0

//go:build integration

package rpc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	runnerv1 "github.com/yamatrireddy/kilnci/proto/gen/go/kiln/runner/v1"
	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/engine/spec"
	"github.com/yamatrireddy/kilnci/server/internal/platform/bus"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/platform/objstore"
	"github.com/yamatrireddy/kilnci/server/internal/platform/pki"
	"github.com/yamatrireddy/kilnci/server/internal/rpc"
	"github.com/yamatrireddy/kilnci/server/internal/scheduler"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/service/logs"
	"github.com/yamatrireddy/kilnci/server/internal/service/runners"
	"github.com/yamatrireddy/kilnci/server/internal/service/runs"
	"github.com/yamatrireddy/kilnci/server/internal/store/storetest"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

type env struct {
	t        *testing.T
	logs     *logs.Service
	addr     string
	ca       *pki.CA
	clk      *clock
	runners  *runners.Service
	runs     *runs.Service
	recorder *audit.Recorder
	org      domain.Org
	project  domain.Project
	admin    *authz.Principal
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := t.Context()
	st := storetest.New(t)
	gen := ids.NewGenerator(nil)
	// Start 7h in the past so a renewal can happen "later" while every
	// issued certificate stays valid in real time.
	clk := &clock{t: time.Now().UTC().Add(-7 * time.Hour)}
	dir := t.TempDir() + "/ca"
	if err := pki.Init(dir, time.Now().Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	az := authz.NewAuthorizer(st)
	rec := audit.NewRecorder(st, gen, clk.now)
	// The clock runs hours behind, so a default lease would already have
	// lapsed for other packages' tests, whose reapers scan the shared
	// database; a lease that outlives the offset keeps them off these jobs.
	sched := scheduler.New(st, logging.Discard(), scheduler.Options{LeaseTTL: 24 * time.Hour}, clk.now)
	runnerSvc := runners.NewService(st, az, rec, ca, gen, clk.now)
	runSvc := runs.NewService(st, az, rec, sched.Progressor(), gen, clk.now)

	obj, err := objstore.NewFS(t.TempDir() + "/logs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = obj.Close() })
	logSvc := logs.NewService(st, az, obj, bus.NewInProcess(), logs.Options{}, clk.now)
	srv, err := rpc.New(logging.Discard(), rpc.Services{Runners: runnerSvc, Scheduler: sched, Logs: logSvc},
		rpc.Options{CA: ca, Hostnames: []string{"127.0.0.1"}, LeaseWait: 300 * time.Millisecond, LeasePoll: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(sctx, lis, time.Second)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	org, err := st.CreateOrg(ctx, domain.Org{ID: gen.New(), Slug: storetest.Unique("o"), Name: "O", CreatedAt: clk.now()})
	if err != nil {
		t.Fatal(err)
	}
	proj, err := st.CreateProject(ctx, domain.Project{ID: gen.New(), OrgID: org.ID, Slug: "p", Name: "P", CreatedAt: clk.now()})
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.CreateUser(ctx, domain.User{ID: gen.New(), Issuer: "https://idp.test", Subject: storetest.Unique("s"),
		Email: storetest.Unique("a") + "@kiln.test", DisplayName: "A", CreatedAt: clk.now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddMembership(ctx, domain.Membership{OrgID: org.ID, UserID: u.ID, Role: domain.RoleAdmin}, clk.now()); err != nil {
		t.Fatal(err)
	}
	return &env{t: t, logs: logSvc, addr: lis.Addr().String(), ca: ca, clk: clk, runners: runnerSvc, runs: runSvc, recorder: rec, org: org, project: proj,
		admin: &authz.Principal{Kind: authz.KindUser, Method: authz.MethodSession, UserID: u.ID}}
}

// dial connects, trusting only the Kiln CA, optionally with a client cert.
func (e *env) dial(cert *tls.Certificate) runnerv1.RunnerServiceClient {
	e.t.Helper()
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: e.ca.Pool(), ServerName: "127.0.0.1"}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	conn, err := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = conn.Close() })
	return runnerv1.NewRunnerServiceClient(conn)
}

func (e *env) token(labels []string) string {
	e.t.Helper()
	tok, _, err := e.runners.CreateRegistrationToken(authz.WithPrincipal(e.t.Context(), e.admin), e.org.Slug, labels, false, time.Hour)
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func newKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, csr
}

func certOf(der []byte, key *ecdsa.PrivateKey) *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func code(err error) codes.Code { return status.Code(err) }

const v1 = rpc.ProtocolVersion

func (e *env) register(labels []string) (string, *tls.Certificate) {
	e.t.Helper()
	key, csr := newKey(e.t)
	resp, err := e.dial(nil).Register(e.t.Context(), &runnerv1.RegisterRequest{
		ProtocolVersion: v1, RegistrationToken: e.token(labels), CsrDer: csr, Name: "builder-1", Version: "1.0.0",
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return resp.GetRunnerId(), certOf(resp.GetCertificateDer(), key)
}

func TestRunnerProtocol_EndToEnd(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()

	key, csr := newKey(t)
	tok := e.token([]string{"linux"})
	anon := e.dial(nil)
	resp, err := anon.Register(ctx, &runnerv1.RegisterRequest{ProtocolVersion: v1, RegistrationToken: tok, CsrDer: csr, Name: "builder-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, runners.TokenPrefix) || resp.GetRunnerId() == "" || len(resp.GetCaCertificateDer()) == 0 {
		t.Fatalf("register response = %+v", resp)
	}
	// Single use.
	_, csr2 := newKey(t)
	if _, err := anon.Register(ctx, &runnerv1.RegisterRequest{ProtocolVersion: v1, RegistrationToken: tok, CsrDer: csr2, Name: "x"}); code(err) != codes.Unauthenticated {
		t.Fatalf("token reuse = %v", err)
	}
	if _, err := anon.Register(ctx, &runnerv1.RegisterRequest{ProtocolVersion: v1, RegistrationToken: runners.TokenPrefix + "guess", CsrDer: csr2, Name: "x"}); code(err) != codes.Unauthenticated {
		t.Fatalf("unknown token = %v", err)
	}
	// Runner-only methods without a client certificate.
	if _, err := anon.Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: v1}); code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous lease = %v", err)
	}

	client := e.dial(certOf(resp.GetCertificateDer(), key))
	if _, err := client.Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: 99}); code(err) != codes.FailedPrecondition {
		t.Fatalf("bad protocol version = %v", err)
	}
	empty, err := client.Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: v1})
	if err != nil || empty.GetJob() != nil {
		t.Fatalf("empty lease = %v %v", empty, err)
	}

	// The timeout outlasts the clock's offset, for the same reason as the lease TTL.
	pl, _ := spec.Parse([]byte("version: 1\njobs:\n  build:\n    image: alpine\n    runs-on: [linux]\n    timeout: 12h\n    env: {A: b}\n    steps: [{name: Build, run: make}]\n"))
	run, err := e.runs.CreateRun(ctx, runs.NewRun{OrgID: e.org.ID, ProjectID: e.project.ID, Event: domain.EventPush,
		Ref: "refs/heads/main", Branch: "main", CommitSHA: strings.Repeat("d", 40), Trusted: true, Pipeline: pl})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := client.Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: v1})
	if err != nil || lease.GetJob() == nil {
		t.Fatalf("lease = %v %v", lease, err)
	}
	job := lease.GetJob()
	env := map[string]string{}
	for _, kv := range job.GetEnv() {
		env[kv.GetName()] = kv.GetValue()
	}
	if job.GetRunId() != run.ID || job.GetImage() != "alpine" || job.GetSteps()[0].GetRun() != "make" ||
		env["KILN_BRANCH"] != "main" || env["KILN_IS_FORK"] != "false" || env["A"] != "b" || env["CI"] != "true" ||
		job.GetCheckout().GetCommitSha() != run.CommitSHA || !job.GetTrusted() {
		t.Fatalf("job = %+v", job)
	}
	for i, chunk := range []string{"==> Step 1/1: Build\n", "ok\n"} {
		if _, err := client.AppendLogs(ctx, &runnerv1.AppendLogsRequest{ProtocolVersion: v1, JobId: job.GetJobId(), LeaseId: job.GetLeaseId(),
			Seq: uint32(i), Data: []byte(chunk)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if _, err := client.AppendLogs(ctx, &runnerv1.AppendLogsRequest{ProtocolVersion: v1, JobId: job.GetJobId(), LeaseId: job.GetLeaseId(),
		Seq: 1, Data: []byte("tampered\n")}); code(err) != codes.Aborted {
		t.Fatalf("conflicting replay = %v", err)
	}
	if _, err := anon.AppendLogs(ctx, &runnerv1.AppendLogsRequest{ProtocolVersion: v1, JobId: job.GetJobId(), LeaseId: job.GetLeaseId(),
		Seq: 2, Data: []byte("x")}); code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous append = %v", err)
	}
	var logBuf strings.Builder
	if err := e.logs.Read(authz.WithPrincipal(ctx, e.admin), logs.JobRef{OrgSlug: e.org.Slug, ProjectSlug: e.project.Slug,
		RunID: run.ID, JobID: job.GetJobId()}, &logBuf); err != nil || logBuf.String() != "==> Step 1/1: Build\nok\n" {
		t.Fatalf("stored log = %q %v", logBuf.String(), err)
	}
	hb, err := client.Heartbeat(ctx, &runnerv1.HeartbeatRequest{ProtocolVersion: v1, JobId: job.GetJobId(), LeaseId: job.GetLeaseId()})
	if err != nil || hb.GetCancel() {
		t.Fatalf("heartbeat = %v %v", hb, err)
	}
	exit0 := int32(0)
	if _, err := client.CompleteJob(ctx, &runnerv1.CompleteJobRequest{ProtocolVersion: v1, JobId: job.GetJobId(), LeaseId: job.GetLeaseId(),
		Result: runnerv1.JobResult_JOB_RESULT_SUCCEEDED, ExitCode: &exit0}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CompleteJob(ctx, &runnerv1.CompleteJobRequest{ProtocolVersion: v1, JobId: job.GetJobId(), LeaseId: job.GetLeaseId(),
		Result: runnerv1.JobResult_JOB_RESULT_SUCCEEDED, ExitCode: &exit0}); code(err) != codes.NotFound {
		t.Fatalf("second complete = %v", err)
	}
	if _, err := client.CompleteJob(ctx, &runnerv1.CompleteJobRequest{ProtocolVersion: v1, JobId: job.GetJobId(), LeaseId: job.GetLeaseId()}); code(err) != codes.InvalidArgument {
		t.Fatalf("unspecified result = %v", err)
	}
	d, err := e.runs.GetRun(authz.WithPrincipal(ctx, e.admin), e.org.Slug, e.project.Slug, run.ID)
	if err != nil || d.Run.Status != domain.RunSucceeded {
		t.Fatalf("run = %+v %v", d.Run, err)
	}

	// Revocation takes effect on the next call.
	if err := e.runners.RevokeRunner(authz.WithPrincipal(ctx, e.admin), e.org.Slug, resp.GetRunnerId()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: v1}); code(err) != codes.Unauthenticated {
		t.Fatalf("revoked runner lease = %v", err)
	}
	if err := e.recorder.VerifyChain(ctx, e.org.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerProtocol_LabelsComeFromTheServer(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	_, cert := e.register([]string{"small"})
	pl, _ := spec.Parse([]byte("version: 1\njobs:\n  gpu:\n    image: alpine\n    runs-on: [gpu]\n    steps: [{run: x}]\n"))
	if _, err := e.runs.CreateRun(ctx, runs.NewRun{OrgID: e.org.ID, ProjectID: e.project.ID, Event: domain.EventPush,
		Ref: "refs/heads/main", CommitSHA: strings.Repeat("e", 40), Trusted: true, Pipeline: pl}); err != nil {
		t.Fatal(err)
	}
	lease, err := e.dial(cert).Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: v1})
	if err != nil || lease.GetJob() != nil {
		t.Fatalf("runner without the gpu label leased %v %v", lease, err)
	}
}

func TestRunnerProtocol_CertificateRenewalAndReuse(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	_, cert := e.register(nil)
	old := e.dial(cert)

	// Too soon after registration.
	_, csr := newKey(t)
	if _, err := old.RenewCertificate(ctx, &runnerv1.RenewCertificateRequest{ProtocolVersion: v1, CsrDer: csr}); code(err) != codes.ResourceExhausted {
		t.Fatalf("early renewal = %v", err)
	}
	e.clk.set(time.Now().UTC())
	key2, csr2 := newKey(t)
	renewed, err := old.RenewCertificate(ctx, &runnerv1.RenewCertificateRequest{ProtocolVersion: v1, CsrDer: csr2})
	if err != nil {
		t.Fatal(err)
	}
	fresh := e.dial(certOf(renewed.GetCertificateDer(), key2))
	if _, err := fresh.Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: v1}); err != nil {
		t.Fatalf("lease with renewed cert: %v", err)
	}
	// The previous certificate still works briefly for ordinary calls...
	if _, err := old.Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: v1}); err != nil {
		t.Fatalf("lease with previous cert during grace: %v", err)
	}
	// ...but renewing from it means two holders: the runner is revoked.
	_, csr3 := newKey(t)
	if _, err := old.RenewCertificate(ctx, &runnerv1.RenewCertificateRequest{ProtocolVersion: v1, CsrDer: csr3}); code(err) != codes.Unauthenticated {
		t.Fatalf("renewal from previous serial = %v", err)
	}
	if _, err := fresh.Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: v1}); code(err) != codes.Unauthenticated {
		t.Fatalf("runner not revoked after reuse: %v", err)
	}
}

func TestRunnerProtocol_RejectsForeignCertificates(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	// A certificate from another CA never verifies.
	otherDir := t.TempDir() + "/other"
	if err := pki.Init(otherDir, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	other, _ := pki.Load(otherDir)
	key, csr := newKey(t)
	id := ids.NewGenerator(nil)
	iss, err := other.SignRunnerCSR(csr, id.New(), e.org.ID, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.dial(certOf(iss.DER, key)).Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: v1})
	if err == nil {
		t.Fatal("foreign-CA certificate accepted")
	}
	// A validly signed certificate for a runner that does not exist.
	iss, err = e.ca.SignRunnerCSR(csr, id.New(), e.org.ID, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.dial(certOf(iss.DER, key)).Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: v1}); code(err) != codes.Unauthenticated {
		t.Fatalf("unknown runner = %v", err)
	}
}

func TestRunnerProtocol_ReuseOutsideGraceRevokes(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	_, cert := e.register(nil)
	old := e.dial(cert)
	e.clk.set(time.Now().UTC())
	key2, csr2 := newKey(t)
	renewed, err := old.RenewCertificate(ctx, &runnerv1.RenewCertificateRequest{ProtocolVersion: v1, CsrDer: csr2})
	if err != nil {
		t.Fatal(err)
	}
	fresh := e.dial(certOf(renewed.GetCertificateDer(), key2))
	// Past the grace period, the old certificate means someone kept a copy.
	e.clk.set(time.Now().UTC().Add(10 * time.Minute))
	if _, err := old.Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: v1}); code(err) != codes.Unauthenticated {
		t.Fatalf("stale cert = %v", err)
	}
	if _, err := fresh.Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: v1}); code(err) != codes.Unauthenticated {
		t.Fatalf("runner not revoked after stale-cert use: %v", err)
	}
	if err := e.recorder.VerifyChain(ctx, e.org.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerProtocol_RenewalRetryIsIdempotent(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	_, cert := e.register(nil)
	old := e.dial(cert)
	e.clk.set(time.Now().UTC())
	key2, csr2 := newKey(t)
	first, err := old.RenewCertificate(ctx, &runnerv1.RenewCertificateRequest{ProtocolVersion: v1, CsrDer: csr2})
	if err != nil {
		t.Fatal(err)
	}
	// The response was "lost": the runner retries with its old cert and the
	// same pending key, and gets the same certificate back.
	again, err := old.RenewCertificate(ctx, &runnerv1.RenewCertificateRequest{ProtocolVersion: v1, CsrDer: csr2})
	if err != nil || string(again.GetCertificateDer()) != string(first.GetCertificateDer()) {
		t.Fatalf("retry = %v", err)
	}
	if _, err := e.dial(certOf(again.GetCertificateDer(), key2)).Lease(ctx, &runnerv1.LeaseRequest{ProtocolVersion: v1}); err != nil {
		t.Fatalf("runner revoked by an idempotent retry: %v", err)
	}
	// A retry with a different key is reuse.
	_, csr3 := newKey(t)
	if _, err := old.RenewCertificate(ctx, &runnerv1.RenewCertificateRequest{ProtocolVersion: v1, CsrDer: csr3}); code(err) != codes.Unauthenticated {
		t.Fatalf("different-key retry = %v", err)
	}
}

func TestRunnerProtocol_ConcurrentPollsAreCapped(t *testing.T) {
	e := newEnv(t)
	_, cert := e.register(nil)
	client := e.dial(cert)
	var wg sync.WaitGroup
	codesSeen := make(chan codes.Code, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.Lease(t.Context(), &runnerv1.LeaseRequest{ProtocolVersion: v1})
			codesSeen <- code(err)
		}()
	}
	wg.Wait()
	close(codesSeen)
	limited := 0
	for c := range codesSeen {
		if c == codes.ResourceExhausted {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("4 concurrent polls from one runner were all accepted")
	}
}
