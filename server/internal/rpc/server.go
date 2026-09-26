// SPDX-License-Identifier: Apache-2.0

// Package rpc is the runner-facing gRPC transport (ADR-0005). It mirrors
// internal/api for runners: thin handlers that authenticate, call one
// service method, and map domain errors to gRPC status codes in exactly one
// place.
//
// Security properties:
//   - TLS 1.3 only, server certificate issued by the Kiln runner CA, client
//     certificates verified against that CA only.
//   - Deny by default (invariant 9): every method must have an entry in
//     methodPolicy, checked when the server is built. Register needs a
//     registration token; every other method needs a verified client
//     certificate of a live runner, re-checked against the database on
//     every call.
//   - Every request carries a supported protocol version.
//   - Per-IP limits on registration, per-runner limits on everything else,
//     bounded message sizes, and panics become Internal errors.
package rpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/net/netutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	runnerv1 "github.com/yamatrireddy/kilnci/proto/gen/go/kiln/runner/v1"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/pki"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ratelimit"
	"github.com/yamatrireddy/kilnci/server/internal/scheduler"
)

// Protocol versions this server accepts: the current one and the previous
// minor one (ADR-0005 §8).
const (
	ProtocolVersion    uint32 = 1
	MinProtocolVersion uint32 = 1
)

// rule is what a method requires of its caller.
type rule int

const (
	ruleRegistrationToken rule = iota + 1
	ruleRunnerCertificate
)

// methodPolicy lists every allowed method. A method missing here is denied,
// and New fails if the service exposes a method with no entry.
var methodPolicy = map[string]rule{
	runnerv1.RunnerService_Register_FullMethodName:         ruleRegistrationToken,
	runnerv1.RunnerService_RenewCertificate_FullMethodName: ruleRunnerCertificate,
	runnerv1.RunnerService_Lease_FullMethodName:            ruleRunnerCertificate,
	runnerv1.RunnerService_Heartbeat_FullMethodName:        ruleRunnerCertificate,
	runnerv1.RunnerService_CompleteJob_FullMethodName:      ruleRunnerCertificate,
	runnerv1.RunnerService_AppendLogs_FullMethodName:       ruleRunnerCertificate,
}

// Options configures the runner gRPC server.
type Options struct {
	// CA issues the server certificate and verifies client certificates.
	CA *pki.CA
	// Hostnames the server certificate is issued for.
	Hostnames []string
	// LeaseWait bounds how long Lease long-polls. Default 25s.
	LeaseWait time.Duration
	// LeasePoll is the first delay between queue checks in one Lease call;
	// it doubles up to 4s. Default 250ms.
	LeasePoll time.Duration
	// MaxConnections bounds concurrent runner connections. Default 1000.
	MaxConnections int
	// RegistrationsPerIP per minute. Default 10.
	RegistrationsPerIP float64
	// CallsPerRunner per minute. Default 600.
	CallsPerRunner float64
	Now            func() time.Time
}

// Services are what the handlers call.
type Services struct {
	Runners   RunnerIdentity
	Scheduler Scheduler
	Logs      LogSink
	// Checkout resolves where a run's code comes from; nil means jobs get no
	// checkout (Phase 1 before VCS integration is configured).
	Checkout CheckoutProvider
}

// Server is the runner gRPC server.
type Server struct {
	grpc     *grpc.Server
	log      *slog.Logger
	maxConns int
}

// New builds the server and validates the method policy.
func New(log *slog.Logger, svc Services, opts Options) (*Server, error) {
	if opts.CA == nil || len(opts.Hostnames) == 0 {
		return nil, errors.New("rpc: CA and hostnames are required")
	}
	if svc.Runners == nil || svc.Scheduler == nil || svc.Logs == nil {
		return nil, errors.New("rpc: runner, scheduler, and log services are required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.LeaseWait <= 0 {
		opts.LeaseWait = 25 * time.Second
	}
	if opts.LeasePoll <= 0 {
		opts.LeasePoll = 250 * time.Millisecond
	}
	if opts.MaxConnections <= 0 {
		opts.MaxConnections = 1000
	}
	if opts.RegistrationsPerIP <= 0 {
		opts.RegistrationsPerIP = 10
	}
	if opts.CallsPerRunner <= 0 {
		opts.CallsPerRunner = 600
	}
	if err := checkPolicy(runnerv1.RunnerService_ServiceDesc); err != nil {
		return nil, err
	}
	certs, err := newCertRotator(opts.CA, opts.Hostnames, opts.Now)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.VerifyClientCertIfGiven,
		ClientCAs:      opts.CA.Pool(),
		GetCertificate: certs.get,
		NextProtos:     []string{"h2"},
	}
	h := &handlers{
		log: log, svc: svc, opts: opts,
		regLimit:    ratelimit.New(opts.RegistrationsPerIP, 5, 100_000, opts.Now),
		runnerLimit: ratelimit.New(opts.CallsPerRunner, 60, 100_000, opts.Now),
	}
	gs := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		// A log chunk (256 KiB) plus framing is the largest request.
		grpc.MaxRecvMsgSize(1<<20),
		grpc.MaxSendMsgSize(4<<20),
		grpc.MaxConcurrentStreams(64),
		grpc.ConnectionTimeout(10*time.Second),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second}),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: 5 * time.Minute, Time: time.Minute, Timeout: 20 * time.Second}),
		grpc.ChainUnaryInterceptor(h.recoverer, h.authorize),
		grpc.ChainStreamInterceptor(denyStreams),
	)
	runnerv1.RegisterRunnerServiceServer(gs, h)
	return &Server{grpc: gs, log: log, maxConns: opts.MaxConnections}, nil
}

func checkPolicy(desc grpc.ServiceDesc) error {
	var missing []string
	for _, m := range desc.Methods {
		full := "/" + desc.ServiceName + "/" + m.MethodName
		if _, ok := methodPolicy[full]; !ok {
			missing = append(missing, full)
		}
	}
	for _, st := range desc.Streams {
		missing = append(missing, "/"+desc.ServiceName+"/"+st.StreamName+" (streams are not allowed)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("rpc: methods without a policy: %v", missing)
	}
	return nil
}

// Serve accepts connections on lis until ctx is done, then stops gracefully
// (bounded by shutdown).
func (s *Server) Serve(ctx context.Context, lis net.Listener, shutdown time.Duration) error {
	errc := make(chan error, 1)
	lis = netutil.LimitListener(lis, s.maxConns)
	go func() { errc <- s.grpc.Serve(lis) }()
	select {
	case err := <-errc:
		return fmt.Errorf("runner grpc: %w", err)
	case <-ctx.Done():
	}
	done := make(chan struct{})
	go func() {
		s.grpc.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdown):
		s.grpc.Stop()
	}
	return nil
}

// certRotator re-issues the in-memory server certificate before it expires.
type certRotator struct {
	ca        *pki.CA
	hostnames []string
	now       func() time.Time
	mu        sync.Mutex
	cert      *tls.Certificate
}

const serverCertTTL = 30 * 24 * time.Hour

func newCertRotator(ca *pki.CA, hostnames []string, now func() time.Time) (*certRotator, error) {
	r := &certRotator{ca: ca, hostnames: hostnames, now: now}
	if _, err := r.get(nil); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certRotator) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	// Re-issue daily, well before the 30-day expiry.
	if r.cert == nil || now.After(r.cert.Leaf.NotBefore.Add(24*time.Hour+5*time.Minute)) {
		c, err := r.ca.IssueServerCert(r.hostnames, now, serverCertTTL)
		if err != nil {
			return nil, fmt.Errorf("issue runner server certificate: %w", err)
		}
		r.cert = &c
	}
	return r.cert, nil
}

type runnerKey struct{}

func runnerFrom(ctx context.Context) (scheduler.Runner, bool) {
	r, ok := ctx.Value(runnerKey{}).(scheduler.Runner)
	return r, ok
}

type identityKey struct{}

func identityFrom(ctx context.Context) (pki.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(pki.Identity)
	return id, ok
}

type versioned interface{ GetProtocolVersion() uint32 }

func (h *handlers) recoverer(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if p := recover(); p != nil {
			h.log.ErrorContext(ctx, "runner rpc panic", "method", info.FullMethod, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			err = status.Error(codes.Internal, "internal error")
		}
	}()
	return next(ctx, req)
}

// authorize enforces methodPolicy, the protocol version, rate limits, and
// runner authentication before any handler runs.
func (h *handlers) authorize(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	r, ok := methodPolicy[info.FullMethod]
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "method not allowed")
	}
	v, ok := req.(versioned)
	if !ok || v.GetProtocolVersion() < MinProtocolVersion || v.GetProtocolVersion() > ProtocolVersion {
		return nil, status.Errorf(codes.FailedPrecondition, "unsupported protocol version (server accepts %d-%d)", MinProtocolVersion, ProtocolVersion)
	}
	switch r {
	case ruleRegistrationToken:
		if !h.regLimit.Allow(peerKey(ctx)) {
			return nil, status.Error(codes.ResourceExhausted, "too many registrations")
		}
		return next(ctx, req)
	case ruleRunnerCertificate:
		leaf, err := verifiedLeaf(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "client certificate required")
		}
		id, err := pki.RunnerIdentity(leaf)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid runner certificate")
		}
		if !h.runnerLimit.Allow(id.RunnerID) {
			return nil, status.Error(codes.ResourceExhausted, "rate limited")
		}
		runner, err := h.svc.Runners.Authenticate(ctx, id)
		if err != nil {
			return nil, h.toStatus(ctx, info.FullMethod, err)
		}
		ctx = context.WithValue(ctx, identityKey{}, id)
		ctx = context.WithValue(ctx, runnerKey{}, runner)
		return next(ctx, req)
	default:
		return nil, status.Error(codes.PermissionDenied, "method not allowed")
	}
}

func denyStreams(any, grpc.ServerStream, *grpc.StreamServerInfo, grpc.StreamHandler) error {
	return status.Error(codes.PermissionDenied, "streams are not allowed")
}

// verifiedLeaf returns the client certificate the TLS stack verified
// against the Kiln CA. Unverified presented certificates are ignored.
func verifiedLeaf(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return nil, errors.New("no verified client certificate")
	}
	return ti.State.VerifiedChains[0][0], nil
}

func peerKey(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "unknown"
	}
	ap, err := netip.ParseAddrPort(p.Addr.String())
	if err != nil {
		return "unknown"
	}
	return ratelimit.NetworkKey(ap.Addr())
}

// toStatus is the single mapping from domain errors to gRPC status codes.
// Unexpected errors are logged once and returned as a generic Internal.
func (h *handlers) toStatus(ctx context.Context, method string, err error) error {
	var ve *domain.ValidationError
	switch {
	case errors.Is(err, domain.ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, "unauthenticated")
	case errors.As(err, &ve):
		msg := "invalid request"
		if len(ve.Fields) > 0 {
			msg = ve.Fields[0].Field + ": " + ve.Fields[0].Message
		}
		return status.Error(codes.InvalidArgument, msg)
	case errors.Is(err, scheduler.ErrLeaseLost), errors.Is(err, domain.ErrNotFound):
		return status.Error(codes.NotFound, "lease not held")
	case errors.Is(err, domain.ErrRateLimited):
		return status.Error(codes.ResourceExhausted, "rate limited")
	case errors.Is(err, domain.ErrConflict):
		return status.Error(codes.Aborted, "conflict")
	case errors.Is(err, domain.ErrForbidden):
		return status.Error(codes.PermissionDenied, "permission denied")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.Error(status.FromContextError(err).Code(), "canceled")
	}
	h.log.ErrorContext(ctx, "runner rpc failed", "method", method, "error", err)
	return status.Error(codes.Internal, "internal error")
}
