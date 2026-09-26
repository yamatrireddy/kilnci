// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runnerv1 "github.com/yamatrireddy/kilnci/proto/gen/go/kiln/runner/v1"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/scheduler"
)

func TestCheckPolicy(t *testing.T) {
	if err := checkPolicy(runnerv1.RunnerService_ServiceDesc); err != nil {
		t.Fatalf("real service must be fully covered: %v", err)
	}
	desc := runnerv1.RunnerService_ServiceDesc
	desc.Methods = append(append([]grpc.MethodDesc{}, desc.Methods...), grpc.MethodDesc{MethodName: "Backdoor"})
	if err := checkPolicy(desc); err == nil || !strings.Contains(err.Error(), "Backdoor") {
		t.Fatalf("unlisted method accepted: %v", err)
	}
	desc = runnerv1.RunnerService_ServiceDesc
	desc.Streams = []grpc.StreamDesc{{StreamName: "Tail"}}
	if err := checkPolicy(desc); err == nil {
		t.Fatal("stream accepted")
	}
}

func TestNew_RequiresCAAndServices(t *testing.T) {
	if _, err := New(logging.Discard(), Services{}, Options{}); err == nil {
		t.Fatal("New without a CA succeeded")
	}
}

func TestToStatus(t *testing.T) {
	h := &handlers{log: logging.Discard()}
	cases := []struct {
		err  error
		want codes.Code
	}{
		{domain.ErrUnauthenticated, codes.Unauthenticated},
		{domain.NewValidationError("csr", "bad"), codes.InvalidArgument},
		{scheduler.ErrLeaseLost, codes.NotFound},
		{fmt.Errorf("x: %w", domain.ErrNotFound), codes.NotFound},
		{domain.ErrRateLimited, codes.ResourceExhausted},
		{domain.ErrConflict, codes.Aborted},
		{domain.ErrForbidden, codes.PermissionDenied},
		{context.Canceled, codes.Canceled},
		{errors.New("db exploded: secret detail"), codes.Internal},
	}
	for _, c := range cases {
		st := status.Convert(h.toStatus(context.Background(), "/m", c.err))
		if st.Code() != c.want {
			t.Errorf("toStatus(%v) = %v, want %v", c.err, st.Code(), c.want)
		}
		if strings.Contains(st.Message(), "secret detail") {
			t.Errorf("internal error detail leaked: %q", st.Message())
		}
	}
}

func TestAuthorize_DeniesUnknownMethodsAndBadVersions(t *testing.T) {
	h := &handlers{log: logging.Discard()}
	next := func(context.Context, any) (any, error) { return "ok", nil }
	_, err := h.authorize(context.Background(), &runnerv1.LeaseRequest{ProtocolVersion: ProtocolVersion},
		&grpc.UnaryServerInfo{FullMethod: "/kiln.runner.v1.RunnerService/Backdoor"}, next)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown method = %v", err)
	}
	for _, v := range []uint32{0, ProtocolVersion + 1} {
		_, err := h.authorize(context.Background(), &runnerv1.LeaseRequest{ProtocolVersion: v},
			&grpc.UnaryServerInfo{FullMethod: runnerv1.RunnerService_Lease_FullMethodName}, next)
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("version %d = %v", v, err)
		}
	}
	// A runner method with no TLS peer is unauthenticated.
	_, err = h.authorize(context.Background(), &runnerv1.LeaseRequest{ProtocolVersion: ProtocolVersion},
		&grpc.UnaryServerInfo{FullMethod: runnerv1.RunnerService_Lease_FullMethodName}, next)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no peer = %v", err)
	}
}

func TestRecoverer(t *testing.T) {
	h := &handlers{log: logging.Discard()}
	_, err := h.recoverer(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/m"}, func(context.Context, any) (any, error) {
		panic("boom")
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("panic = %v", err)
	}
}
