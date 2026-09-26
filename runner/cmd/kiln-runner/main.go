// SPDX-License-Identifier: Apache-2.0

// Command kiln-runner registers with a Kiln server and runs jobs in hardened
// Docker containers. This file only wires components together.
//
//	kiln-runner register --server HOST:PORT --ca-file ca.crt --token-file FILE --name NAME --state-dir DIR
//	kiln-runner run --state-dir DIR --egress-policy host-enforced|none
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/moby/moby/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	runnerv1 "github.com/yamatrireddy/kilnci/proto/gen/go/kiln/runner/v1"
	"github.com/yamatrireddy/kilnci/runner/executor/docker"
	"github.com/yamatrireddy/kilnci/runner/internal/agent"
	"github.com/yamatrireddy/kilnci/runner/internal/identity"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(mainCode())
}

func mainCode() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "kiln-runner:", err)
		return 1
	}
	return 0
}

const usage = `usage:
  kiln-runner register --server HOST:PORT --ca-file ca.crt --token-file FILE|- --name NAME --state-dir DIR
  kiln-runner run --state-dir DIR --egress-policy host-enforced|none`

func run(ctx context.Context, args []string, stdin io.Reader, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "register":
		return register(ctx, args[1:], stdin, stderr)
	case "run":
		return runAgent(ctx, args[1:], stderr)
	default:
		return errors.New(usage)
	}
}

func register(ctx context.Context, args []string, stdin io.Reader, stderr io.Writer) error {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", "", "Kiln runner endpoint, host:port")
	caFile := fs.String("ca-file", "", "the Kiln runner CA certificate (required: it is pinned)")
	tokenFile := fs.String("token-file", "", "file holding the registration token, or - for stdin (never pass tokens as arguments)")
	name := fs.String("name", "", "display name for this runner")
	stateDir := fs.String("state-dir", "", "directory for this runner's key and certificate (mode 0700)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	if *server == "" || *caFile == "" || *tokenFile == "" || *name == "" || *stateDir == "" {
		return errors.New(usage)
	}
	caPEM, err := readOperatorFile(*caFile)
	if err != nil {
		return fmt.Errorf("read CA: %w", err)
	}
	tokenBytes, err := readOperatorInput(*tokenFile, stdin)
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}
	tlsCfg, err := identity.TLSForRegistration(*server, caPEM)
	if err != nil {
		return err //nolint:wrapcheck // contextual
	}
	conn, err := grpc.NewClient(*server, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close() }()
	id, err := identity.Register(ctx, runnerv1.NewRunnerServiceClient(conn), *stateDir, *server, caPEM,
		strings.TrimSpace(string(tokenBytes)), *name, version)
	if err != nil {
		return err //nolint:wrapcheck // contextual
	}
	defer func() { _ = id.Close() }()
	_, _ = fmt.Fprintf(stderr, "registered runner %s\n", id.RunnerID())
	return nil
}

// readOperatorInput reads at most 256 bytes from stdin when path is "-", and
// otherwise reads the operator-supplied file at path.
func readOperatorInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		b, err := io.ReadAll(io.LimitReader(stdin, 256))
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return b, nil
	}
	return readOperatorFile(path)
}

// readOperatorFile reads a small file the operator named on the command line.
func readOperatorFile(path string) ([]byte, error) {
	b, err := fs.ReadFile(os.DirFS(filepath.Dir(path)), filepath.Base(path))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	return b, nil
}

// grpcConn re-dials after a certificate renewal so new TLS sessions present
// the new certificate.
type grpcConn struct {
	id     *identity.Identity
	mu     sync.Mutex
	conn   *grpc.ClientConn
	client runnerv1.RunnerServiceClient
}

func (c *grpcConn) dial() error {
	cfg, err := c.id.ClientTLS()
	if err != nil {
		return err //nolint:wrapcheck // contextual
	}
	conn, err := grpc.NewClient(c.id.Server(), grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(8<<20)))
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	c.mu.Lock()
	old := c.conn
	c.conn, c.client = conn, runnerv1.NewRunnerServiceClient(conn)
	c.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (c *grpcConn) Client() agent.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.client
}

func (c *grpcConn) Reconnect() error { return c.dial() }

func runAgent(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", "", "directory written by `kiln-runner register`")
	egress := fs.String("egress-policy", "", "host-enforced: the host firewall blocks metadata and private ranges for job containers (see docs); none: accept the risk (every job log shows a warning)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	if *stateDir == "" || (*egress != "host-enforced" && *egress != "none") {
		return errors.New(usage)
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	id, err := identity.Load(*stateDir)
	if err != nil {
		return err //nolint:wrapcheck // contextual
	}
	defer func() { _ = id.Close() }()
	docker0, err := client.New(client.FromEnv)
	if err != nil {
		return fmt.Errorf("docker client: %w", err)
	}
	defer func() { _ = docker0.Close() }()
	exec, err := docker.New(docker0, docker.Options{Log: log})
	if err != nil {
		return err //nolint:wrapcheck // contextual
	}
	conn := &grpcConn{id: id}
	if err := conn.dial(); err != nil {
		return err
	}
	if *egress == "none" {
		log.WarnContext(ctx, "egress policy is none: jobs may reach cloud metadata and private networks")
	}
	log.InfoContext(ctx, "kiln-runner started", "runner_id", id.RunnerID(), "server", id.Server(), "version", version)
	a := agent.New(conn, id, exec, agent.Options{EgressUnrestricted: *egress == "none", Log: log})
	if err := a.Run(ctx); !errors.Is(err, context.Canceled) {
		return err //nolint:wrapcheck // contextual
	}
	log.InfoContext(ctx, "kiln-runner stopped")
	return nil
}
