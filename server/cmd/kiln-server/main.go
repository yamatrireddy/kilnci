// SPDX-License-Identifier: Apache-2.0

// Command kiln-server runs the Kiln control plane. This file only wires
// components together; behavior lives in internal packages.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/yamatrireddy/kilnci/server/internal/api"
	"github.com/yamatrireddy/kilnci/server/internal/auth"
	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/platform/config"
	"github.com/yamatrireddy/kilnci/server/internal/platform/httpclient"
	"github.com/yamatrireddy/kilnci/server/internal/platform/httpserver"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/platform/telemetry"
	"github.com/yamatrireddy/kilnci/server/internal/scheduler"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/service/orgs"
	"github.com/yamatrireddy/kilnci/server/internal/service/runs"
	"github.com/yamatrireddy/kilnci/server/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(mainCode())
}

// mainCode runs the server and returns the process exit code, so deferred
// cleanup runs before os.Exit.
func mainCode() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], config.OSSource(), os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "kiln-server:", err)
		return 1
	}
	return 0
}

func run(ctx context.Context, args []string, src config.Source, stderr io.Writer) error {
	flags := flag.NewFlagSet("kiln-server", flag.ContinueOnError)
	flags.SetOutput(stderr)
	embedded := flags.Bool("embedded", false, "single-binary mode: needs only PostgreSQL")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	cfg, err := config.Load(src, *embedded)
	if err != nil {
		return err //nolint:wrapcheck // already a complete, user-facing message
	}
	log := logging.New(stderr, logging.Options{Level: cfg.Log.Level, Format: cfg.Log.Format})
	log.InfoContext(ctx, "starting kiln-server", "version", version, "env", cfg.Env, "embedded", cfg.Embedded)
	if cfg.HTTP.TLSMode == config.TLSModeUpstream && len(cfg.HTTP.TrustedProxies) == 0 && !cfg.IsDevelopment() {
		log.WarnContext(ctx, "KILN_TLS_MODE=upstream but KILN_TRUSTED_PROXIES is empty: every client will share "+
			"the proxy's rate-limit bucket and audit records will show the proxy address")
	}

	egress := httpclient.New(httpclient.Options{AllowedPrefixes: cfg.HTTP.EgressAllowedPrefixes})
	shutdownTracing, err := telemetry.Setup(ctx, telemetry.Options{
		ServiceVersion: version,
		OTLPEndpoint:   cfg.Tracing.OTLPEndpoint,
		Insecure:       cfg.Tracing.Insecure,
		HTTPClient:     egress,
	})
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}
	defer func() {
		if err := shutdownTracing(context.WithoutCancel(ctx)); err != nil {
			log.WarnContext(ctx, "flush traces", "error", err)
		}
	}()

	st, err := store.Open(ctx, store.Options{URL: cfg.DB.URL.Reveal(), MaxConns: cfg.DB.MaxConns})
	if err != nil {
		return err //nolint:wrapcheck // store errors are already contextual and credential-free
	}
	defer st.Close()
	if cfg.DB.MigrateOnStart {
		if err := st.Migrate(ctx, log); err != nil {
			return err //nolint:wrapcheck // contextual
		}
	}

	gen := ids.NewGenerator(nil)
	authorizer := authz.NewAuthorizer(st)
	recorder := audit.NewRecorder(st, gen, nil)
	idp := auth.NewOIDCProvider(auth.OIDCOptions{
		IssuerURL:    cfg.OIDC.IssuerURL,
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret.Reveal(),
		RedirectURL:  cfg.PublicOrigin() + "/api/v1/auth/callback",
		HTTPClient:   egress,
	})
	authSvc := auth.NewService(st, idp, recorder, authorizer, gen, log, nil, auth.Options{
		PublicOrigin:           cfg.PublicOrigin(),
		SessionIdleTimeout:     cfg.Auth.SessionIdleTimeout,
		SessionAbsoluteTimeout: cfg.Auth.SessionAbsoluteTimeout,
		AccessTokenTTL:         cfg.Auth.DesktopAccessTokenTTL,
		RefreshTokenTTL:        cfg.Auth.DesktopRefreshTokenTTL,
		AutoProvision:          cfg.Auth.AutoProvision,
		AllowedEmailDomains:    cfg.Auth.AllowedEmailDomains,
		BootstrapAdminEmails:   cfg.Auth.BootstrapAdminEmails,
		RequiredAMR:            cfg.OIDC.RequiredAMR,
	})
	orgSvc := orgs.NewService(st, authorizer, recorder, gen, nil)
	sched := scheduler.New(st, log, scheduler.Options{}, nil)
	runSvc := runs.NewService(st, authorizer, recorder, sched.Progressor(), gen, nil)

	var webFS fs.FS
	if cfg.Web.Dir != "" {
		webFS = os.DirFS(cfg.Web.Dir)
	}
	handler, _, err := api.NewHandler(api.Deps{
		Log:    log,
		IDs:    gen,
		Authn:  authSvc,
		Auth:   authSvc,
		Orgs:   orgSvc,
		Runs:   runSvc,
		Checks: map[string]api.ReadinessCheck{"database": st.Ping},
		Options: api.Options{
			MaxBodyBytes:   cfg.HTTP.MaxBodyBytes,
			AllowedOrigins: cfg.HTTP.AllowedOrigins,
			TrustedProxies: cfg.HTTP.TrustedProxies,
			HSTS:           cfg.HTTP.PublicURL.Scheme == "https",
			WebFS:          webFS,
		},
	})
	if err != nil {
		return fmt.Errorf("build http handler: %w", err)
	}

	srvOpts := httpserver.Options{
		Addr:              cfg.HTTP.Addr,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		ShutdownTimeout:   cfg.HTTP.ShutdownTimeout,
	}
	if cfg.HTTP.TLSMode == config.TLSModeServer {
		srvOpts.TLSCertFile, srvOpts.TLSKeyFile = cfg.HTTP.TLSCertFile, cfg.HTTP.TLSKeyFile
	}
	// Background work is owned by this errgroup and stops with ctx.
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		authSvc.RunJanitor(gctx, 10*time.Minute)
		return nil
	})
	g.Go(func() error {
		sched.RunReaper(gctx)
		return nil
	})
	g.Go(func() error { return httpserver.Serve(gctx, log, srvOpts, handler, nil) })
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("serve: %w", err)
	}
	log.InfoContext(ctx, "kiln-server stopped")
	return nil
}
