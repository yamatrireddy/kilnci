// SPDX-License-Identifier: Apache-2.0

// Package httpserver runs the HTTP listener with hardened timeouts, TLS
// settings, and bounded graceful shutdown.
package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Options configures Serve.
type Options struct {
	Addr              string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	// TLSCertFile and TLSKeyFile enable TLS when both are set.
	TLSCertFile string
	TLSKeyFile  string
}

const maxHeaderBytes = 64 << 10

// TLSConfig is the server TLS policy: TLS 1.2 minimum with modern AEAD suites
// (TLS 1.3 suites are not configurable and are all acceptable).
func TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
}

// Serve listens on opts.Addr and serves h until ctx is cancelled, then stops
// accepting connections and drains in-flight requests for at most
// opts.ShutdownTimeout. ready, if non-nil, receives the bound address.
func Serve(ctx context.Context, log *slog.Logger, opts Options, h http.Handler, ready chan<- net.Addr) error {
	srv := &http.Server{
		Addr:              opts.Addr,
		Handler:           h,
		ReadHeaderTimeout: opts.ReadHeaderTimeout,
		ReadTimeout:       opts.ReadTimeout,
		WriteTimeout:      opts.WriteTimeout,
		IdleTimeout:       opts.IdleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}
	useTLS := opts.TLSCertFile != "" && opts.TLSKeyFile != ""
	if useTLS {
		srv.TLSConfig = TLSConfig()
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", opts.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", opts.Addr, err)
	}
	if ready != nil {
		ready <- ln.Addr()
	}
	log.InfoContext(ctx, "http server listening", "addr", ln.Addr().String(), "tls", useTLS)

	errc := make(chan error, 1)
	go func() {
		if useTLS {
			errc <- srv.ServeTLS(ln, opts.TLSCertFile, opts.TLSKeyFile)
		} else {
			errc <- srv.Serve(ln)
		}
	}()

	select {
	case err := <-errc:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	log.InfoContext(ctx, "http server shutting down", "timeout", opts.ShutdownTimeout)
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opts.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}
