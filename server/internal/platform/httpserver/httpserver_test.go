// SPDX-License-Identifier: Apache-2.0

package httpserver

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
)

func TestServe_ServesAndShutsDownGracefully(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started, release := make(chan struct{}), make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release // hold the request open across shutdown
		w.WriteHeader(http.StatusTeapot)
	})
	ready := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, logging.Discard(), Options{
			Addr: "127.0.0.1:0", ReadHeaderTimeout: time.Second, ReadTimeout: 5 * time.Second,
			WriteTimeout: 5 * time.Second, IdleTimeout: time.Second, ShutdownTimeout: 5 * time.Second,
		}, h, ready)
	}()
	addr := <-ready

	status := make(chan int, 1)
	go func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr.String()+"/", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			status <- -1
			return
		}
		_ = resp.Body.Close()
		status <- resp.StatusCode
	}()

	// Once the request is in flight, begin shutdown and then release it.
	<-started
	cancel()
	close(release)

	if got := <-status; got != http.StatusTeapot {
		t.Fatalf("in-flight request status = %d, want 418 (drained)", got)
	}
	if err := <-done; err != nil {
		t.Fatalf("Serve returned %v", err)
	}
}

func TestServe_ListenError(t *testing.T) {
	err := Serve(context.Background(), logging.Discard(), Options{Addr: "256.0.0.1:1"}, http.NotFoundHandler(), nil)
	if err == nil {
		t.Fatal("want listen error")
	}
}

func TestTLSConfig_MinimumVersion(t *testing.T) {
	c := TLSConfig()
	if c.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x", c.MinVersion)
	}
	for _, s := range c.CipherSuites {
		for _, insecure := range tls.InsecureCipherSuites() {
			if s == insecure.ID {
				t.Fatalf("insecure suite %s enabled", insecure.Name)
			}
		}
	}
}
