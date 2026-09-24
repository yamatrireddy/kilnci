// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"sort"
	"time"
)

// ReadinessCheck reports whether a dependency is usable.
type ReadinessCheck func(ctx context.Context) error

const readinessTimeout = 2 * time.Second

// healthz reports that the process is alive. It checks nothing else, so an
// orchestrator does not restart a healthy process because a dependency is down.
func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz reports whether every dependency is reachable. Failures are logged
// with detail but the response only names the failing check.
func (s *server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
	defer cancel()

	names := make([]string, 0, len(s.checks))
	for n := range s.checks {
		names = append(names, n)
	}
	sort.Strings(names)

	checks := make(map[string]string, len(names))
	ready := true
	for _, n := range names {
		if err := s.checks[n](ctx); err != nil {
			ready = false
			checks[n] = "unavailable"
			s.log.WarnContext(r.Context(), "readiness check failed", "check", n, "error", err)
			continue
		}
		checks[n] = "ok"
	}
	status, code := "ok", http.StatusOK
	if !ready {
		status, code = "unavailable", http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"status": status, "checks": checks})
}
