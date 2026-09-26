// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/service/logs"
)

// LogService is what the log handlers need from internal/service/logs.
type LogService interface {
	Authorize(ctx context.Context, ref logs.JobRef) error
	Read(ctx context.Context, ref logs.JobRef, w io.Writer) error
	Stream(ctx context.Context, ref logs.JobRef, from int, emit func(logs.Event) error) error
}

func jobRef(r *http.Request) logs.JobRef {
	return logs.JobRef{
		OrgSlug: r.PathValue("orgSlug"), ProjectSlug: r.PathValue("projectSlug"),
		RunID: r.PathValue("runId"), JobID: r.PathValue("jobId"),
	}
}

// logHeaders mark log bytes as inert data (ADR-0007 §4): never sniffed,
// never rendered as a document, never cached.
func logHeaders(h http.Header, contentType string) {
	h.Set("Content-Type", contentType)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("Cache-Control", "no-store")
}

func (s *server) getJobLog(w http.ResponseWriter, r *http.Request) {
	ref := jobRef(r)
	// Authorize before any byte is written so errors are proper problems.
	if err := s.logs.Authorize(r.Context(), ref); err != nil {
		s.errs.write(w, r, err)
		return
	}
	logHeaders(w.Header(), "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="job-`+ref.JobID+`.log"`)
	w.WriteHeader(http.StatusOK)
	if err := s.logs.Read(r.Context(), ref, w); err != nil && r.Context().Err() == nil {
		s.log.ErrorContext(r.Context(), "read job log", "error", err)
	}
}

// Stream limits.
const (
	maxStreamsPerPrincipal = 10
	streamPing             = 15 * time.Second
	streamWriteTimeout     = 30 * time.Second
)

// streamLimiter caps concurrent log streams per principal (T-10).
type streamLimiter struct {
	mu     sync.Mutex
	active map[string]int
}

func (l *streamLimiter) acquire(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active == nil {
		l.active = map[string]int{}
	}
	if l.active[key] >= maxStreamsPerPrincipal {
		return false
	}
	l.active[key]++
	return true
}

func (l *streamLimiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[key]--; l.active[key] <= 0 {
		delete(l.active, key)
	}
}

type chunkEvent struct {
	Seq  int    `json:"seq"`
	Data string `json:"data"`
}

type endEvent struct {
	Status string `json:"status"`
}

// sseWriter serializes SSE frames from the stream and the ping loop.
type sseWriter struct {
	mu sync.Mutex
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (sw *sseWriter) frame(s string) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	_ = sw.rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
	if _, err := io.WriteString(sw.w, s); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	if err := sw.rc.Flush(); err != nil {
		return fmt.Errorf("flush event: %w", err)
	}
	return nil
}

func (s *server) streamJobLog(w http.ResponseWriter, r *http.Request) {
	ref := jobRef(r)
	from := 0
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			s.errs.write(w, r, domain.NewValidationError("Last-Event-ID", "must be a chunk number"))
			return
		}
		from = n + 1
	}
	p, _ := authz.FromContext(r.Context())
	key := p.UserID + "/" + p.CredentialID
	if !s.streams.acquire(key) {
		s.errs.write(w, r, fmt.Errorf("too many open log streams: %w", domain.ErrRateLimited))
		return
	}
	defer s.streams.release(key)
	if err := s.logs.Authorize(r.Context(), ref); err != nil {
		s.errs.write(w, r, err)
		return
	}
	logHeaders(w.Header(), "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	sw := &sseWriter{w: w, rc: http.NewResponseController(w)}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		t := time.NewTicker(streamPing)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if sw.frame(": ping\n\n") != nil {
					cancel()
					return
				}
			}
		}
	}()
	err := s.logs.Stream(ctx, ref, from, func(ev logs.Event) error {
		if ev.End {
			b, _ := json.Marshal(endEvent{Status: string(ev.Status)})
			return sw.frame("event: end\ndata: " + string(b) + "\n\n")
		}
		b, _ := json.Marshal(chunkEvent{Seq: ev.Seq, Data: base64.StdEncoding.EncodeToString(ev.Data)})
		return sw.frame("id: " + strconv.Itoa(ev.Seq) + "\nevent: chunk\ndata: " + string(b) + "\n\n")
	})
	if err != nil && ctx.Err() == nil && !errors.Is(err, context.Canceled) {
		s.log.WarnContext(r.Context(), "log stream ended with an error", "error", err)
	}
}
