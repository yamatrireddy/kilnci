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
	"strings"
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
	Stream(ctx context.Context, ref logs.JobRef, from logs.Position, emit func(logs.Event) error) error
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
	release, err := s.logLimits.acquire(r, &s.logLimits.downloads, func(ctx context.Context) error { return s.logs.Authorize(ctx, ref) })
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	defer release()
	logHeaders(w.Header(), "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="job-`+ref.JobID+`.log"`)
	w.WriteHeader(http.StatusOK)
	if err := s.logs.Read(r.Context(), ref, w); err != nil && r.Context().Err() == nil {
		s.log.ErrorContext(r.Context(), "read job log", "error", err)
	}
}

// Log read limits (T-10). Streams hold a goroutine, a bus subscription,
// and periodic store reads for up to 30 minutes; downloads read up to
// 64 MiB. Both are capped per user (across all of the user's sessions and
// tokens), per org, and in total.
const (
	maxStreamsPerUser   = 10
	maxStreamsPerOrg    = 200
	maxStreamsTotal     = 2000
	maxDownloadsPerUser = 4
	maxDownloadsPerOrg  = 32
	maxDownloadsTotal   = 128

	streamPing         = 15 * time.Second
	streamWriteTimeout = 30 * time.Second
)

// limiter caps concurrent holders per key and in total.
type limiter struct {
	mu     sync.Mutex
	active map[string]int
	total  int
}

func (l *limiter) acquire(key string, perKey, total int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active == nil {
		l.active = map[string]int{}
	}
	if l.active[key] >= perKey || l.total >= total {
		return false
	}
	l.active[key]++
	l.total++
	return true
}

func (l *limiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.active[key]--; l.active[key] <= 0 {
		delete(l.active, key)
	}
}

// logLimit is one kind of log read with its caps.
type logLimit struct {
	users, orgs            limiter
	perUser, perOrg, total int
}

// logLimiter holds the caps for log streams and downloads.
type logLimiter struct {
	streams, downloads logLimit
}

func newLogLimiter() *logLimiter {
	return &logLimiter{
		streams:   logLimit{perUser: maxStreamsPerUser, perOrg: maxStreamsPerOrg, total: maxStreamsTotal},
		downloads: logLimit{perUser: maxDownloadsPerUser, perOrg: maxDownloadsPerOrg, total: maxDownloadsTotal},
	}
}

var errTooManyLogReads = fmt.Errorf("too many concurrent log reads: %w", domain.ErrRateLimited)

// acquire takes a per-user slot, then runs authorize, then takes a per-org
// slot, so requests for an org the caller cannot read never use up that
// org's slots. The total is enforced on the per-user counter.
func (ll *logLimiter) acquire(r *http.Request, l *logLimit, authorize func(context.Context) error) (func(), error) {
	p, ok := authz.FromContext(r.Context())
	if !ok {
		return nil, domain.ErrUnauthenticated
	}
	// Keyed by user, not credential: extra sessions or tokens add no slots.
	user := p.UserID
	if user == "" {
		user = "credential/" + p.CredentialID
	}
	if !l.users.acquire(user, l.perUser, l.total) {
		return nil, errTooManyLogReads
	}
	if err := authorize(r.Context()); err != nil {
		l.users.release(user)
		return nil, err
	}
	org := r.PathValue("orgSlug")
	if !l.orgs.acquire(org, l.perOrg, l.total) {
		l.users.release(user)
		return nil, errTooManyLogReads
	}
	return func() {
		l.orgs.release(org)
		l.users.release(user)
	}, nil
}

type chunkEvent struct {
	Attempt int    `json:"attempt"`
	Seq     int    `json:"seq"`
	Data    string `json:"data"`
}

type attemptEvent struct {
	Attempt int `json:"attempt"`
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

// parseLastEventID reads "<attempt>.<seq>" (the IDs this server sends) or
// a bare "<seq>" meaning the latest attempt, and returns where to resume.
func parseLastEventID(v string) (logs.Position, error) {
	bad := domain.NewValidationError("Last-Event-ID", "must be an event ID from this stream")
	a, sq, found := strings.Cut(v, ".")
	if !found {
		a, sq = "0", v
	}
	attempt, err := strconv.Atoi(a)
	if err != nil || attempt < 0 || attempt > maxEventNumber {
		return logs.Position{}, bad
	}
	seq, err := strconv.Atoi(sq)
	if err != nil || seq < 0 || seq >= logs.MaxChunks {
		return logs.Position{}, bad
	}
	return logs.Position{Attempt: attempt, Seq: seq + 1}, nil
}

// maxEventNumber bounds the attempt in an event ID.
const maxEventNumber = 1 << 20

func (s *server) streamJobLog(w http.ResponseWriter, r *http.Request) {
	ref := jobRef(r)
	var from logs.Position
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		var err error
		if from, err = parseLastEventID(v); err != nil {
			s.errs.write(w, r, err)
			return
		}
	}
	release, err := s.logLimits.acquire(r, &s.logLimits.streams, func(ctx context.Context) error { return s.logs.Authorize(ctx, ref) })
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	defer release()
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
	err = s.logs.Stream(ctx, ref, from, func(ev logs.Event) error {
		switch {
		case ev.End:
			b, _ := json.Marshal(endEvent{Status: string(ev.Status)})
			return sw.frame("event: end\ndata: " + string(b) + "\n\n")
		case ev.NewAttempt:
			b, _ := json.Marshal(attemptEvent{Attempt: ev.Attempt})
			return sw.frame("event: attempt\ndata: " + string(b) + "\n\n")
		}
		b, _ := json.Marshal(chunkEvent{Attempt: ev.Attempt, Seq: ev.Seq, Data: base64.StdEncoding.EncodeToString(ev.Data)})
		return sw.frame("id: " + strconv.Itoa(ev.Attempt) + "." + strconv.Itoa(ev.Seq) + "\nevent: chunk\ndata: " + string(b) + "\n\n")
	})
	if err != nil && ctx.Err() == nil && !errors.Is(err, context.Canceled) {
		s.log.WarnContext(r.Context(), "log stream ended with an error", "error", err)
	}
}
