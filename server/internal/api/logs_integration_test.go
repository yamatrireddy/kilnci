// SPDX-License-Identifier: Apache-2.0

//go:build integration

package api_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/scheduler"
)

// TestJobLogs_HeadersAndServerSentEvents: logs are served as inert data and
// streamed as SSE with base64 payloads (ADR-0007 §4). The log contains an
// HTML/script payload and ANSI escapes to prove nothing interprets them.
func TestJobLogs_HeadersAndServerSentEvents(t *testing.T) {
	f := newFixture(t)
	e := f.env
	ctx := t.Context()
	runID := f.newRun(false)
	sched := scheduler.New(e.st, logging.Discard(), scheduler.Options{}, e.clock.now)
	rid := ids.NewGenerator(nil).New()
	now := e.clock.now()
	if err := e.st.CreateRunner(ctx, domain.Runner{ID: rid, OrgID: f.orgID, Name: "r", CertSerial: rid, CertDER: []byte{1},
		CertSPKIHash: []byte{1}, CertRenewedAt: now, CertExpiresAt: now.Add(time.Hour), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	rn := scheduler.Runner{ID: rid, OrgID: f.orgID}
	var l *scheduler.Lease
	for l == nil { // other runs in the org may be queued first
		var err error
		if l, err = sched.Lease(ctx, rn); err != nil || l == nil {
			t.Fatalf("lease: %v", err)
		}
		if l.Run.ID != runID {
			zero := 0
			_ = sched.Complete(ctx, rn, l.Job.ID, l.ID, scheduler.Result{Status: domain.JobSucceeded, ExitCode: &zero})
			l = nil
		}
	}
	payload := "\x1b[31m<script>alert(1)</script>\x1b[0m\n"
	if _, err := e.logs.Append(ctx, rn, l.Job.ID, l.ID, 0, []byte(payload)); err != nil {
		t.Fatal(err)
	}
	zero := 0
	if err := sched.Complete(ctx, rn, l.Job.ID, l.ID, scheduler.Result{Status: domain.JobSucceeded, ExitCode: &zero}); err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/orgs/" + f.org + "/projects/" + f.project + "/runs/" + runID + "/jobs/" + l.Job.ID + "/logs"

	rec := e.do(f.actors[viewer], http.MethodGet, base, "")
	e.mustStatus(rec, http.StatusOK)
	h := rec.Header()
	if rec.Body.String() != payload || !strings.HasPrefix(h.Get("Content-Type"), "text/plain") ||
		h.Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(h.Get("Content-Security-Policy"), "sandbox") ||
		!strings.HasPrefix(h.Get("Content-Disposition"), "attachment") || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("raw log response: headers=%v body=%q", h, rec.Body.String())
	}

	rec = e.do(f.actors[viewer], http.MethodGet, base+"/stream", "")
	e.mustStatus(rec, http.StatusOK)
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream content type = %q", rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	if strings.Contains(body, "<script>") {
		t.Fatalf("raw bytes in the event stream: %q", body)
	}
	frames := strings.Split(strings.TrimSpace(body), "\n\n")
	if len(frames) != 3 || frames[0] != "event: attempt\ndata: {\"attempt\":1}" ||
		!strings.HasPrefix(frames[1], "id: 1.0\nevent: chunk\ndata: ") || !strings.HasPrefix(frames[2], "event: end\ndata: ") {
		t.Fatalf("frames = %q", frames)
	}
	var ev struct {
		Attempt int    `json:"attempt"`
		Seq     int    `json:"seq"`
		Data    string `json:"data"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(frames[1], "id: 1.0\nevent: chunk\ndata: ")), &ev); err != nil || ev.Attempt != 1 {
		t.Fatal(err)
	}
	if dec, _ := base64.StdEncoding.DecodeString(ev.Data); string(dec) != payload {
		t.Fatalf("decoded chunk = %q", dec)
	}
	if !strings.Contains(frames[2], `"status":"succeeded"`) {
		t.Fatalf("end frame = %q", frames[2])
	}

	// Resuming after the last chunk returns only the attempt and end events,
	// whether the ID names the attempt or (legacy) only the chunk.
	for _, id := range []string{"1.0", "0"} {
		rec = e.do(f.actors[viewer], http.MethodGet, base+"/stream", "", withHeader("Last-Event-ID", id))
		e.mustStatus(rec, http.StatusOK)
		if frames := strings.Split(strings.TrimSpace(rec.Body.String()), "\n\n"); len(frames) != 2 || !strings.HasPrefix(frames[1], "event: end") {
			t.Fatalf("resumed after %q frames = %q", id, frames)
		}
	}
	// An ID from an older attempt replays the latest attempt from the start.
	rec = e.do(f.actors[viewer], http.MethodGet, base+"/stream", "", withHeader("Last-Event-ID", "7.0"))
	if frames := strings.Split(strings.TrimSpace(rec.Body.String()), "\n\n"); len(frames) != 3 {
		t.Fatalf("resumed from another attempt frames = %q", frames)
	}
	for _, id := range []string{"x", "1.x", "-1", "1.16384", "1.2.3"} {
		rec = e.do(f.actors[viewer], http.MethodGet, base+"/stream", "", withHeader("Last-Event-ID", id))
		e.mustStatus(rec, http.StatusUnprocessableEntity)
	}
}
