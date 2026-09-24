// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

const fakeSecret = "fake-value-that-must-not-appear"

func TestNew_AddsCorrelationIDs(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, Options{Level: slog.LevelInfo, Format: "json"})

	tid, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	sid, _ := trace.SpanIDFromHex("0102030405060708")
	ctx := trace.ContextWithSpanContext(context.Background(),
		trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid}))
	ctx = WithOrgID(WithRequestID(ctx, "req-1"), "org-1")

	log.With("component", "test").InfoContext(ctx, "hello")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not JSON: %v: %s", err, buf.String())
	}
	for k, want := range map[string]string{
		"request_id": "req-1",
		"org_id":     "org-1",
		"trace_id":   "0102030405060708090a0b0c0d0e0f10",
		"component":  "test",
	} {
		if rec[k] != want {
			t.Errorf("%s = %v, want %q", k, rec[k], want)
		}
	}
}

func TestNew_RedactsSensitiveKeys(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		var buf bytes.Buffer
		log := New(&buf, Options{Level: slog.LevelDebug, Format: format})
		log.WithGroup("g").Info("x",
			"password", fakeSecret,
			"client_secret", fakeSecret,
			"Authorization", fakeSecret,
			"refreshToken", fakeSecret,
			"api-key", fakeSecret,
			"session_id", fakeSecret,
			"code_verifier", fakeSecret,
			slog.Group("nested", "db_url", fakeSecret),
			"user", "alice",
		)
		out := buf.String()
		if strings.Contains(out, fakeSecret) {
			t.Fatalf("%s: secret leaked: %s", format, out)
		}
		if !strings.Contains(out, "alice") {
			t.Fatalf("%s: non-sensitive attr dropped: %s", format, out)
		}
	}
}

func TestNew_EscapesControlCharacters(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, Options{Format: "json"}).Info("x", "branch", "main\n{\"level\":\"ERROR\"}\x1b[31m")
	if n := strings.Count(buf.String(), "\n"); n != 1 {
		t.Fatalf("log injection: record spans %d lines: %q", n, buf.String())
	}
	if strings.ContainsRune(buf.String(), 0x1b) {
		t.Fatal("raw ESC written to log")
	}
}

func TestNew_RespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, Options{Level: slog.LevelWarn, Format: "text"})
	log.Info("quiet")
	log.Warn("loud")
	if strings.Contains(buf.String(), "quiet") || !strings.Contains(buf.String(), "loud") {
		t.Fatalf("level not respected: %q", buf.String())
	}
}

func TestContextAccessors_Empty(t *testing.T) {
	if RequestID(context.Background()) != "" || OrgID(context.Background()) != "" {
		t.Fatal("empty context should yield empty IDs")
	}
	Discard().Info("dropped")
}
