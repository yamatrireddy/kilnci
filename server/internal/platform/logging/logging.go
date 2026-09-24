// SPDX-License-Identifier: Apache-2.0

// Package logging builds Kiln's structured logger.
//
// Every record logged with a context carries request_id, trace_id, and org_id
// when they are known. Attributes whose keys look like credentials are
// redacted before they reach any output, as a backstop to config.Secret and to
// reviewers; the rule is still "never log secrets".
package logging

import (
	"context"
	"io"
	"log/slog"
	"regexp"

	"go.opentelemetry.io/otel/trace"
)

// Redacted replaces sensitive attribute values.
const Redacted = "[REDACTED]"

// sensitiveKey matches attribute keys whose values must never be logged.
var sensitiveKey = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|authorization|cookie|api[_-]?key|private[_-]?key|credential|dsn|db[_-]?url|code[_-]?verifier|session[_-]?id)`)

// Options configures New.
type Options struct {
	Level  slog.Leveler
	Format string // "json" or "text"
}

// New returns a logger writing to w.
func New(w io.Writer, opts Options) *slog.Logger {
	ho := &slog.HandlerOptions{Level: opts.Level, ReplaceAttr: redact}
	var h slog.Handler
	if opts.Format == "text" {
		h = slog.NewTextHandler(w, ho)
	} else {
		h = slog.NewJSONHandler(w, ho)
	}
	return slog.New(&contextHandler{Handler: h})
}

func redact(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() != slog.KindGroup && sensitiveKey.MatchString(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	return a
}

type ctxKey int

const (
	requestIDKey ctxKey = iota
	orgIDKey
)

// WithRequestID returns ctx carrying the request ID.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestID returns the request ID in ctx, or "".
func RequestID(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

// WithOrgID returns ctx carrying the org ID for log correlation.
func WithOrgID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, orgIDKey, id)
}

// OrgID returns the org ID in ctx, or "".
func OrgID(ctx context.Context) string {
	v, _ := ctx.Value(orgIDKey).(string)
	return v
}

// contextHandler adds correlation IDs from the record's context.
type contextHandler struct {
	slog.Handler
}

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := RequestID(ctx); id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	if sc := trace.SpanContextFromContext(ctx); sc.HasTraceID() {
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()))
	}
	if id := OrgID(ctx); id != "" {
		r.AddAttrs(slog.String("org_id", id))
	}
	return h.Handler.Handle(ctx, r) //nolint:wrapcheck // pass-through
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{Handler: h.Handler.WithGroup(name)}
}

// Discard returns a logger that drops everything; for tests.
func Discard() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
