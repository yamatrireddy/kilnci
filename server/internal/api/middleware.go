// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
)

type middleware func(http.Handler) http.Handler

func chain(h http.Handler, mws ...middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// statusRecorder captures the response status and size for logs and spans.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err //nolint:wrapcheck // io pass-through
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// reqState is shared by outer middleware and the router. Inner layers see
// copies of *http.Request, so outer layers cannot read r.Pattern themselves;
// the router records the matched route here instead.
type reqState struct {
	route string
}

type reqStateKey struct{}

func stateFrom(r *http.Request) *reqState {
	if s, ok := r.Context().Value(reqStateKey{}).(*reqState); ok {
		return s
	}
	return &reqState{}
}

func (s *reqState) routeName() string {
	if s.route == "" {
		return "unmatched"
	}
	return s.route
}

// recoverer turns panics into a generic 500 and logs the stack server-side.
func recoverer(log *slog.Logger) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer recoverPanic(r.Context(), w, log)
			next.ServeHTTP(w, r)
		})
	}
}

// recoverPanic must be deferred directly so that recover() takes effect.
func recoverPanic(ctx context.Context, w http.ResponseWriter, log *slog.Logger) {
	v := recover()
	if v == nil {
		return
	}
	if v == http.ErrAbortHandler { //nolint:errorlint // sentinel compared by identity per net/http docs
		panic(v)
	}
	log.ErrorContext(ctx, "panic serving request", "panic", v, "stack", string(debug.Stack()))
	writeProblem(ctx, w, internalProblem, nil)
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

// requestID assigns every request an ID for correlation. A well-formed
// inbound X-Request-Id is kept only when the direct peer is a trusted proxy;
// otherwise clients could plant IDs that collide with other users' requests
// in logs and audit records.
func requestID(gen *ids.Generator, ips clientIPResolver) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-Id")
			if !requestIDPattern.MatchString(id) || !ips.peerTrusted(r) {
				id = gen.New()
			}
			w.Header().Set("X-Request-Id", id)
			ctx := context.WithValue(logging.WithRequestID(r.Context(), id), reqStateKey{}, &reqState{})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// tracing starts a server span per request, continuing W3C trace context.
func tracing() middleware {
	tracer := otel.Tracer("github.com/yamatrireddy/kilnci/server/internal/api")
	prop := propagation.TraceContext{}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := prop.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			ctx, span := tracer.Start(ctx, r.Method, trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(attribute.String("http.request.method", r.Method)))
			defer span.End()
			rec, ok := w.(*statusRecorder)
			if !ok {
				rec = &statusRecorder{ResponseWriter: w}
			}
			r = r.WithContext(ctx)
			next.ServeHTTP(rec, r)
			route := stateFrom(r).routeName()
			span.SetName(r.Method + " " + route)
			span.SetAttributes(attribute.String("http.route", route))
			span.SetAttributes(attribute.Int("http.response.status_code", rec.status))
			if rec.status >= 500 {
				span.SetStatus(codes.Error, http.StatusText(rec.status))
			}
		})
	}
}

// accessLog logs one line per request. It logs the matched route pattern, not
// the raw URL, so query strings (OIDC codes, state) and IDs never reach logs.
func accessLog(log *slog.Logger, ips clientIPResolver) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			route := stateFrom(r).routeName()
			level := slog.LevelInfo
			if rec.status >= 500 {
				level = slog.LevelError
			}
			log.LogAttrs(r.Context(), level, "http request",
				slog.String("method", r.Method),
				slog.String("route", route),
				slog.Int("status", rec.status),
				slog.Int("bytes", rec.bytes),
				slog.Duration("duration", time.Since(start)),
				slog.String("client_ip", ips.resolve(r).String()),
			)
		})
	}
}

// API responses are never rendered as documents, so the policy is maximal.
const apiCSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// securityHeaders sets the headers from security-standards §10 on every response.
// The SPA handler overrides Content-Security-Policy and Cache-Control for documents.
func securityHeaders(hsts bool) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", apiCSP)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-site")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
			h.Set("Cache-Control", "no-store")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

var (
	corsAllowMethods = "GET, POST, PUT, PATCH, DELETE"
	corsAllowHeaders = "Authorization, Content-Type, Idempotency-Key, If-Match, X-Request-Id, Traceparent"
)

// cors allows cross-origin API calls only from explicitly listed origins (the
// desktop app). Credentials (cookies) are never allowed cross-origin: those
// clients authenticate with bearer tokens, so a listed origin still cannot
// ride a browser session.
func cors(allowed []string) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			w.Header().Add("Vary", "Origin")
			if origin == "" || !slices.Contains(allowed, origin) {
				next.ServeHTTP(w, r)
				return
			}
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Expose-Headers", "X-Request-Id, ETag, Location")
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Set("Access-Control-Allow-Methods", corsAllowMethods)
				h.Set("Access-Control-Allow-Headers", corsAllowHeaders)
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// bodyLimit caps request bodies; handlers see *http.MaxBytesError past the limit.
// webhookPrefix is where signature-verified webhook ingest lives; its
// bodies may be larger (SS §5) and are verified before parsing.
const webhookPrefix = "/api/v1/webhooks/"

// webhookMaxBodyBytes is the webhook body limit (SS §5: 5 MiB).
const webhookMaxBodyBytes = 5 << 20

func bodyLimit(maxBytes int64) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit := maxBytes
			if strings.HasPrefix(r.URL.Path, webhookPrefix) {
				limit = webhookMaxBodyBytes
			}
			if r.ContentLength > limit {
				writeProblem(r.Context(), w, problemKind{ProblemPayloadTooLarge, "Request body too large", http.StatusRequestEntityTooLarge}, nil)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}
