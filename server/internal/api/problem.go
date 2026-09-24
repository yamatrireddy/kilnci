// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
)

// Problem is an RFC 9457 problem details body. Type URIs are stable and part
// of the API contract; Title is generic. Internal details (SQL, paths, stack
// traces, wrapped error text) never appear here.
type Problem struct {
	Type      string              `json:"type"`
	Title     string              `json:"title"`
	Status    int                 `json:"status"`
	Detail    string              `json:"detail,omitempty"`
	RequestID string              `json:"requestId"`
	Errors    []domain.FieldError `json:"errors,omitempty"`
}

// Problem type URIs.
const (
	ProblemNotFound           = "urn:kiln:problem:not-found"
	ProblemConflict           = "urn:kiln:problem:conflict"
	ProblemValidation         = "urn:kiln:problem:validation"
	ProblemForbidden          = "urn:kiln:problem:forbidden"
	ProblemUnauthenticated    = "urn:kiln:problem:unauthenticated"
	ProblemRateLimited        = "urn:kiln:problem:rate-limited"
	ProblemPreconditionFailed = "urn:kiln:problem:precondition-failed"
	ProblemMethodNotAllowed   = "urn:kiln:problem:method-not-allowed"
	ProblemPayloadTooLarge    = "urn:kiln:problem:payload-too-large"
	ProblemUnavailable        = "urn:kiln:problem:unavailable"
	ProblemInternal           = "urn:kiln:problem:internal"
)

type problemKind struct {
	typ    string
	title  string
	status int
}

// domainProblems is the one and only mapping from domain errors to HTTP.
var domainProblems = []struct {
	err  error
	kind problemKind
}{
	{domain.ErrNotFound, problemKind{ProblemNotFound, "Resource not found", http.StatusNotFound}},
	{domain.ErrConflict, problemKind{ProblemConflict, "Conflict with current state", http.StatusConflict}},
	{domain.ErrValidation, problemKind{ProblemValidation, "Request validation failed", http.StatusUnprocessableEntity}},
	{domain.ErrForbidden, problemKind{ProblemForbidden, "Permission denied", http.StatusForbidden}},
	{domain.ErrUnauthenticated, problemKind{ProblemUnauthenticated, "Authentication required", http.StatusUnauthorized}},
	{domain.ErrRateLimited, problemKind{ProblemRateLimited, "Too many requests", http.StatusTooManyRequests}},
	{domain.ErrPreconditionFailed, problemKind{ProblemPreconditionFailed, "Precondition failed", http.StatusPreconditionFailed}},
}

var internalProblem = problemKind{ProblemInternal, "Internal server error", http.StatusInternalServerError}

// errorWriter writes problems and logs unexpected errors exactly once.
type errorWriter struct {
	log *slog.Logger
}

// write maps err to a problem response. Expected domain errors are not logged
// (they are the client's problem); anything else is logged at Error with the
// request ID and answered with a generic 500.
func (ew errorWriter) write(w http.ResponseWriter, r *http.Request, err error) {
	var maxBytes *http.MaxBytesError
	if errors.As(err, &maxBytes) {
		writeProblem(r.Context(), w, problemKind{ProblemPayloadTooLarge, "Request body too large", http.StatusRequestEntityTooLarge}, nil)
		return
	}
	for _, dp := range domainProblems {
		if errors.Is(err, dp.err) {
			var fields []domain.FieldError
			var ve *domain.ValidationError
			if errors.As(err, &ve) {
				fields = ve.Fields
			}
			if dp.kind.status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", `Bearer realm="kiln"`)
			}
			writeProblem(r.Context(), w, dp.kind, fields)
			return
		}
	}
	if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
		// Client went away; nothing useful to send or log.
		return
	}
	ew.log.ErrorContext(r.Context(), "request failed", "method", r.Method, "route", stateFrom(r).routeName(), "error", err)
	writeProblem(r.Context(), w, internalProblem, nil)
}

func writeProblem(ctx context.Context, w http.ResponseWriter, k problemKind, fields []domain.FieldError) {
	p := Problem{Type: k.typ, Title: k.title, Status: k.status, RequestID: logging.RequestID(ctx), Errors: fields}
	h := w.Header()
	h.Set("Content-Type", "application/problem+json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(k.status)
	_ = json.NewEncoder(w).Encode(p)
}
