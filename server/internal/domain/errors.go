// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"errors"
	"strings"
)

// Sentinel domain errors. Lower layers wrap these with context using %w; the
// API layer maps them to problem responses in exactly one place
// (internal/api/problem.go). Messages are deliberately generic because they may
// reach clients.
var (
	// ErrNotFound means the resource does not exist or the caller may not know
	// that it exists. Cross-org access also returns ErrNotFound.
	ErrNotFound = errors.New("not found")
	// ErrConflict means the request conflicts with current state (e.g. duplicate slug).
	ErrConflict = errors.New("conflict")
	// ErrValidation means the input violates a business rule.
	ErrValidation = errors.New("validation failed")
	// ErrForbidden means the caller is known and can see the resource but lacks
	// the permission for this action.
	ErrForbidden = errors.New("forbidden")
	// ErrUnauthenticated means no valid principal is associated with the request.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrRateLimited means the caller exceeded a rate limit or quota.
	ErrRateLimited = errors.New("rate limited")
	// ErrPreconditionFailed means an If-Match or similar precondition did not hold.
	ErrPreconditionFailed = errors.New("precondition failed")
)

// FieldError describes one invalid input field. Field is a JSON pointer-like
// path (e.g. "slug"); Message is safe to show to the caller.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError carries field-level details for ErrValidation. It unwraps to
// ErrValidation so callers can use errors.Is.
type ValidationError struct {
	Fields []FieldError
}

// NewValidationError returns a ValidationError for a single field.
func NewValidationError(field, message string) *ValidationError {
	return &ValidationError{Fields: []FieldError{{Field: field, Message: message}}}
}

// Add appends a field error.
func (e *ValidationError) Add(field, message string) {
	e.Fields = append(e.Fields, FieldError{Field: field, Message: message})
}

// OrNil returns nil when no field errors were recorded, so callers can build a
// ValidationError incrementally and return it unconditionally.
func (e *ValidationError) OrNil() error {
	if e == nil || len(e.Fields) == 0 {
		return nil
	}
	return e
}

// Error implements error.
func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		parts = append(parts, f.Field+": "+f.Message)
	}
	return "validation failed: " + strings.Join(parts, "; ")
}

// Unwrap makes errors.Is(err, ErrValidation) true.
func (e *ValidationError) Unwrap() error { return ErrValidation }
