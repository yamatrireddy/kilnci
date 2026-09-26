// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	// DefaultTimeout bounds one API call, including reading the response.
	DefaultTimeout = 30 * time.Second
	// maxResponseBytes caps how much of a response is read. A lint result
	// for the largest accepted pipeline is far smaller.
	maxResponseBytes = 1 << 20
)

// Client calls the Kiln API as one principal.
type Client struct {
	base      *url.URL
	token     string
	userAgent string
	http      *http.Client
}

// Options configure a Client.
type Options struct {
	// Timeout bounds each call; zero means DefaultTimeout.
	Timeout time.Duration
	// Transport overrides the HTTP transport (tests). Nil means a clone of
	// the default transport with TLS 1.2 as the minimum version.
	Transport http.RoundTripper
	// UserAgent is sent as the User-Agent header.
	UserAgent string
}

// New returns a Client for the server at base (as validated by
// config.ParseServer) that authenticates with token.
func New(base *url.URL, token string, opts Options) (*Client, error) {
	if base == nil || token == "" {
		return nil, errors.New("client: server and token are required")
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	rt := opts.Transport
	if rt == nil {
		t, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("client: unexpected default transport")
		}
		t = t.Clone()
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		rt = t
	}
	return &Client{
		base:      base,
		token:     token,
		userAgent: opts.UserAgent,
		http: &http.Client{
			Transport: rt,
			Timeout:   opts.Timeout,
			// Never follow redirects: the token must reach only the server
			// the user named, and a redirected POST would be replayed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// LintProblem is one validation problem (schema LintProblem).
type LintProblem struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// LintResult is the lint API's response (schema LintResult).
type LintResult struct {
	Valid    bool          `json:"valid"`
	Problems []LintProblem `json:"problems"`
}

// Lint validates pipeline source with POST /api/v1/pipelines/lint. An
// invalid pipeline is not an error: its problems are in the result.
func (c *Client) Lint(ctx context.Context, source string) (LintResult, error) {
	// No HTML escaping: it would grow each <, >, and & to six bytes and can
	// push a pipeline within the server's size limit past its body limit.
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(struct {
		Pipeline string `json:"pipeline"`
	}{source}); err != nil {
		return LintResult{}, fmt.Errorf("encode request: %w", err)
	}
	var out LintResult
	if err := c.post(ctx, "/api/v1/pipelines/lint", body.Bytes(), &out); err != nil {
		return LintResult{}, err
	}
	if out.Valid != (len(out.Problems) == 0) {
		return LintResult{}, errors.New("server returned an inconsistent lint result")
	}
	return out, nil
}

func (c *Client) post(ctx context.Context, path string, body []byte, out any) error {
	u := *c.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, application/problem+json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// url.Error carries the URL, which holds no credentials (ParseServer
		// rejects user info), and never the Authorization header.
		return fmt.Errorf("call %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return newAPIError(resp, data)
	}
	if !hasMediaType(resp.Header.Get("Content-Type"), "application/json") {
		return errors.New("server returned a non-JSON response; check the server URL")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// FieldError is one field-level validation error in a problem response.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// APIError is a non-200 response, decoded from RFC 9457 problem JSON when
// the server sent one.
type APIError struct {
	Status    int          `json:"status"`
	Title     string       `json:"title"`
	Detail    string       `json:"detail"`
	RequestID string       `json:"requestId"`
	Errors    []FieldError `json:"errors"`
	// RetryAfter is the server's Retry-After on a 429, or zero.
	RetryAfter time.Duration `json:"-"`
}

func newAPIError(resp *http.Response, data []byte) *APIError {
	e := &APIError{}
	if hasMediaType(resp.Header.Get("Content-Type"), "application/problem+json") {
		_ = json.Unmarshal(data, e) // best effort: the status line still explains it
	}
	e.Status = resp.StatusCode
	if e.Title == "" {
		e.Title = http.StatusText(resp.StatusCode)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			e.RetryAfter = time.Duration(s) * time.Second
		}
	}
	return e
}

// Error describes the failure, with a hint for the common causes. The text
// comes partly from the server; callers writing it to a terminal sanitize it.
func (e *APIError) Error() string {
	msg := fmt.Sprintf("server returned %d %s", e.Status, e.Title)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	for _, fe := range e.Errors {
		msg += fmt.Sprintf("; %s: %s", fe.Field, fe.Message)
	}
	switch {
	case e.Status == http.StatusUnauthorized:
		msg += " (check the token: it may be missing, expired, or revoked)"
	case e.Status == http.StatusForbidden:
		msg += " (the token needs the pipelines:lint scope)"
	case e.Status == http.StatusTooManyRequests && e.RetryAfter > 0:
		msg += fmt.Sprintf(" (retry after %s)", e.RetryAfter)
	case e.Status >= 300 && e.Status < 400:
		msg += " (redirects are not followed; check the server URL)"
	}
	if e.RequestID != "" {
		msg += " [request " + e.RequestID + "]"
	}
	return msg
}

func hasMediaType(header, want string) bool {
	mt, _, err := mime.ParseMediaType(header)
	return err == nil && mt == want
}
