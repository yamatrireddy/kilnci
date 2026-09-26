// SPDX-License-Identifier: Apache-2.0

// Package executor defines how a runner executes one leased job. Job code is
// hostile by assumption (security-standards §8); every executor runs steps
// inside an isolated sandbox and never evaluates job input on the host.
package executor

import (
	"context"
	"errors"
	"io"
	"time"
)

// EnvVar is one environment variable.
type EnvVar struct {
	Name  string
	Value string
}

// Step is one script run with /bin/sh -e -c inside the sandbox.
type Step struct {
	Name    string
	Run     string
	Env     []EnvVar
	Timeout time.Duration // zero: bounded by the job
}

// Checkout says which commit to place in the workspace.
type Checkout struct {
	// RepositoryURL is an https clone URL without credentials; empty means
	// the job gets an empty workspace.
	RepositoryURL string
	CommitSHA     string
	// AuthorizationHeader, if set, is sent only by the checkout step.
	AuthorizationHeader string
}

// Job is everything an executor needs.
type Job struct {
	ID       string
	Image    string
	Steps    []Step
	Env      []EnvVar
	Timeout  time.Duration
	Checkout Checkout
	// Trusted is false for untrusted (fork) jobs: images are pulled
	// anonymously and nothing privileged is ever offered.
	Trusted bool
}

// Outcome is how a job ended.
type Outcome int

// Outcomes.
const (
	Succeeded Outcome = iota + 1
	Failed
	Canceled
)

// Result reports a finished job. Reason is short, safe display text.
type Result struct {
	Outcome  Outcome
	ExitCode int
	Reason   string
}

// Executor runs a job, writing all output (already interleaved stdout and
// stderr) to out. Canceling ctx stops the job; the executor then returns a
// Canceled result. An error means the executor itself failed (the job
// could not be run), not that the job's steps failed.
type Executor interface {
	Run(ctx context.Context, job Job, out io.Writer) (Result, error)
}

// ErrInvalidJob means the job description is malformed and must not run.
var ErrInvalidJob = errors.New("invalid job")
