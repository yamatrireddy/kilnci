// SPDX-License-Identifier: Apache-2.0

package domain

import "time"

// RunStatus is a run's lifecycle state. Transitions are defined only in
// internal/engine/states.go; code never assigns a status directly.
type RunStatus string

// Run statuses.
const (
	// RunAwaitingApproval: an untrusted (fork) run waits for a developer.
	RunAwaitingApproval RunStatus = "awaiting_approval"
	RunQueued           RunStatus = "queued"
	RunRunning          RunStatus = "running"
	RunSucceeded        RunStatus = "succeeded"
	RunFailed           RunStatus = "failed"
	RunCanceled         RunStatus = "canceled"
)

// IsTerminal reports whether the run has finished.
func (s RunStatus) IsTerminal() bool {
	return s == RunSucceeded || s == RunFailed || s == RunCanceled
}

// JobStatus is a job's lifecycle state (see internal/engine/states.go).
type JobStatus string

// Job statuses.
const (
	// JobPending: waiting for dependencies or run approval.
	JobPending JobStatus = "pending"
	// JobQueued: runnable; waiting for a runner lease.
	JobQueued JobStatus = "queued"
	// JobRunning: leased by a runner.
	JobRunning   JobStatus = "running"
	JobSucceeded JobStatus = "succeeded"
	JobFailed    JobStatus = "failed"
	JobCanceled  JobStatus = "canceled"
	// JobSkipped: a dependency did not succeed.
	JobSkipped JobStatus = "skipped"
)

// IsTerminal reports whether the job has finished.
func (s JobStatus) IsTerminal() bool {
	switch s {
	case JobSucceeded, JobFailed, JobCanceled, JobSkipped:
		return true
	default:
		return false
	}
}

// TriggerEvent is what started a run.
type TriggerEvent string

// Trigger events.
const (
	EventPush        TriggerEvent = "push"
	EventPullRequest TriggerEvent = "pull_request"
	EventManual      TriggerEvent = "manual"
)

// Run is one execution of a project's pipeline for one commit.
type Run struct {
	ID        string
	OrgID     string
	ProjectID string
	// Number is sequential per project, for display.
	Number    int64
	Status    RunStatus
	Event     TriggerEvent
	Ref       string // full git ref, e.g. refs/heads/main
	Branch    string // head branch name (untrusted display text for forks)
	CommitSHA string
	// Title is the commit message's first line or PR title: untrusted text.
	Title    string
	PRNumber int
	// IsFork: the change comes from a fork, so the run is untrusted.
	IsFork bool
	// Trusted runs may use trusted runners (ADR-0005 §9).
	Trusted bool
	// ActorLogin is the VCS login (or Kiln user ID for manual runs) that caused the run.
	ActorLogin string
	// CreatedBy is the Kiln user who started a manual run ("" otherwise).
	CreatedBy string
	// IdempotencyKey deduplicates manual run creation ("" if none was sent).
	IdempotencyKey string
	// Error is a safe, author-facing reason when the run failed before any job ran.
	Error      string
	CreatedAt  time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
}

// Job is one node of a run's graph, executed by one runner.
type Job struct {
	ID      string
	OrgID   string
	RunID   string
	Name    string
	Status  JobStatus
	Needs   []string
	Image   string
	Labels  []string
	Steps   []JobStep
	Env     []EnvVar
	Timeout time.Duration
	// Attempt counts leases (1 for the first); MaxAttempts = 1 + retries.
	Attempt     int
	MaxAttempts int
	// Trusted mirrors the run: only trusted jobs may use trusted runners.
	Trusted         bool
	RunnerID        string
	FailureReason   string
	ExitCode        *int
	CancelRequested bool
	QueuedAt        *time.Time
	StartedAt       *time.Time
	FinishedAt      *time.Time
	CreatedAt       time.Time
}

// JobStep is one step of a job's script.
type JobStep struct {
	Name    string        `json:"name"`
	Run     string        `json:"run"`
	Env     []EnvVar      `json:"env,omitempty"`
	Timeout time.Duration `json:"timeout,omitempty"`
}

// EnvVar is one environment variable.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
