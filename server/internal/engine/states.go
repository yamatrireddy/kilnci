// SPDX-License-Identifier: Apache-2.0

// Package engine holds the run and job state machines (CLAUDE.md invariant
// 5). Every status change in Kiln goes through RunTransition or
// JobTransition; the store then applies it as a compare-and-swap on the
// expected previous status, so concurrent actors (runners, the reaper, a
// user canceling) cannot overwrite each other's transitions.
package engine

import (
	"fmt"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
)

// runEdges lists every allowed run transition.
var runEdges = map[domain.RunStatus][]domain.RunStatus{
	domain.RunAwaitingApproval: {domain.RunQueued, domain.RunCanceled},
	domain.RunQueued:           {domain.RunRunning, domain.RunSucceeded, domain.RunFailed, domain.RunCanceled},
	domain.RunRunning:          {domain.RunSucceeded, domain.RunFailed, domain.RunCanceled},
}

// jobEdges lists every allowed job transition.
var jobEdges = map[domain.JobStatus][]domain.JobStatus{
	domain.JobPending: {domain.JobQueued, domain.JobSkipped, domain.JobCanceled},
	domain.JobQueued:  {domain.JobRunning, domain.JobCanceled, domain.JobFailed},
	// running → queued is a retry after a lost lease.
	domain.JobRunning: {domain.JobSucceeded, domain.JobFailed, domain.JobCanceled, domain.JobQueued},
}

// initialRun lists the statuses a run may be created in: awaiting approval
// (untrusted), queued, or failed (the pipeline could not be loaded).
var initialRun = []domain.RunStatus{domain.RunAwaitingApproval, domain.RunQueued, domain.RunFailed}

// InitialRunStatus returns the status a new run starts in.
func InitialRunStatus(needsApproval, pipelineValid bool) domain.RunStatus {
	switch {
	case !pipelineValid:
		return domain.RunFailed
	case needsApproval:
		return domain.RunAwaitingApproval
	default:
		return domain.RunQueued
	}
}

// ValidInitialRunStatus reports whether a run may be created in s.
func ValidInitialRunStatus(s domain.RunStatus) bool {
	for _, x := range initialRun {
		if x == s {
			return true
		}
	}
	return false
}

// RunTransition returns nil if a run may move from → to, and a
// domain.ErrConflict otherwise (the state changed under the caller, or the
// request makes no sense in the current state).
func RunTransition(from, to domain.RunStatus) error {
	for _, x := range runEdges[from] {
		if x == to {
			return nil
		}
	}
	return fmt.Errorf("run cannot move from %s to %s: %w", from, to, domain.ErrConflict)
}

// JobTransition returns nil if a job may move from → to, and a
// domain.ErrConflict otherwise.
func JobTransition(from, to domain.JobStatus) error {
	for _, x := range jobEdges[from] {
		if x == to {
			return nil
		}
	}
	return fmt.Errorf("job cannot move from %s to %s: %w", from, to, domain.ErrConflict)
}

// RunOutcome derives a run's status from its jobs once they are all terminal:
// canceled if any job was canceled, failed if any failed or was skipped,
// succeeded otherwise. ok is false while any job is still unfinished.
func RunOutcome(jobs []domain.JobStatus) (status domain.RunStatus, ok bool) {
	status = domain.RunSucceeded
	for _, s := range jobs {
		switch s {
		case domain.JobSucceeded:
		case domain.JobCanceled:
			status = domain.RunCanceled
		case domain.JobFailed, domain.JobSkipped:
			if status != domain.RunCanceled {
				status = domain.RunFailed
			}
		default:
			return "", false
		}
	}
	return status, true
}
