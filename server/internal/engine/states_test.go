// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"testing"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
)

var allRun = []domain.RunStatus{
	domain.RunAwaitingApproval, domain.RunQueued, domain.RunRunning,
	domain.RunSucceeded, domain.RunFailed, domain.RunCanceled,
}

var allJob = []domain.JobStatus{
	domain.JobPending, domain.JobQueued, domain.JobRunning, domain.JobSucceeded,
	domain.JobFailed, domain.JobCanceled, domain.JobSkipped,
}

func TestRunTransition_TerminalStatesAreFinal(t *testing.T) {
	for _, from := range allRun {
		for _, to := range allRun {
			err := RunTransition(from, to)
			if from.IsTerminal() && err == nil {
				t.Errorf("terminal run %s moved to %s", from, to)
			}
			if err != nil && !errors.Is(err, domain.ErrConflict) {
				t.Errorf("RunTransition error must be ErrConflict: %v", err)
			}
		}
	}
}

func TestRunTransition_AllowedEdges(t *testing.T) {
	allowed := map[[2]domain.RunStatus]bool{
		{domain.RunAwaitingApproval, domain.RunQueued}:   true,
		{domain.RunAwaitingApproval, domain.RunCanceled}: true,
		{domain.RunQueued, domain.RunRunning}:            true,
		{domain.RunQueued, domain.RunSucceeded}:          true,
		{domain.RunQueued, domain.RunFailed}:             true,
		{domain.RunQueued, domain.RunCanceled}:           true,
		{domain.RunRunning, domain.RunSucceeded}:         true,
		{domain.RunRunning, domain.RunFailed}:            true,
		{domain.RunRunning, domain.RunCanceled}:          true,
	}
	for _, from := range allRun {
		for _, to := range allRun {
			if got := RunTransition(from, to) == nil; got != allowed[[2]domain.RunStatus{from, to}] {
				t.Errorf("RunTransition(%s, %s) allowed=%v", from, to, got)
			}
		}
	}
	// An untrusted run can never start running without approval.
	if RunTransition(domain.RunAwaitingApproval, domain.RunRunning) == nil {
		t.Fatal("awaiting_approval must not skip straight to running")
	}
}

func TestJobTransition_AllowedEdges(t *testing.T) {
	allowed := map[[2]domain.JobStatus]bool{
		{domain.JobPending, domain.JobQueued}:    true,
		{domain.JobPending, domain.JobSkipped}:   true,
		{domain.JobPending, domain.JobCanceled}:  true,
		{domain.JobQueued, domain.JobRunning}:    true,
		{domain.JobQueued, domain.JobCanceled}:   true,
		{domain.JobQueued, domain.JobFailed}:     true,
		{domain.JobRunning, domain.JobSucceeded}: true,
		{domain.JobRunning, domain.JobFailed}:    true,
		{domain.JobRunning, domain.JobCanceled}:  true,
		{domain.JobRunning, domain.JobQueued}:    true,
	}
	for _, from := range allJob {
		for _, to := range allJob {
			got := JobTransition(from, to) == nil
			if got != allowed[[2]domain.JobStatus{from, to}] {
				t.Errorf("JobTransition(%s, %s) allowed=%v", from, to, got)
			}
			if from.IsTerminal() && got {
				t.Errorf("terminal job %s moved", from)
			}
		}
	}
}

func TestInitialRunStatus(t *testing.T) {
	cases := []struct {
		approval, valid bool
		want            domain.RunStatus
	}{
		{false, true, domain.RunQueued},
		{true, true, domain.RunAwaitingApproval},
		{true, false, domain.RunFailed},
		{false, false, domain.RunFailed},
	}
	for _, c := range cases {
		got := InitialRunStatus(c.approval, c.valid)
		if got != c.want || !ValidInitialRunStatus(got) {
			t.Errorf("InitialRunStatus(%v, %v) = %s", c.approval, c.valid, got)
		}
	}
	if ValidInitialRunStatus(domain.RunRunning) || ValidInitialRunStatus(domain.RunSucceeded) {
		t.Fatal("runs must not be created running or finished")
	}
}

func TestRunOutcome(t *testing.T) {
	cases := []struct {
		jobs []domain.JobStatus
		want domain.RunStatus
		ok   bool
	}{
		{[]domain.JobStatus{domain.JobSucceeded, domain.JobSucceeded}, domain.RunSucceeded, true},
		{[]domain.JobStatus{domain.JobSucceeded, domain.JobFailed, domain.JobSkipped}, domain.RunFailed, true},
		{[]domain.JobStatus{domain.JobFailed, domain.JobCanceled}, domain.RunCanceled, true},
		{[]domain.JobStatus{domain.JobCanceled, domain.JobFailed}, domain.RunCanceled, true},
		{[]domain.JobStatus{domain.JobSucceeded, domain.JobRunning}, "", false},
		{[]domain.JobStatus{domain.JobPending}, "", false},
		{nil, domain.RunSucceeded, true},
	}
	for _, c := range cases {
		got, ok := RunOutcome(c.jobs)
		if got != c.want || ok != c.ok {
			t.Errorf("RunOutcome(%v) = %s,%v want %s,%v", c.jobs, got, ok, c.want, c.ok)
		}
	}
}

func TestStatusIsTerminal(t *testing.T) {
	for _, s := range allJob {
		want := s == domain.JobSucceeded || s == domain.JobFailed || s == domain.JobCanceled || s == domain.JobSkipped
		if s.IsTerminal() != want {
			t.Errorf("%s.IsTerminal() = %v", s, !want)
		}
	}
}
