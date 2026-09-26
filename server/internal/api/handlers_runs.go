// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"

	"github.com/yamatrireddy/kilnci/server/internal/api/gen"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/engine/spec"
	"github.com/yamatrireddy/kilnci/server/internal/service/paging"
	"github.com/yamatrireddy/kilnci/server/internal/service/runs"
)

// RunService is what the run handlers need from internal/service/runs.
type RunService interface {
	ListRuns(ctx context.Context, orgSlug, projectSlug string, pr paging.Request) (paging.Page[domain.Run], error)
	GetRun(ctx context.Context, orgSlug, projectSlug, runID string) (runs.Detail, error)
	CancelRun(ctx context.Context, orgSlug, projectSlug, runID string) (runs.Detail, error)
	ApproveRun(ctx context.Context, orgSlug, projectSlug, runID string) (runs.Detail, error)
	LintPipeline(ctx context.Context, source string) ([]spec.Problem, error)
}

func toGenRun(r domain.Run) gen.Run {
	out := gen.Run{
		Id: r.ID, Number: r.Number, Status: gen.RunStatus(r.Status), Event: gen.RunEvent(r.Event), Ref: r.Ref,
		Branch: r.Branch, CommitSha: r.CommitSHA, Title: r.Title, IsFork: r.IsFork, Trusted: r.Trusted,
		ActorLogin: r.ActorLogin, CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
	}
	if r.PRNumber > 0 {
		n := r.PRNumber
		out.PrNumber = &n
	}
	if r.Error != "" {
		e := r.Error
		out.Error = &e
	}
	return out
}

func toGenJob(j domain.Job) gen.Job {
	steps := make([]gen.JobStep, len(j.Steps))
	for i, st := range j.Steps {
		steps[i] = gen.JobStep{Name: st.Name}
	}
	return gen.Job{
		Id: j.ID, Name: j.Name, Status: gen.JobStatus(j.Status), Needs: nonNilStrings(j.Needs), Image: j.Image,
		Labels: nonNilStrings(j.Labels), Steps: steps, Attempt: j.Attempt, MaxAttempts: j.MaxAttempts,
		TimeoutSeconds: int(j.Timeout.Seconds()), ExitCode: j.ExitCode, FailureReason: j.FailureReason,
		QueuedAt: j.QueuedAt, StartedAt: j.StartedAt, FinishedAt: j.FinishedAt,
	}
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func toGenRunDetail(d runs.Detail) gen.RunDetail {
	out := gen.RunDetail{Run: toGenRun(d.Run), Jobs: make([]gen.Job, len(d.Jobs))}
	for i, j := range d.Jobs {
		out.Jobs[i] = toGenJob(j)
	}
	return out
}

func (s *server) listRuns(w http.ResponseWriter, r *http.Request) {
	pg, err := s.runs.ListRuns(r.Context(), r.PathValue("orgSlug"), r.PathValue("projectSlug"), pageRequest(r))
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	out := gen.RunList{Items: make([]gen.Run, len(pg.Items)), NextCursor: nextCursor(pg.NextCursor)}
	for i, run := range pg.Items {
		out.Items[i] = toGenRun(run)
	}
	writeJSON(w, http.StatusOK, out)
}

type runAction func(ctx context.Context, orgSlug, projectSlug, runID string) (runs.Detail, error)

func (s *server) runDetail(action func(*server) runAction) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, err := action(s)(r.Context(), r.PathValue("orgSlug"), r.PathValue("projectSlug"), r.PathValue("runId"))
		if err != nil {
			s.errs.write(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, toGenRunDetail(d))
	}
}

func (s *server) lintPipeline(w http.ResponseWriter, r *http.Request) {
	var body gen.LintRequest
	if err := decodeJSON(r, &body); err != nil {
		s.errs.write(w, r, err)
		return
	}
	problems, err := s.runs.LintPipeline(r.Context(), body.Pipeline)
	if err != nil {
		s.errs.write(w, r, err)
		return
	}
	out := gen.LintResult{Valid: len(problems) == 0, Problems: make([]gen.LintProblem, len(problems))}
	for i, p := range problems {
		out.Problems[i] = gen.LintProblem{Path: p.Path, Line: p.Line, Message: p.Message}
	}
	writeJSON(w, http.StatusOK, out)
}
