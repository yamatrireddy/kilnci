// SPDX-License-Identifier: Apache-2.0

// Package runs implements run use cases: listing and reading runs, canceling
// them, approving untrusted runs, creating runs from a parsed pipeline, and
// linting pipelines.
//
// User-facing methods authorize against the specific org and project via
// authz; a caller who is not a member of the org gets domain.ErrNotFound, and
// a run is always looked up by (org, project, run ID) so an ID from another
// project or org is indistinguishable from a missing one. CreateRun is a
// system operation: its callers (webhook triggers, the manual-run use case)
// authorize before calling it.
package runs

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"go.opentelemetry.io/otel"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/engine"
	"github.com/yamatrireddy/kilnci/server/internal/engine/spec"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/service/paging"
	"github.com/yamatrireddy/kilnci/server/internal/store"
)

var tracer = otel.Tracer("github.com/yamatrireddy/kilnci/server/internal/service/runs")

// Store is the persistence this service needs.
type Store interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
	GetOrgForMember(ctx context.Context, slug, userID string) (domain.OrgWithRole, error)
	GetProject(ctx context.Context, orgID, slug string) (domain.Project, error)
	NextRunNumber(ctx context.Context, orgID, projectID string) (int64, error)
	CreateRun(ctx context.Context, r domain.Run) (domain.Run, error)
	CreateJob(ctx context.Context, j domain.Job) error
	GetRun(ctx context.Context, orgID, projectID, runID string) (domain.Run, error)
	LockRun(ctx context.Context, orgID, runID string) (domain.Run, error)
	GetRunByIdempotencyKey(ctx context.Context, orgID, projectID, key string) (domain.Run, error)
	ListRuns(ctx context.Context, orgID, projectID, beforeID string, limit int32) ([]domain.Run, error)
	ListJobs(ctx context.Context, orgID, runID string) ([]domain.Job, error)
	UpdateRunStatus(ctx context.Context, c store.RunStatusChange) error
	UpdateJobStatus(ctx context.Context, c store.JobStatusChange) error
	RequestJobCancel(ctx context.Context, orgID, jobID string) error
}

// Authorizer decides whether a principal may act on a resource.
type Authorizer interface {
	Check(ctx context.Context, p *authz.Principal, a authz.Action, res authz.Resource) error
}

// Auditor records privileged actions.
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) error
}

// Progressor advances a run after its jobs change (internal/scheduler).
type Progressor interface {
	Progress(ctx context.Context, orgID, runID string) (domain.Run, error)
}

// Service implements the run use cases.
type Service struct {
	store    Store
	az       Authorizer
	audit    Auditor
	progress Progressor
	ids      *ids.Generator
	now      func() time.Time
}

// NewService returns a Service. now may be nil (time.Now).
func NewService(s Store, az Authorizer, a Auditor, p Progressor, gen *ids.Generator, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: s, az: az, audit: a, progress: p, ids: gen, now: now}
}

// Detail is a run with its jobs.
type Detail struct {
	Run  domain.Run
	Jobs []domain.Job
}

func principal(ctx context.Context) (*authz.Principal, error) {
	p, ok := authz.FromContext(ctx)
	if !ok {
		return nil, domain.ErrUnauthenticated
	}
	return p, nil
}

// resolve finds the org (through the caller's membership) and project, and
// authorizes a on them.
func (s *Service) resolve(ctx context.Context, orgSlug, projectSlug string, a authz.Action) (domain.Project, error) {
	p, err := principal(ctx)
	if err != nil {
		return domain.Project{}, err
	}
	if domain.ValidateSlug("orgSlug", orgSlug) != nil || domain.ValidateSlug("projectSlug", projectSlug) != nil {
		return domain.Project{}, domain.ErrNotFound
	}
	org, err := s.store.GetOrgForMember(ctx, orgSlug, p.UserID)
	if err != nil {
		return domain.Project{}, fmt.Errorf("resolve org: %w", err)
	}
	if err := s.az.Check(ctx, p, a, authz.Resource{OrgID: org.ID}); err != nil {
		return domain.Project{}, fmt.Errorf("authorize %s: %w", a, err)
	}
	proj, err := s.store.GetProject(ctx, org.ID, projectSlug)
	if err != nil {
		return domain.Project{}, fmt.Errorf("resolve project: %w", err)
	}
	return proj, nil
}

// ListRuns lists a project's runs, newest first.
func (s *Service) ListRuns(ctx context.Context, orgSlug, projectSlug string, pr paging.Request) (paging.Page[domain.Run], error) {
	ctx, span := tracer.Start(ctx, "runs.ListRuns")
	defer span.End()
	proj, err := s.resolve(ctx, orgSlug, projectSlug, authz.ActionRunsList)
	if err != nil {
		return paging.Page[domain.Run]{}, err
	}
	before, limit, err := pr.Parse()
	if err != nil {
		return paging.Page[domain.Run]{}, err //nolint:wrapcheck // validation error
	}
	rs, err := s.store.ListRuns(ctx, proj.OrgID, proj.ID, before, limit+1)
	if err != nil {
		return paging.Page[domain.Run]{}, fmt.Errorf("list runs: %w", err)
	}
	return paging.Build(rs, limit, func(r domain.Run) string { return r.ID }), nil
}

// GetRun returns a run and its jobs.
func (s *Service) GetRun(ctx context.Context, orgSlug, projectSlug, runID string) (Detail, error) {
	ctx, span := tracer.Start(ctx, "runs.GetRun")
	defer span.End()
	proj, err := s.resolve(ctx, orgSlug, projectSlug, authz.ActionRunsRead)
	if err != nil {
		return Detail{}, err
	}
	return s.detail(ctx, proj, runID)
}

func (s *Service) detail(ctx context.Context, proj domain.Project, runID string) (Detail, error) {
	if !ids.Valid(runID) {
		return Detail{}, domain.ErrNotFound
	}
	run, err := s.store.GetRun(ctx, proj.OrgID, proj.ID, runID)
	if err != nil {
		return Detail{}, fmt.Errorf("get run: %w", err)
	}
	jobs, err := s.store.ListJobs(ctx, proj.OrgID, run.ID)
	if err != nil {
		return Detail{}, fmt.Errorf("list jobs: %w", err)
	}
	return Detail{Run: run, Jobs: jobs}, nil
}

// CancelRun cancels a run: pending and queued jobs are canceled now, running
// jobs are flagged so their runners stop them, and the run finishes once no
// job is running. Canceling a finished run is domain.ErrConflict.
func (s *Service) CancelRun(ctx context.Context, orgSlug, projectSlug, runID string) (Detail, error) {
	ctx, span := tracer.Start(ctx, "runs.CancelRun")
	defer span.End()
	proj, err := s.resolve(ctx, orgSlug, projectSlug, authz.ActionRunsCancel)
	if err != nil {
		return Detail{}, err
	}
	if _, err := s.detail(ctx, proj, runID); err != nil {
		return Detail{}, err
	}
	ctx = logging.WithOrgID(ctx, proj.OrgID)
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		run, err := s.store.LockRun(ctx, proj.OrgID, runID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if run.Status.IsTerminal() {
			return fmt.Errorf("run already finished: %w", domain.ErrConflict)
		}
		jobs, err := s.store.ListJobs(ctx, proj.OrgID, runID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		now := s.now().UTC()
		for _, j := range jobs {
			switch j.Status {
			case domain.JobPending, domain.JobQueued:
				if err := engine.JobTransition(j.Status, domain.JobCanceled); err != nil {
					return err //nolint:wrapcheck // domain error
				}
				if err := s.store.UpdateJobStatus(ctx, store.JobStatusChange{
					OrgID: j.OrgID, JobID: j.ID, From: j.Status, To: domain.JobCanceled, At: now, FailureReason: "canceled by a user",
				}); err != nil {
					return err //nolint:wrapcheck // store errors are contextual
				}
			case domain.JobRunning:
				if err := s.store.RequestJobCancel(ctx, j.OrgID, j.ID); err != nil {
					return err //nolint:wrapcheck // store errors are contextual
				}
			default:
			}
		}
		if run.Status == domain.RunAwaitingApproval {
			// Nothing ran; finish immediately.
			if err := engine.RunTransition(run.Status, domain.RunCanceled); err != nil {
				return err //nolint:wrapcheck // domain error
			}
			if err := s.store.UpdateRunStatus(ctx, store.RunStatusChange{
				OrgID: run.OrgID, RunID: run.ID, From: run.Status, To: domain.RunCanceled, FinishedAt: &now,
			}); err != nil {
				return err //nolint:wrapcheck // store errors are contextual
			}
		} else if _, err := s.progress.Progress(ctx, proj.OrgID, runID); err != nil {
			return err //nolint:wrapcheck // contextual
		}
		return s.audit.Record(ctx, audit.Entry{
			OrgID: proj.OrgID, Action: "runs:cancel", TargetType: "run", TargetID: runID,
			Details: map[string]string{"project_id": proj.ID, "from": string(run.Status)},
		})
	})
	if err != nil {
		return Detail{}, fmt.Errorf("cancel run: %w", err)
	}
	return s.detail(ctx, proj, runID)
}

// ApproveRun lets an untrusted run's jobs start. Only runs awaiting approval
// can be approved (domain.ErrConflict otherwise). The approval is audited
// because it runs fork code on the org's runners (ADR-0008 §5).
func (s *Service) ApproveRun(ctx context.Context, orgSlug, projectSlug, runID string) (Detail, error) {
	ctx, span := tracer.Start(ctx, "runs.ApproveRun")
	defer span.End()
	proj, err := s.resolve(ctx, orgSlug, projectSlug, authz.ActionRunsApprove)
	if err != nil {
		return Detail{}, err
	}
	if _, err := s.detail(ctx, proj, runID); err != nil {
		return Detail{}, err
	}
	ctx = logging.WithOrgID(ctx, proj.OrgID)
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		run, err := s.store.LockRun(ctx, proj.OrgID, runID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if err := engine.RunTransition(run.Status, domain.RunQueued); err != nil {
			return fmt.Errorf("run is not awaiting approval: %w", domain.ErrConflict)
		}
		if err := s.store.UpdateRunStatus(ctx, store.RunStatusChange{
			OrgID: run.OrgID, RunID: run.ID, From: run.Status, To: domain.RunQueued,
		}); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if _, err := s.progress.Progress(ctx, proj.OrgID, runID); err != nil {
			return err //nolint:wrapcheck // contextual
		}
		return s.audit.Record(ctx, audit.Entry{
			OrgID: proj.OrgID, Action: "runs:approve", TargetType: "run", TargetID: runID,
			Details: map[string]string{"project_id": proj.ID, "commit_sha": run.CommitSHA, "fork": fmt.Sprint(run.IsFork)},
		})
	})
	if err != nil {
		return Detail{}, fmt.Errorf("approve run: %w", err)
	}
	return s.detail(ctx, proj, runID)
}

// LintPipeline validates a pipeline definition. An invalid pipeline is not an
// error: its problems are returned.
func (s *Service) LintPipeline(ctx context.Context, source string) ([]spec.Problem, error) {
	ctx, span := tracer.Start(ctx, "runs.LintPipeline")
	defer span.End()
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.az.Check(ctx, p, authz.ActionPipelinesLint, authz.Resource{OwnerUserID: p.UserID}); err != nil {
		return nil, fmt.Errorf("authorize: %w", err)
	}
	_, err = spec.Parse([]byte(source))
	var pe *spec.Error
	switch {
	case err == nil:
		return []spec.Problem{}, nil
	case errors.As(err, &pe):
		return pe.Problems, nil
	default:
		return nil, fmt.Errorf("lint pipeline: %w", err)
	}
}

// NewRun describes a run to create. Every string field except the VCS
// identifiers is untrusted display text and is sanitized.
type NewRun struct {
	OrgID, ProjectID string
	Event            domain.TriggerEvent
	Ref              string
	Branch           string
	CommitSHA        string
	Title            string
	PRNumber         int
	// Trusted must be set explicitly, and only when the change provably
	// comes from the project's own repository (a push, a pull request whose
	// head repository ID equals the base repository ID, or a developer's
	// manual run). The zero value is untrusted: the run needs approval and
	// never uses trusted runners (fail closed).
	Trusted bool
	// IsFork marks a pull request from another repository. A fork run is
	// never trusted, whatever Trusted says.
	IsFork         bool
	ActorLogin     string
	CreatedBy      string
	IdempotencyKey string
	// Pipeline is the parsed pipeline; nil when it could not be loaded, in
	// which case PipelineErr says why and the run is created failed.
	Pipeline    *spec.Pipeline
	PipelineErr error
	// RequireApproval starts even a trusted run in awaiting_approval.
	RequireApproval bool
}

// ErrNoPipeline is the PipelineErr for a commit without .kiln/pipeline.yaml.
var ErrNoPipeline = errors.New("no pipeline file")

// pipelineErrorText turns a load failure into text safe to show every viewer
// of the run: validation problems (which never echo document values) or a
// fixed message. Raw errors (which could carry internal URLs or response
// bodies) are never stored.
func pipelineErrorText(err error) string {
	var pe *spec.Error
	switch {
	case errors.As(err, &pe):
		parts := make([]string, len(pe.Problems))
		for i, p := range pe.Problems {
			parts[i] = p.String()
		}
		return "invalid pipeline: " + strings.Join(parts, "; ")
	case errors.Is(err, ErrNoPipeline):
		return "no " + spec.Path + " in this commit"
	default:
		return "the pipeline could not be loaded"
	}
}

var (
	shaPattern = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	refPattern = regexp.MustCompile(`^refs/(heads|pull)/[^\x00-\x20\x7f~^:?*\[\\]{1,240}$`)
)

// Limits on untrusted text stored with a run.
const (
	maxTitleBytes = 1024
	maxShortBytes = 255
	maxErrorBytes = 8192
)

// CreateRun creates a run and its jobs in one transaction and queues the
// jobs that can start. It does not authorize: callers must. With an
// idempotency key that was already used for the project, the existing run is
// returned.
func (s *Service) CreateRun(ctx context.Context, nr NewRun) (domain.Run, error) {
	ctx, span := tracer.Start(ctx, "runs.CreateRun")
	defer span.End()
	if !shaPattern.MatchString(nr.CommitSHA) || !refPattern.MatchString(nr.Ref) || strings.Contains(nr.Ref, "..") {
		return domain.Run{}, domain.NewValidationError("ref", "must be a branch or pull request ref and a full commit SHA")
	}
	switch nr.Event {
	case domain.EventPush, domain.EventPullRequest, domain.EventManual:
	default:
		return domain.Run{}, domain.NewValidationError("event", "is not a supported event")
	}
	if nr.PRNumber < 0 || nr.PRNumber > math.MaxInt32 {
		return domain.Run{}, domain.NewValidationError("prNumber", "is out of range")
	}
	if nr.Pipeline == nil && nr.PipelineErr == nil {
		return domain.Run{}, domain.NewValidationError("pipeline", "is required")
	}
	trusted := nr.Trusted && !nr.IsFork
	now := s.now().UTC()
	run := domain.Run{
		ID: s.ids.New(), OrgID: nr.OrgID, ProjectID: nr.ProjectID, Event: nr.Event, Ref: nr.Ref,
		Branch: clean(nr.Branch, maxShortBytes), CommitSHA: nr.CommitSHA, Title: clean(nr.Title, maxTitleBytes),
		PRNumber: nr.PRNumber, IsFork: nr.IsFork, Trusted: trusted, ActorLogin: clean(nr.ActorLogin, maxShortBytes),
		CreatedBy: nr.CreatedBy, IdempotencyKey: nr.IdempotencyKey, CreatedAt: now,
		Status: engine.InitialRunStatus(nr.RequireApproval || !trusted, nr.Pipeline != nil),
	}
	if nr.Pipeline == nil {
		run.Error = truncate(pipelineErrorText(nr.PipelineErr), maxErrorBytes)
		run.FinishedAt = &now
	}
	if !engine.ValidInitialRunStatus(run.Status) {
		return domain.Run{}, fmt.Errorf("invalid initial status %s: %w", run.Status, domain.ErrConflict)
	}

	err := s.store.InTx(ctx, func(ctx context.Context) error {
		if nr.IdempotencyKey != "" {
			existing, err := s.store.GetRunByIdempotencyKey(ctx, nr.OrgID, nr.ProjectID, nr.IdempotencyKey)
			if err == nil {
				// Replaying a key is only valid for the same request.
				if existing.Event != run.Event || existing.Ref != run.Ref || existing.CommitSHA != run.CommitSHA ||
					existing.CreatedBy != run.CreatedBy {
					return domain.NewValidationError("Idempotency-Key", "was already used for a different request")
				}
				run = existing
				return nil
			}
			if !errors.Is(err, domain.ErrNotFound) {
				return err //nolint:wrapcheck // store errors are contextual
			}
		}
		n, err := s.store.NextRunNumber(ctx, nr.OrgID, nr.ProjectID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		run.Number = n
		created, err := s.store.CreateRun(ctx, run)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		run = created
		if nr.Pipeline == nil {
			return nil
		}
		for _, j := range nr.Pipeline.Jobs {
			if err := s.store.CreateJob(ctx, s.newJob(run, nr.Pipeline, j, now)); err != nil {
				return err //nolint:wrapcheck // store errors are contextual
			}
		}
		if run.Status == domain.RunQueued {
			progressed, err := s.progress.Progress(ctx, run.OrgID, run.ID)
			if err != nil {
				return err //nolint:wrapcheck // contextual
			}
			run = progressed
		}
		return nil
	})
	if err != nil {
		return domain.Run{}, fmt.Errorf("create run: %w", err)
	}
	return run, nil
}

func (s *Service) newJob(run domain.Run, pl *spec.Pipeline, j spec.Job, now time.Time) domain.Job {
	steps := make([]domain.JobStep, len(j.Steps))
	for i, st := range j.Steps {
		steps[i] = domain.JobStep{Name: st.Name, Run: st.Run, Env: toEnv(st.Env), Timeout: st.Timeout}
	}
	return domain.Job{
		ID: s.ids.New(), OrgID: run.OrgID, RunID: run.ID, Name: j.ID, Status: domain.JobPending,
		Needs: j.Needs, Image: j.Image, Labels: j.RunsOn, Steps: steps, Env: mergeEnv(pl.Env, j.Env),
		Timeout: j.Timeout, Attempt: 0, MaxAttempts: 1 + j.Retries, Trusted: run.Trusted, CreatedAt: now,
	}
}

func toEnv(in []spec.EnvVar) []domain.EnvVar {
	out := make([]domain.EnvVar, len(in))
	for i, e := range in {
		out[i] = domain.EnvVar{Name: e.Name, Value: e.Value}
	}
	return out
}

// mergeEnv overlays job env on pipeline env; the result is sorted by name.
func mergeEnv(base, over []spec.EnvVar) []domain.EnvVar {
	m := make(map[string]string, len(base)+len(over))
	var names []string
	for _, list := range [][]spec.EnvVar{base, over} {
		for _, e := range list {
			if _, ok := m[e.Name]; !ok {
				names = append(names, e.Name)
			}
			m[e.Name] = e.Value
		}
	}
	out := make([]domain.EnvVar, 0, len(names))
	slices.Sort(names)
	for _, n := range names {
		out = append(out, domain.EnvVar{Name: n, Value: m[n]})
	}
	return out
}

// clean makes untrusted single-line text safe to store and display: invalid
// UTF-8 and control characters are replaced, only the first line is kept,
// and the result is truncated on a rune boundary.
func clean(s string, maxBytes int) string {
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.Map(func(r rune) rune {
		if isUnsafeRune(r) {
			return utf8.RuneError
		}
		return r
	}, s)
	return truncate(strings.TrimSpace(s), maxBytes)
}

// isUnsafeRune reports control characters and invisible format characters
// (bidi overrides, zero-width joiners, soft hyphens, line separators) that
// can make untrusted text display differently from what it says.
func isUnsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}

func truncate(s string, maxBytes int) string {
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
