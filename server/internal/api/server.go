// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
)

// Options configures the HTTP surface.
type Options struct {
	MaxBodyBytes   int64
	AllowedOrigins []string
	TrustedProxies []netip.Prefix
	// HSTS sends Strict-Transport-Security; set whenever the public URL is https.
	HSTS       bool
	RateLimits RateLimits
	// WebFS holds the built web app; nil disables serving it.
	WebFS fs.FS
}

// Deps are the collaborators the HTTP layer needs. Handlers call services
// only; they never touch the store.
type Deps struct {
	Log     *slog.Logger
	IDs     *ids.Generator
	Authn   Authenticator
	Auth    AuthService
	Orgs    OrgService
	Runs    RunService
	Runners RunnerService
	Logs    LogService
	VCS     VCSService
	Checks  map[string]ReadinessCheck
	Options Options
}

type server struct {
	log     *slog.Logger
	checks  map[string]ReadinessCheck
	errs    errorWriter
	ips     clientIPResolver
	auth    AuthService
	orgs    OrgService
	runs    RunService
	runners RunnerService
	logs    LogService
	vcs     VCSService
	streams streamLimiter
}

// NewHandler builds the complete, validated HTTP handler. It returns an error
// (and the server must not start) if any route violates the routing policy.
func NewHandler(d Deps) (http.Handler, *Router, error) {
	if d.Log == nil || d.IDs == nil {
		return nil, nil, errors.New("api: Log and IDs are required")
	}
	if d.Options.MaxBodyBytes <= 0 {
		return nil, nil, errors.New("api: MaxBodyBytes must be positive")
	}
	s := &server{
		log:     d.Log,
		checks:  d.Checks,
		errs:    errorWriter{log: d.Log},
		ips:     clientIPResolver{trusted: d.Options.TrustedProxies},
		auth:    d.Auth,
		orgs:    d.Orgs,
		runs:    d.Runs,
		runners: d.Runners,
		logs:    d.Logs,
		vcs:     d.VCS,
	}

	spec, err := loadSpec()
	if err != nil {
		return nil, nil, err
	}
	validator, err := newSpecValidator(spec)
	if err != nil {
		return nil, nil, err
	}
	lim := newLimiters(d.Options.RateLimits)

	rt := newRouter(d.Authn, s.errs)
	rt.validate = validator.validate
	rt.limits = lim
	s.register(rt)

	apiHandler, err := rt.build()
	if err != nil {
		return nil, nil, fmt.Errorf("build router: %w", err)
	}

	root := http.NewServeMux()
	root.Handle("/api/", apiHandler)
	root.Handle("/healthz", apiHandler)
	root.Handle("/readyz", apiHandler)
	if d.Options.WebFS != nil {
		spa, err := newSPAHandler(d.Options.WebFS, s.errs, d.Options.HSTS)
		if err != nil {
			return nil, nil, err
		}
		root.Handle("/", spa)
	} else {
		root.Handle("/", apiHandler)
	}

	return chain(root,
		recoverer(d.Log),
		requestID(d.IDs, s.ips),
		tracing(),
		requestMeta(s.ips),
		accessLog(d.Log, s.ips),
		securityHeaders(d.Options.HSTS),
		cors(d.Options.AllowedOrigins),
		rateLimit(lim, s.errs),
		bodyLimit(d.Options.MaxBodyBytes),
	), rt, nil
}

// register declares every operation in docs/api/openapi.yaml with its
// x-kiln-permission. TestRoutesMatchSpec keeps this list and the spec in sync.
func (s *server) register(rt *Router) {
	const (
		get, post, put, del = http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete
	)
	rt.Handle(get, "/healthz", authz.PermissionPublic, healthz)
	rt.Handle(get, "/readyz", authz.PermissionPublic, s.readyz)

	if s.auth != nil {
		rt.Handle(get, "/api/v1/auth/login", authz.PermissionPreAuth, s.startLogin)
		rt.Handle(get, "/api/v1/auth/callback", authz.PermissionPreAuth, s.completeLogin)
		rt.Handle(post, "/api/v1/auth/token", authz.PermissionPreAuth, s.exchangeToken)
		rt.Handle(get, "/api/v1/session", authz.ActionSessionRead, s.getSession)
		rt.Handle(del, "/api/v1/session", authz.ActionSessionDelete, s.deleteSession)
		rt.Handle(get, "/api/v1/tokens", authz.ActionTokensList, s.listTokens)
		rt.Handle(post, "/api/v1/tokens", authz.ActionTokensCreate, s.createToken)
		rt.Handle(del, "/api/v1/tokens/{tokenId}", authz.ActionTokensDelete, s.revokeToken)
	}
	if s.orgs != nil {
		rt.Handle(get, "/api/v1/orgs", authz.ActionOrgsList, s.listOrgs)
		rt.Handle(post, "/api/v1/orgs", authz.ActionOrgsCreate, s.createOrg)
		rt.Handle(get, "/api/v1/orgs/{orgSlug}", authz.ActionOrgsRead, s.getOrg)
		rt.Handle(get, "/api/v1/orgs/{orgSlug}/members", authz.ActionMembersList, s.listMembers)
		rt.Handle(post, "/api/v1/orgs/{orgSlug}/members", authz.ActionMembersManage, s.addMember)
		rt.Handle(put, "/api/v1/orgs/{orgSlug}/members/{userId}", authz.ActionMembersManage, s.updateMember)
		rt.Handle(del, "/api/v1/orgs/{orgSlug}/members/{userId}", authz.ActionMembersManage, s.removeMember)
		rt.Handle(get, "/api/v1/orgs/{orgSlug}/projects", authz.ActionProjectsList, s.listProjects)
		rt.Handle(post, "/api/v1/orgs/{orgSlug}/projects", authz.ActionProjectsCreate, s.createProject)
		rt.Handle(get, "/api/v1/orgs/{orgSlug}/projects/{projectSlug}", authz.ActionProjectsRead, s.getProject)
		rt.Handle(get, "/api/v1/orgs/{orgSlug}/audit-events", authz.ActionAuditRead, s.listAuditEvents)
	}
	if s.runs != nil {
		const runPath = "/api/v1/orgs/{orgSlug}/projects/{projectSlug}/runs"
		rt.Handle(get, runPath, authz.ActionRunsList, s.listRuns)
		rt.Handle(get, runPath+"/{runId}", authz.ActionRunsRead, s.runDetail(func(s *server) runAction { return s.runs.GetRun }))
		rt.Handle(post, runPath+"/{runId}/cancel", authz.ActionRunsCancel, s.runDetail(func(s *server) runAction { return s.runs.CancelRun }))
		rt.Handle(post, runPath+"/{runId}/approve", authz.ActionRunsApprove, s.runDetail(func(s *server) runAction { return s.runs.ApproveRun }))
		rt.Handle(post, "/api/v1/pipelines/lint", authz.ActionPipelinesLint, s.lintPipeline)
	}
	if s.vcs != nil {
		rt.Handle(post, "/api/v1/webhooks/github", authz.PermissionPublic, s.githubWebhook)
		rt.Handle(post, "/api/v1/admin/github-installations", authz.ActionVCSInstallationsManage, s.bindGitHubInstallation)
		rt.Handle(del, "/api/v1/admin/github-installations/{installationId}", authz.ActionVCSInstallationsManage, s.unbindGitHubInstallation)
		rt.Handle(get, "/api/v1/orgs/{orgSlug}/github-installations", authz.ActionVCSInstallationsList, s.listGitHubInstallations)
		const repoPath = "/api/v1/orgs/{orgSlug}/projects/{projectSlug}/repository"
		rt.Handle(get, repoPath, authz.ActionRepositoryRead, s.getRepository)
		rt.Handle(put, repoPath, authz.ActionRepositoryManage, s.linkRepository)
		rt.Handle(del, repoPath, authz.ActionRepositoryManage, s.unlinkRepository)
		rt.Handle(post, "/api/v1/orgs/{orgSlug}/projects/{projectSlug}/runs", authz.ActionRunsCreate, s.createRun)
	}
	if s.logs != nil {
		const jobPath = "/api/v1/orgs/{orgSlug}/projects/{projectSlug}/runs/{runId}/jobs/{jobId}"
		rt.Handle(get, jobPath+"/logs", authz.ActionLogsRead, s.getJobLog)
		rt.Handle(get, jobPath+"/logs/stream", authz.ActionLogsRead, s.streamJobLog)
	}
	if s.runners != nil {
		rt.Handle(get, "/api/v1/orgs/{orgSlug}/runners", authz.ActionRunnersList, s.listRunners)
		rt.Handle(del, "/api/v1/orgs/{orgSlug}/runners/{runnerId}", authz.ActionRunnersManage, s.revokeRunner)
		rt.Handle(post, "/api/v1/orgs/{orgSlug}/runner-registration-tokens", authz.ActionRunnersManage, s.createRunnerRegistrationToken)
	}
}
