// SPDX-License-Identifier: Apache-2.0

package authz

import "github.com/yamatrireddy/kilnci/server/internal/domain"

// Action is a permission name, "<resource>:<verb>". Every API operation
// declares one as x-kiln-permission in docs/api/openapi.yaml, and the router
// refuses to start if a route names an action that is not in this table.
type Action string

// Actions. Keep sorted by resource; add new ones here and to the policy table.
const (
	ActionSessionRead   Action = "session:read"
	ActionSessionDelete Action = "session:delete"

	ActionOrgsList   Action = "orgs:list"
	ActionOrgsCreate Action = "orgs:create"
	ActionOrgsRead   Action = "orgs:read"

	ActionMembersList   Action = "members:list"
	ActionMembersManage Action = "members:manage"

	ActionProjectsList   Action = "projects:list"
	ActionProjectsCreate Action = "projects:create"
	ActionProjectsRead   Action = "projects:read"

	ActionAuditRead Action = "audit:read"

	ActionRunsList    Action = "runs:list"
	ActionRunsRead    Action = "runs:read"
	ActionRunsCancel  Action = "runs:cancel"
	ActionRunsApprove Action = "runs:approve"

	ActionLogsRead Action = "logs:read"

	ActionPipelinesLint Action = "pipelines:lint"

	ActionRunnersList   Action = "runners:list"
	ActionRunnersManage Action = "runners:manage"

	ActionTokensList   Action = "tokens:list"
	ActionTokensCreate Action = "tokens:create"
	ActionTokensDelete Action = "tokens:delete"
)

// Pseudo-permissions for routes reachable without a principal. The router
// allows them only on an explicit allowlist of paths (CLAUDE.md invariant 9,
// ADR-0003).
const (
	// PermissionPublic marks /healthz, /readyz, and signature-verified webhooks.
	PermissionPublic Action = "public"
	// PermissionPreAuth marks the OIDC login flow endpoints.
	PermissionPreAuth Action = "preauth"
)

// rule says what minimum org role an action needs. selfOnly actions concern the
// principal's own credential and need no org membership; instanceAdmin actions
// need the instance-admin flag.
type rule struct {
	minRole       domain.Role
	selfOnly      bool
	instanceAdmin bool
}

// policy is the complete role → action table. An action missing from this
// table is denied for everyone.
var policy = map[Action]rule{
	ActionSessionRead:   {selfOnly: true},
	ActionSessionDelete: {selfOnly: true},

	ActionOrgsList:   {selfOnly: true}, // lists only the caller's own orgs
	ActionOrgsCreate: {instanceAdmin: true},
	ActionOrgsRead:   {minRole: domain.RoleViewer},

	ActionMembersList:   {minRole: domain.RoleViewer},
	ActionMembersManage: {minRole: domain.RoleAdmin},

	ActionProjectsList:   {minRole: domain.RoleViewer},
	ActionProjectsCreate: {minRole: domain.RoleAdmin},
	ActionProjectsRead:   {minRole: domain.RoleViewer},

	ActionAuditRead: {minRole: domain.RoleAdmin},

	ActionRunsList:   {minRole: domain.RoleViewer},
	ActionRunsRead:   {minRole: domain.RoleViewer},
	ActionRunsCancel: {minRole: domain.RoleDeveloper},
	// Approving runs untrusted (fork) code on the org's runners (ADR-0008 §5).
	ActionRunsApprove: {minRole: domain.RoleDeveloper},

	// Logs can contain leaked secrets despite masking (A10); same audience
	// as the run itself.
	ActionLogsRead: {minRole: domain.RoleViewer},

	ActionPipelinesLint: {selfOnly: true}, // reads no tenant data

	ActionRunnersList:   {minRole: domain.RoleAdmin},
	ActionRunnersManage: {minRole: domain.RoleAdmin},

	ActionTokensList:   {selfOnly: true},
	ActionTokensCreate: {selfOnly: true},
	ActionTokensDelete: {selfOnly: true},
}

// Known reports whether a is a declared action (or a pseudo-permission).
func Known(a Action) bool {
	if a == PermissionPublic || a == PermissionPreAuth {
		return true
	}
	_, ok := policy[a]
	return ok
}

// Actions returns every declared action, for exhaustive tests.
func Actions() []Action {
	out := make([]Action, 0, len(policy))
	for a := range policy {
		out = append(out, a)
	}
	return out
}
