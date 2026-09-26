// SPDX-License-Identifier: Apache-2.0

/**
 * TanStack Query keys, shared so every client caches and invalidates the same
 * way. Keys are hierarchical: invalidating `queryKeys.org(slug)` also
 * invalidates that org's projects and members.
 */
export const queryKeys = {
  session: () => ["session"] as const,
  orgs: () => ["orgs"] as const,
  org: (orgSlug: string) => ["orgs", orgSlug] as const,
  projects: (orgSlug: string) => ["orgs", orgSlug, "projects"] as const,
  project: (orgSlug: string, projectSlug: string) => ["orgs", orgSlug, "projects", projectSlug] as const,
  runs: (orgSlug: string, projectSlug: string) => ["orgs", orgSlug, "projects", projectSlug, "runs"] as const,
  run: (orgSlug: string, projectSlug: string, runId: string) => ["orgs", orgSlug, "projects", projectSlug, "runs", runId] as const,
  jobLog: (orgSlug: string, projectSlug: string, runId: string, jobId: string) =>
    ["orgs", orgSlug, "projects", projectSlug, "runs", runId, "jobs", jobId, "log"] as const,
  members: (orgSlug: string) => ["orgs", orgSlug, "members"] as const,
  auditEvents: (orgSlug: string) => ["orgs", orgSlug, "audit-events"] as const,
  tokens: () => ["tokens"] as const,
};
