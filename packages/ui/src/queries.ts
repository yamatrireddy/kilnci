// SPDX-License-Identifier: Apache-2.0
//
// TanStack Query hooks over @kiln/api-client. All server state flows through
// these hooks (coding-standards §11); components never call fetch.
import type { APITokenCreate, MemberAdd, OrgCreate, ProjectCreate, Role } from "@kiln/api-client";
import { isFinishedStatus, queryKeys } from "@kiln/core";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { usePlatform } from "./platform";

export function useSession() {
  const { client } = usePlatform();
  return useQuery({ queryKey: queryKeys.session(), queryFn: () => client.getSession() });
}

export function useOrgs() {
  const { client } = usePlatform();
  return useQuery({ queryKey: queryKeys.orgs(), queryFn: () => client.listOrgs({ limit: 100 }) });
}

export function useOrg(orgSlug: string) {
  const { client } = usePlatform();
  return useQuery({ queryKey: queryKeys.org(orgSlug), queryFn: () => client.getOrg(orgSlug) });
}

export function useProjects(orgSlug: string) {
  const { client } = usePlatform();
  return useQuery({ queryKey: queryKeys.projects(orgSlug), queryFn: () => client.listProjects(orgSlug, { limit: 100 }) });
}

export function useProject(orgSlug: string, projectSlug: string) {
  const { client } = usePlatform();
  return useQuery({
    queryKey: queryKeys.project(orgSlug, projectSlug),
    queryFn: () => client.getProject(orgSlug, projectSlug),
  });
}

/** How often active runs, jobs, and stored logs are re-read. */
export const RUN_POLL_MS = 5_000;

export function useRuns(orgSlug: string, projectSlug: string) {
  const { client } = usePlatform();
  return useInfiniteQuery({
    queryKey: queryKeys.runs(orgSlug, projectSlug),
    queryFn: ({ pageParam }) => client.listRuns(orgSlug, projectSlug, { limit: 25, ...(pageParam ? { cursor: pageParam } : {}) }),
    initialPageParam: "",
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    // Keep statuses fresh while anything on screen can still change.
    refetchInterval: (q) =>
      q.state.data?.pages.some((p) => p.items.some((r) => !isFinishedStatus(r.status))) ? RUN_POLL_MS : false,
  });
}

export function useRun(orgSlug: string, projectSlug: string, runId: string) {
  const { client } = usePlatform();
  return useQuery({
    queryKey: queryKeys.run(orgSlug, projectSlug, runId),
    queryFn: () => client.getRun(orgSlug, projectSlug, runId),
    refetchInterval: (q) => {
      const d = q.state.data;
      if (!d) return false;
      return !isFinishedStatus(d.run.status) || d.jobs.some((j) => !isFinishedStatus(j.status)) ? RUN_POLL_MS : false;
    },
  });
}

/**
 * How often a client that cannot stream re-reads a running job's stored log.
 * Each read downloads the whole log, so this is deliberately slow (T-10).
 */
export const STORED_LOG_POLL_MS = 30_000;

/** The stored log, for clients that cannot stream; re-read while `live`. */
export function useStoredJobLog(orgSlug: string, projectSlug: string, runId: string, jobId: string, opts: { enabled: boolean; live: boolean }) {
  const { client } = usePlatform();
  return useQuery({
    queryKey: queryKeys.jobLog(orgSlug, projectSlug, runId, jobId),
    queryFn: () => client.getJobLog(orgSlug, projectSlug, runId, jobId),
    enabled: opts.enabled,
    refetchInterval: opts.live ? STORED_LOG_POLL_MS : false,
    refetchOnWindowFocus: false,
    staleTime: Infinity,
  });
}

function useRunAction(orgSlug: string, projectSlug: string, action: "cancel" | "approve") {
  const { client } = usePlatform();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (runId: string) =>
      action === "cancel" ? client.cancelRun(orgSlug, projectSlug, runId) : client.approveRun(orgSlug, projectSlug, runId),
    onSuccess: (detail, runId) => {
      qc.setQueryData(queryKeys.run(orgSlug, projectSlug, runId), detail);
      return qc.invalidateQueries({ queryKey: queryKeys.runs(orgSlug, projectSlug) });
    },
  });
}

export function useCancelRun(orgSlug: string, projectSlug: string) {
  return useRunAction(orgSlug, projectSlug, "cancel");
}

export function useApproveRun(orgSlug: string, projectSlug: string) {
  return useRunAction(orgSlug, projectSlug, "approve");
}

export function useMembers(orgSlug: string) {
  const { client } = usePlatform();
  return useQuery({ queryKey: queryKeys.members(orgSlug), queryFn: () => client.listMembers(orgSlug, { limit: 100 }) });
}

export function useAuditEvents(orgSlug: string, enabled: boolean) {
  const { client } = usePlatform();
  return useQuery({
    queryKey: queryKeys.auditEvents(orgSlug),
    queryFn: () => client.listAuditEvents(orgSlug, { limit: 100 }),
    enabled,
  });
}

export function useTokens() {
  const { client } = usePlatform();
  return useQuery({ queryKey: queryKeys.tokens(), queryFn: () => client.listTokens() });
}

export function useCreateOrg() {
  const { client } = usePlatform();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: OrgCreate) => client.createOrg(body),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.orgs() }),
  });
}

export function useCreateProject(orgSlug: string) {
  const { client } = usePlatform();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ProjectCreate) => client.createProject(orgSlug, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.projects(orgSlug) }),
  });
}

export function useAddMember(orgSlug: string) {
  const { client } = usePlatform();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: MemberAdd) => client.addMember(orgSlug, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.members(orgSlug) }),
  });
}

export function useUpdateMember(orgSlug: string) {
  const { client } = usePlatform();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: Role }) => client.updateMember(orgSlug, userId, role),
    // The org key is a prefix of the members key, so this refetches the member
    // list and the org (whose `role` changes if callers change their own role).
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.org(orgSlug) }),
  });
}

export function useRemoveMember(orgSlug: string) {
  const { client } = usePlatform();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) => client.removeMember(orgSlug, userId),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.members(orgSlug) }),
  });
}

export function useCreateToken() {
  const { client } = usePlatform();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: APITokenCreate) => client.createToken(body),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.tokens() }),
  });
}

export function useRevokeToken() {
  const { client } = usePlatform();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (tokenId: string) => client.revokeToken(tokenId),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.tokens() }),
  });
}

export function useSignOut() {
  const platform = usePlatform();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => platform.client.signOut(),
    onSettled: async () => {
      qc.clear();
      await platform.afterSignOut?.();
    },
  });
}
