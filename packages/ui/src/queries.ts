// SPDX-License-Identifier: Apache-2.0
//
// TanStack Query hooks over @kiln/api-client. All server state flows through
// these hooks (coding-standards §11); components never call fetch.
import type { APITokenCreate, MemberAdd, OrgCreate, ProjectCreate, Role } from "@kiln/api-client";
import { queryKeys } from "@kiln/core";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

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
