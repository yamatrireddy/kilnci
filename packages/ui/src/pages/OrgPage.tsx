// SPDX-License-Identifier: Apache-2.0
import { roleAtLeast } from "@kiln/core";
import { Anchor, Breadcrumbs, Group, Stack, Tabs, Text, Title } from "@mantine/core";
import { Link, useParams, useSearchParams } from "react-router";

import { QueryState } from "../components/QueryState";
import { RoleBadge } from "../components/RoleBadge";
import { useOrg } from "../queries";
import { AuditTab } from "./org/AuditTab";
import { MembersTab } from "./org/MembersTab";
import { ProjectsTab } from "./org/ProjectsTab";

const TABS = ["projects", "members", "audit"] as const;
type Tab = (typeof TABS)[number];

export function OrgPage() {
  const { orgSlug = "" } = useParams();
  const org = useOrg(orgSlug);
  const [params, setParams] = useSearchParams();
  const requested = params.get("tab");
  const tab: Tab = TABS.includes(requested as Tab) ? (requested as Tab) : "projects";

  return (
    <QueryState query={org} label="organization">
      {(o) => {
        const isAdmin = roleAtLeast(o.role, "admin");
        return (
          <Stack>
            <Breadcrumbs>
              <Anchor component={Link} to="/orgs">
                Organizations
              </Anchor>
              <Text>{o.name}</Text>
            </Breadcrumbs>
            <Group justify="space-between">
              <div>
                <Title order={2}>{o.name}</Title>
                <Text c="dimmed" ff="monospace" size="sm">
                  {o.slug}
                </Text>
              </div>
              <RoleBadge role={o.role} />
            </Group>
            <Tabs
              value={tab}
              onChange={(v) => {
                setParams(v && v !== "projects" ? { tab: v } : {}, { replace: true });
              }}
              keepMounted={false}
            >
              <Tabs.List>
                <Tabs.Tab value="projects">Projects</Tabs.Tab>
                <Tabs.Tab value="members">Members</Tabs.Tab>
                {isAdmin ? <Tabs.Tab value="audit">Audit log</Tabs.Tab> : null}
              </Tabs.List>
              <Tabs.Panel value="projects" pt="md">
                <ProjectsTab org={o} />
              </Tabs.Panel>
              <Tabs.Panel value="members" pt="md">
                <MembersTab org={o} />
              </Tabs.Panel>
              {isAdmin ? (
                <Tabs.Panel value="audit" pt="md">
                  <AuditTab org={o} />
                </Tabs.Panel>
              ) : null}
            </Tabs>
          </Stack>
        );
      }}
    </QueryState>
  );
}
