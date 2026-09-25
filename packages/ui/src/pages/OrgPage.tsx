// SPDX-License-Identifier: Apache-2.0
import { roleAtLeast } from "@kiln/core";
import { useParams, useSearchParams } from "react-router";

import { QueryState } from "../components/QueryState";
import { RoleBadge } from "../components/RoleBadge";
import { Breadcrumbs, PageHeader, Tabs } from "../components/ui";
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
        const tabs: { value: Tab; label: string }[] = [
          { value: "projects", label: "Projects" },
          { value: "members", label: "Members" },
          ...(isAdmin ? [{ value: "audit" as const, label: "Audit log" }] : []),
        ];
        // A non-admin who follows a ?tab=audit link lands on Projects.
        const current: Tab = tabs.some((t) => t.value === tab) ? tab : "projects";
        return (
          <div className="flex flex-col gap-5">
            <Breadcrumbs items={[{ label: "Organizations", to: "/orgs" }, { label: o.name }]} />
            <PageHeader
              title={o.name}
              subtitle={<span className="font-mono">{o.slug}</span>}
              actions={<RoleBadge role={o.role} />}
            />
            <Tabs
              label={`${o.name} sections`}
              value={current}
              tabs={tabs}
              onChange={(v) => {
                setParams(v !== "projects" ? { tab: v } : {}, { replace: true });
              }}
            >
              {current === "projects" ? <ProjectsTab org={o} /> : null}
              {current === "members" ? <MembersTab org={o} /> : null}
              {current === "audit" ? <AuditTab org={o} /> : null}
            </Tabs>
          </div>
        );
      }}
    </QueryState>
  );
}
