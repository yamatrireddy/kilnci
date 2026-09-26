// SPDX-License-Identifier: Apache-2.0
import { formatDateTime } from "@kiln/core";
import { useParams } from "react-router";

import { QueryState } from "../components/QueryState";
import { Breadcrumbs, Card, PageHeader } from "../components/ui";
import { useProject } from "../queries";
import { RunsTable } from "./project/RunsTable";

export function ProjectPage() {
  const { orgSlug = "", projectSlug = "" } = useParams();
  const project = useProject(orgSlug, projectSlug);
  return (
    <QueryState query={project} label="project">
      {(p) => (
        <div className="flex flex-col gap-5">
          <Breadcrumbs
            items={[
              { label: "Organizations", to: "/orgs" },
              { label: orgSlug, to: `/orgs/${orgSlug}` },
              { label: p.name },
            ]}
          />
          <PageHeader
            title={p.name}
            subtitle={
              <>
                <span className="font-mono">
                  {orgSlug}/{p.slug}
                </span>{" "}
                · created {formatDateTime(p.createdAt)}
              </>
            }
          />
          <Card className="p-4 sm:p-6">
            <h3 className="mb-3 text-lg text-fg">Runs</h3>
            <RunsTable orgSlug={orgSlug} projectSlug={p.slug} />
          </Card>
        </div>
      )}
    </QueryState>
  );
}
