// SPDX-License-Identifier: Apache-2.0
import { formatDateTime } from "@kiln/core";
import { useParams } from "react-router";

import { EmptyState, QueryState } from "../components/QueryState";
import { Breadcrumbs, Card, PageHeader } from "../components/ui";
import { useProject } from "../queries";

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
            <EmptyState
              title="No pipelines yet"
              description="Pipelines and runs arrive in Phase 1. Add a .kiln/pipeline.yaml to your repository to get ready."
            />
          </Card>
        </div>
      )}
    </QueryState>
  );
}
