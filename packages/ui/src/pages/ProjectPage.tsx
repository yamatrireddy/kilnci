// SPDX-License-Identifier: Apache-2.0
import { formatDateTime } from "@kiln/core";
import { Anchor, Breadcrumbs, Paper, Stack, Text, Title } from "@mantine/core";
import { Link, useParams } from "react-router";

import { EmptyState, QueryState } from "../components/QueryState";
import { useProject } from "../queries";

export function ProjectPage() {
  const { orgSlug = "", projectSlug = "" } = useParams();
  const project = useProject(orgSlug, projectSlug);
  return (
    <QueryState query={project} label="project">
      {(p) => (
        <Stack>
          <Breadcrumbs>
            <Anchor component={Link} to="/orgs">
              Organizations
            </Anchor>
            <Anchor component={Link} to={`/orgs/${orgSlug}`}>
              {orgSlug}
            </Anchor>
            <Text>{p.name}</Text>
          </Breadcrumbs>
          <div>
            <Title order={2}>{p.name}</Title>
            <Text c="dimmed" size="sm">
              <Text span ff="monospace">
                {orgSlug}/{p.slug}
              </Text>{" "}
              · created {formatDateTime(p.createdAt)}
            </Text>
          </div>
          <Paper withBorder p="lg" radius="md">
            <EmptyState
              title="No pipelines yet"
              description="Pipelines and runs arrive in Phase 1. Add a .kiln/pipeline.yaml to your repository to get ready."
            />
          </Paper>
        </Stack>
      )}
    </QueryState>
  );
}
