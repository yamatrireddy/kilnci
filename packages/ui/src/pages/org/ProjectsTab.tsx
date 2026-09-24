// SPDX-License-Identifier: Apache-2.0
import type { Org } from "@kiln/api-client";
import { formatRelative, roleAtLeast } from "@kiln/core";
import { Anchor, Button, Group, Modal, Stack, Table, Text } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconPlus } from "@tabler/icons-react";
import { Link } from "react-router";

import { EmptyState, QueryState } from "../../components/QueryState";
import { SlugNameForm } from "../../components/SlugNameForm";
import { useCreateProject, useProjects } from "../../queries";

export function ProjectsTab({ org }: { org: Org }) {
  const projects = useProjects(org.slug);
  const create = useCreateProject(org.slug);
  const [opened, { open, close }] = useDisclosure(false);
  const canCreate = roleAtLeast(org.role, "admin"); // UX hint; the server enforces.

  const button = canCreate ? (
    <Button leftSection={<IconPlus size={16} aria-hidden />} onClick={open}>
      New project
    </Button>
  ) : null;

  return (
    <Stack>
      {canCreate ? <Group justify="flex-end">{button}</Group> : null}
      <QueryState
        query={projects}
        label="projects"
        isEmpty={(d) => d.items.length === 0}
        empty={<EmptyState title="No projects yet" description="Projects group pipelines and runs." action={button} />}
      >
        {(data) => (
          <Table highlightOnHover verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th scope="col">Project</Table.Th>
                <Table.Th scope="col">Slug</Table.Th>
                <Table.Th scope="col">Created</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {data.items.map((p) => (
                <Table.Tr key={p.id}>
                  <Table.Td>
                    <Anchor component={Link} to={`/orgs/${org.slug}/projects/${p.slug}`} fw={500}>
                      {p.name}
                    </Anchor>
                  </Table.Td>
                  <Table.Td>
                    <Text ff="monospace" size="sm">
                      {p.slug}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      {formatRelative(p.createdAt)}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </QueryState>
      <Modal opened={opened} onClose={close} title="New project" centered>
        <SlugNameForm
          submitLabel="Create project"
          pending={create.isPending}
          error={create.error}
          onCancel={close}
          onSubmit={(v) => {
            create.mutate(v, {
              onSuccess: (p) => {
                close();
                create.reset();
                notifications.show({ color: "green", message: `Created ${p.name}` });
              },
            });
          }}
        />
      </Modal>
    </Stack>
  );
}
