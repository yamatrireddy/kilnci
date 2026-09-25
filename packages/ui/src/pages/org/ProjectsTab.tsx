// SPDX-License-Identifier: Apache-2.0
import type { Org } from "@kiln/api-client";
import { formatRelative, roleAtLeast } from "@kiln/core";
import { IconPlus } from "@tabler/icons-react";

import { EmptyState, QueryState } from "../../components/QueryState";
import { SlugNameForm } from "../../components/SlugNameForm";
import { Button, Modal, Table, Td, TextLink, Th, useDisclosure, useNotify } from "../../components/ui";
import { useCreateProject, useProjects } from "../../queries";

export function ProjectsTab({ org }: { org: Org }) {
  const projects = useProjects(org.slug);
  const create = useCreateProject(org.slug);
  const [opened, { open, close }] = useDisclosure(false);
  const notify = useNotify();
  const canCreate = roleAtLeast(org.role, "admin"); // UX hint; the server enforces.

  const closeModal = () => {
    create.reset();
    close();
  };

  const button = canCreate ? (
    <Button leftSection={<IconPlus size={16} aria-hidden />} onClick={open}>
      New project
    </Button>
  ) : null;

  return (
    <div className="flex flex-col gap-4">
      {canCreate ? <div className="flex justify-end">{button}</div> : null}
      <QueryState
        query={projects}
        label="projects"
        isEmpty={(d) => d.items.length === 0}
        empty={<EmptyState title="No projects yet" description="Projects group pipelines and runs." />}
      >
        {(data) => (
          <Table highlightOnHover>
            <thead>
              <tr>
                <Th>Project</Th>
                <Th>Slug</Th>
                <Th>Created</Th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((p) => (
                <tr key={p.id}>
                  <Td>
                    <TextLink to={`/orgs/${org.slug}/projects/${p.slug}`} className="font-medium">
                      {p.name}
                    </TextLink>
                  </Td>
                  <Td className="whitespace-nowrap font-mono">{p.slug}</Td>
                  <Td className="whitespace-nowrap text-dimmed">{formatRelative(p.createdAt)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </QueryState>
      <Modal opened={opened} onClose={closeModal} title="New project">
        <SlugNameForm
          submitLabel="Create project"
          pending={create.isPending}
          error={create.error}
          onCancel={closeModal}
          onSubmit={(v) => {
            create.mutate(v, {
              onSuccess: (p) => {
                closeModal();
                notify({ color: "green", message: `Created ${p.name}` });
              },
            });
          }}
        />
      </Modal>
    </div>
  );
}
