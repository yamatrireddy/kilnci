// SPDX-License-Identifier: Apache-2.0
import { formatDateTime } from "@kiln/core";
import { IconPlus } from "@tabler/icons-react";
import { useNavigate } from "react-router";

import { EmptyState, QueryState } from "../components/QueryState";
import { RoleBadge } from "../components/RoleBadge";
import { SlugNameForm } from "../components/SlugNameForm";
import { Button, Modal, PageHeader, Table, Td, TextLink, Th, useDisclosure, useNotify } from "../components/ui";
import { useCreateOrg, useOrgs, useSession } from "../queries";

export function OrgsPage() {
  const orgs = useOrgs();
  const session = useSession();
  const [opened, { open, close }] = useDisclosure(false);
  const create = useCreateOrg();
  const navigate = useNavigate();
  const notify = useNotify();
  // Only instance admins may create orgs. Hiding the button is a courtesy;
  // the server enforces it.
  const canCreate = session.data?.instanceAdmin === true;

  const closeModal = () => {
    create.reset();
    close();
  };

  const createButton = canCreate ? (
    <Button leftSection={<IconPlus size={16} aria-hidden />} onClick={open}>
      New organization
    </Button>
  ) : null;

  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Organizations" actions={createButton} />
      <QueryState
        query={orgs}
        label="organizations"
        isEmpty={(d) => d.items.length === 0}
        empty={
          <EmptyState
            title="You are not in any organization yet"
            description={
              canCreate ? "Use New organization to create one." : "Ask an admin to invite you to an organization."
            }
          />
        }
      >
        {(data) => (
          <Table highlightOnHover>
            <thead>
              <tr>
                <Th>Name</Th>
                <Th>Slug</Th>
                <Th>Your role</Th>
                <Th>Created</Th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((o) => (
                <tr key={o.id}>
                  <Td>
                    <TextLink to={`/orgs/${o.slug}`} className="font-medium">
                      {o.name}
                    </TextLink>
                  </Td>
                  <Td className="whitespace-nowrap font-mono">{o.slug}</Td>
                  <Td>
                    <RoleBadge role={o.role} />
                  </Td>
                  <Td className="whitespace-nowrap text-dimmed">{formatDateTime(o.createdAt)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </QueryState>

      <Modal opened={opened} onClose={closeModal} title="New organization">
        <SlugNameForm
          submitLabel="Create organization"
          pending={create.isPending}
          error={create.error}
          onCancel={closeModal}
          onSubmit={(v) => {
            create.mutate(v, {
              onSuccess: (org) => {
                closeModal();
                notify({ color: "green", message: `Created ${org.name}` });
                void navigate(`/orgs/${org.slug}`);
              },
            });
          }}
        />
      </Modal>
    </div>
  );
}
