// SPDX-License-Identifier: Apache-2.0
import { formatDateTime } from "@kiln/core";
import { Anchor, Button, Group, Modal, Stack, Table, Text, Title } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconPlus } from "@tabler/icons-react";
import { Link, useNavigate } from "react-router";

import { EmptyState, QueryState } from "../components/QueryState";
import { RoleBadge } from "../components/RoleBadge";
import { SlugNameForm } from "../components/SlugNameForm";
import { useCreateOrg, useOrgs, useSession } from "../queries";

export function OrgsPage() {
  const orgs = useOrgs();
  const session = useSession();
  const [opened, { open, close }] = useDisclosure(false);
  const create = useCreateOrg();
  const navigate = useNavigate();
  // Only instance admins may create orgs. Hiding the button is a courtesy;
  // the server enforces it.
  const canCreate = session.data?.instanceAdmin === true;

  const createButton = canCreate ? (
    <Button leftSection={<IconPlus size={16} aria-hidden />} onClick={open}>
      New organization
    </Button>
  ) : null;

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>Organizations</Title>
        {createButton}
      </Group>
      <QueryState
        query={orgs}
        label="organizations"
        isEmpty={(d) => d.items.length === 0}
        empty={
          <EmptyState
            title="You are not in any organization yet"
            description={canCreate ? "Create one to get started." : "Ask an admin to invite you to an organization."}
            action={createButton}
          />
        }
      >
        {(data) => (
          <Table highlightOnHover verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th scope="col">Name</Table.Th>
                <Table.Th scope="col">Slug</Table.Th>
                <Table.Th scope="col">Your role</Table.Th>
                <Table.Th scope="col">Created</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {data.items.map((o) => (
                <Table.Tr key={o.id}>
                  <Table.Td>
                    <Anchor component={Link} to={`/orgs/${o.slug}`} fw={500}>
                      {o.name}
                    </Anchor>
                  </Table.Td>
                  <Table.Td>
                    <Text ff="monospace" size="sm">
                      {o.slug}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <RoleBadge role={o.role} />
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      {formatDateTime(o.createdAt)}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </QueryState>

      <Modal opened={opened} onClose={close} title="New organization" centered>
        <SlugNameForm
          submitLabel="Create organization"
          pending={create.isPending}
          error={create.error}
          onCancel={close}
          onSubmit={(v) => {
            create.mutate(v, {
              onSuccess: (org) => {
                close();
                notifications.show({ color: "green", message: `Created ${org.name}` });
                void navigate(`/orgs/${org.slug}`);
              },
            });
          }}
        />
      </Modal>
    </Stack>
  );
}
