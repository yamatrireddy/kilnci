// SPDX-License-Identifier: Apache-2.0
import { ApiError, type Member, type Org, type Role } from "@kiln/api-client";
import { ROLES, roleAtLeast, roleLabel } from "@kiln/core";
import { ActionIcon, Button, Group, Modal, Select, Stack, Table, Text, TextInput, Tooltip } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconTrash, IconUserPlus } from "@tabler/icons-react";
import { useState, type SyntheticEvent } from "react";

import { ConfirmModal } from "../../components/ConfirmModal";
import { ErrorAlert, errorMessage } from "../../components/ErrorAlert";
import { QueryState } from "../../components/QueryState";
import { RoleBadge } from "../../components/RoleBadge";
import { useAddMember, useMembers, useRemoveMember, useSession, useUpdateMember } from "../../queries";

const roleOptions = (allowOwner: boolean) =>
  ROLES.filter((r) => allowOwner || r !== "owner").map((r) => ({ value: r, label: roleLabel(r) }));

function mutationMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 409) {
    return "An organization must keep at least one owner.";
  }
  if (error instanceof ApiError && error.status === 403) {
    return "Only owners can grant, change, or remove the owner role.";
  }
  return errorMessage(error);
}

export function MembersTab({ org }: { org: Org }) {
  const members = useMembers(org.slug);
  const session = useSession();
  const update = useUpdateMember(org.slug);
  const remove = useRemoveMember(org.slug);
  const [inviteOpened, invite] = useDisclosure(false);
  const [toRemove, setToRemove] = useState<Member | null>(null);
  // UX hints only; the server enforces every rule.
  const canManage = roleAtLeast(org.role, "admin");
  const isOwner = org.role === "owner";

  return (
    <Stack>
      {canManage ? (
        <Group justify="flex-end">
          <Button leftSection={<IconUserPlus size={16} aria-hidden />} onClick={invite.open}>
            Add member
          </Button>
        </Group>
      ) : null}
      <QueryState query={members} label="members" isEmpty={(d) => d.items.length === 0}>
        {(data) => (
          <Table verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th scope="col">Name</Table.Th>
                <Table.Th scope="col">Email</Table.Th>
                <Table.Th scope="col">Role</Table.Th>
                {canManage ? (
                  <Table.Th scope="col">
                    <span className="visually-hidden">Actions</span>
                  </Table.Th>
                ) : null}
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {data.items.map((m) => {
                const editable = canManage && (isOwner || m.role !== "owner");
                const isSelf = m.userId === session.data?.user.id;
                return (
                  <Table.Tr key={m.userId}>
                    <Table.Td>
                      <Text fw={500} size="sm">
                        {m.displayName}
                        {isSelf ? " (you)" : ""}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{m.email}</Text>
                    </Table.Td>
                    <Table.Td>
                      {editable ? (
                        <Select
                          aria-label={`Role for ${m.displayName}`}
                          data={roleOptions(isOwner)}
                          value={m.role}
                          allowDeselect={false}
                          w={150}
                          disabled={update.isPending}
                          onChange={(v) => {
                            if (!v || v === m.role) return;
                            update.mutate(
                              { userId: m.userId, role: v },
                              {
                                onSuccess: () => notifications.show({ color: "green", message: `${m.displayName} is now ${roleLabel(v)}` }),
                                onError: (e) => notifications.show({ color: "red", title: "Role not changed", message: mutationMessage(e) }),
                              },
                            );
                          }}
                        />
                      ) : (
                        <RoleBadge role={m.role} />
                      )}
                    </Table.Td>
                    {canManage ? (
                      <Table.Td>
                        {editable ? (
                          <Tooltip label="Remove from organization">
                            <ActionIcon
                              variant="subtle"
                              color="red"
                              aria-label={`Remove ${m.displayName}`}
                              onClick={() => {
                                setToRemove(m);
                              }}
                            >
                              <IconTrash size={16} aria-hidden />
                            </ActionIcon>
                          </Tooltip>
                        ) : null}
                      </Table.Td>
                    ) : null}
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        )}
      </QueryState>

      <InviteModal org={org} opened={inviteOpened} onClose={invite.close} allowOwner={isOwner} />

      <ConfirmModal
        opened={toRemove !== null}
        title="Remove member"
        confirmLabel="Remove"
        loading={remove.isPending}
        onClose={() => {
          setToRemove(null);
        }}
        onConfirm={() => {
          if (!toRemove) return;
          remove.mutate(toRemove.userId, {
            onSuccess: () => {
              notifications.show({ color: "green", message: `Removed ${toRemove.displayName}` });
              setToRemove(null);
            },
            onError: (e) => {
              notifications.show({ color: "red", title: "Not removed", message: mutationMessage(e) });
              setToRemove(null);
            },
          });
        }}
      >
        Remove {toRemove?.displayName} ({toRemove?.email}) from {org.name}? They lose access immediately.
      </ConfirmModal>
    </Stack>
  );
}

function InviteModal({ org, opened, onClose, allowOwner }: { org: Org; opened: boolean; onClose: () => void; allowOwner: boolean }) {
  const add = useAddMember(org.slug);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("developer");
  const fieldErrors = add.error instanceof ApiError ? add.error.fieldErrors() : {};

  const close = () => {
    setEmail("");
    add.reset();
    onClose();
  };
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    add.mutate(
      { email: email.trim(), role },
      {
        onSuccess: (m) => {
          notifications.show({ color: "green", message: `Added ${m.email}. They can sign in with that address.` });
          close();
        },
      },
    );
  };

  return (
    <Modal opened={opened} onClose={close} title="Add member" centered>
      <form onSubmit={submit} noValidate>
        <Stack>
          {add.error && !(add.error instanceof ApiError && add.error.status === 422) ? (
            <ErrorAlert error={add.error} title="Could not add member" />
          ) : null}
          <TextInput
            label="Email"
            type="email"
            required
            autoComplete="off"
            value={email}
            onChange={(e) => {
              setEmail(e.currentTarget.value);
            }}
            error={fieldErrors.email}
            data-autofocus
          />
          <Select
            label="Role"
            data={roleOptions(allowOwner)}
            value={role}
            allowDeselect={false}
            onChange={(v) => {
              if (v) setRole(v);
            }}
          />
          <Text size="xs" c="dimmed">
            People who have not signed in to Kiln yet are invited; they join when they first sign in with this email.
          </Text>
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" loading={add.isPending} disabled={!email.includes("@")}>
              Add member
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
