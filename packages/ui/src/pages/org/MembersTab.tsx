// SPDX-License-Identifier: Apache-2.0
import { ApiError, type Member, type Org, type Role } from "@kiln/api-client";
import { ROLES, roleAtLeast, roleLabel } from "@kiln/core";
import { IconTrash, IconUserPlus } from "@tabler/icons-react";
import { useState, type SyntheticEvent } from "react";

import { ConfirmModal } from "../../components/ConfirmModal";
import { ErrorAlert, errorMessage } from "../../components/ErrorAlert";
import { QueryState } from "../../components/QueryState";
import { RoleBadge } from "../../components/RoleBadge";
import {
  Button,
  IconButton,
  Modal,
  SelectField,
  Table,
  Td,
  TextField,
  Th,
  Tooltip,
  useDisclosure,
  useNotify,
} from "../../components/ui";
import { useAddMember, useMembers, useRemoveMember, useSession, useUpdateMember } from "../../queries";

const roleOptions = (allowOwner: boolean) =>
  ROLES.filter((r) => allowOwner || r !== "owner").map((r) => ({ value: r, label: roleLabel(r) }));

function isRole(v: string): v is Role {
  return (ROLES as readonly string[]).includes(v);
}

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
  const notify = useNotify();
  const [inviteOpened, invite] = useDisclosure(false);
  const [toRemove, setToRemove] = useState<Member | null>(null);
  // UX hints only; the server enforces every rule.
  const canManage = roleAtLeast(org.role, "admin");
  const isOwner = org.role === "owner";

  return (
    <div className="flex flex-col gap-4">
      {canManage ? (
        <div className="flex justify-end">
          <Button leftSection={<IconUserPlus size={16} aria-hidden />} onClick={invite.open}>
            Add member
          </Button>
        </div>
      ) : null}
      <QueryState query={members} label="members" isEmpty={(d) => d.items.length === 0}>
        {(data) => (
          <Table>
            <thead>
              <tr>
                <Th>Name</Th>
                <Th>Email</Th>
                <Th>Role</Th>
                {canManage ? (
                  <Th className="w-12">
                    <span className="sr-only">Actions</span>
                  </Th>
                ) : null}
              </tr>
            </thead>
            <tbody>
              {data.items.map((m) => {
                const editable = canManage && (isOwner || m.role !== "owner");
                const isSelf = m.userId === session.data?.user.id;
                return (
                  <tr key={m.userId}>
                    <Td className="whitespace-nowrap font-medium">
                      {m.displayName}
                      {isSelf ? <span className="font-normal text-dimmed"> (you)</span> : null}
                    </Td>
                    <Td className="whitespace-nowrap">{m.email}</Td>
                    <Td>
                      {editable ? (
                        <SelectField
                          aria-label={`Role for ${m.displayName}`}
                          options={roleOptions(isOwner)}
                          value={m.role}
                          className="w-40"
                          disabled={update.isPending}
                          onChange={(e) => {
                            const v = e.currentTarget.value;
                            if (!isRole(v) || v === m.role) return;
                            update.mutate(
                              { userId: m.userId, role: v },
                              {
                                onSuccess: () => {
                                  notify({ color: "green", message: `${m.displayName} is now ${roleLabel(v)}` });
                                },
                                onError: (err) => {
                                  notify({ color: "red", title: "Role not changed", message: mutationMessage(err) });
                                },
                              },
                            );
                          }}
                        />
                      ) : (
                        <RoleBadge role={m.role} />
                      )}
                    </Td>
                    {canManage ? (
                      <Td className="text-right">
                        {editable ? (
                          <Tooltip label="Remove from organization" describe={false}>
                            <IconButton
                              variant="subtle-danger"
                              aria-label={`Remove ${m.displayName}`}
                              onClick={() => {
                                setToRemove(m);
                              }}
                            >
                              <IconTrash size={16} aria-hidden />
                            </IconButton>
                          </Tooltip>
                        ) : null}
                      </Td>
                    ) : null}
                  </tr>
                );
              })}
            </tbody>
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
              notify({ color: "green", message: `Removed ${toRemove.displayName}` });
              setToRemove(null);
            },
            onError: (e) => {
              notify({ color: "red", title: "Not removed", message: mutationMessage(e) });
              setToRemove(null);
            },
          });
        }}
      >
        Remove {toRemove?.displayName} ({toRemove?.email}) from {org.name}? They lose access immediately.
      </ConfirmModal>
    </div>
  );
}

function InviteModal({ org, opened, onClose, allowOwner }: { org: Org; opened: boolean; onClose: () => void; allowOwner: boolean }) {
  const add = useAddMember(org.slug);
  const notify = useNotify();
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
          notify({ color: "green", message: `Added ${m.email}. They can sign in with that address.` });
          close();
        },
      },
    );
  };

  return (
    <Modal opened={opened} onClose={close} title="Add member">
      <form onSubmit={submit} noValidate>
        <div className="flex flex-col gap-4">
          {add.error && !(add.error instanceof ApiError && add.error.status === 422) ? (
            <ErrorAlert error={add.error} title="Could not add member" />
          ) : null}
          <TextField
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
          <SelectField
            label="Role"
            options={roleOptions(allowOwner)}
            value={role}
            onChange={(e) => {
              const v = e.currentTarget.value;
              if (isRole(v)) setRole(v);
            }}
          />
          <p className="text-xs text-dimmed">
            People who have not signed in to Kiln yet are invited; they join when they first sign in with this email.
          </p>
          <div className="mt-2 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button variant="default" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" loading={add.isPending} disabled={!email.includes("@")}>
              Add member
            </Button>
          </div>
        </div>
      </form>
    </Modal>
  );
}
