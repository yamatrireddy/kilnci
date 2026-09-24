// SPDX-License-Identifier: Apache-2.0
import { ApiError, type APIToken, type Permission } from "@kiln/api-client";
import { formatDateTime, formatRelative } from "@kiln/core";
import {
  ActionIcon,
  Alert,
  Button,
  Checkbox,
  Code,
  CopyButton,
  Group,
  Modal,
  NumberInput,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconCheck, IconCopy, IconKey, IconTrash } from "@tabler/icons-react";
import { useState, type SyntheticEvent } from "react";

import { ConfirmModal } from "../components/ConfirmModal";
import { ErrorAlert } from "../components/ErrorAlert";
import { EmptyState, QueryState } from "../components/QueryState";
import { useCreateToken, useRevokeToken, useTokens } from "../queries";

const SCOPES: { value: Permission; label: string }[] = [
  { value: "orgs:list", label: "List organizations" },
  { value: "orgs:read", label: "Read organizations" },
  { value: "projects:list", label: "List projects" },
  { value: "projects:read", label: "Read projects" },
  { value: "members:list", label: "List members" },
  { value: "audit:read", label: "Read audit logs (admins)" },
  { value: "session:read", label: "Read your identity" },
];

export function TokensPage() {
  const tokens = useTokens();
  const revoke = useRevokeToken();
  const [createOpened, create] = useDisclosure(false);
  const [toRevoke, setToRevoke] = useState<APIToken | null>(null);

  const button = (
    <Button leftSection={<IconKey size={16} aria-hidden />} onClick={create.open}>
      New token
    </Button>
  );

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>API tokens</Title>
        {button}
      </Group>
      <Text c="dimmed" size="sm">
        Personal tokens for scripts and the CLI. They act as you, limited to the permissions you choose, and are
        read-only for now. Treat them like passwords.
      </Text>
      <QueryState
        query={tokens}
        label="API tokens"
        isEmpty={(d) => d.items.length === 0}
        empty={<EmptyState title="No API tokens" action={button} />}
      >
        {(data) => (
          <Table verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th scope="col">Name</Table.Th>
                <Table.Th scope="col">Token</Table.Th>
                <Table.Th scope="col">Permissions</Table.Th>
                <Table.Th scope="col">Last used</Table.Th>
                <Table.Th scope="col">Expires</Table.Th>
                <Table.Th scope="col">
                  <span className="visually-hidden">Actions</span>
                </Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {data.items.map((t) => (
                <Table.Tr key={t.id}>
                  <Table.Td fw={500}>{t.name}</Table.Td>
                  <Table.Td>
                    <Code>{t.prefix}…</Code>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs">{t.scopes.join(", ")}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      {t.lastUsedAt ? formatRelative(t.lastUsedAt) : "Never"}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{formatDateTime(t.expiresAt)}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Tooltip label="Revoke token">
                      <ActionIcon
                        color="red"
                        variant="subtle"
                        aria-label={`Revoke ${t.name}`}
                        onClick={() => {
                          setToRevoke(t);
                        }}
                      >
                        <IconTrash size={16} aria-hidden />
                      </ActionIcon>
                    </Tooltip>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </QueryState>

      <CreateTokenModal opened={createOpened} onClose={create.close} />

      <ConfirmModal
        opened={toRevoke !== null}
        title="Revoke token"
        confirmLabel="Revoke"
        loading={revoke.isPending}
        onClose={() => {
          setToRevoke(null);
        }}
        onConfirm={() => {
          if (!toRevoke) return;
          revoke.mutate(toRevoke.id, {
            onSuccess: () => {
              notifications.show({ color: "green", message: `Revoked ${toRevoke.name}` });
              setToRevoke(null);
            },
          });
        }}
      >
        Revoke {toRevoke?.name}? Anything using it stops working immediately.
      </ConfirmModal>
    </Stack>
  );
}

function CreateTokenModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const create = useCreateToken();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<Permission[]>(["orgs:list", "orgs:read", "projects:list", "projects:read"]);
  const [days, setDays] = useState<number>(30);
  const [secret, setSecret] = useState<string | null>(null);
  const fieldErrors = create.error instanceof ApiError ? create.error.fieldErrors() : {};

  const close = () => {
    // Drop the secret from memory as soon as the dialog closes.
    setSecret(null);
    setName("");
    create.reset();
    onClose();
  };
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    create.mutate(
      { name: name.trim(), scopes, expiresInDays: days },
      {
        onSuccess: (res) => {
          setSecret(res.token);
        },
      },
    );
  };

  return (
    <Modal opened={opened} onClose={close} title={secret ? "Copy your new token" : "New API token"} centered size="lg">
      {secret ? (
        <Stack>
          <Alert color="yellow" variant="light">
            This is the only time the token is shown. Store it in a password manager or secret store.
          </Alert>
          <Group gap="xs" wrap="nowrap">
            <Code block style={{ flex: 1, wordBreak: "break-all" }} aria-label="New API token">
              {secret}
            </Code>
            <CopyButton value={secret} timeout={2000}>
              {({ copied, copy }) => (
                <Tooltip label={copied ? "Copied" : "Copy"}>
                  <ActionIcon variant="light" onClick={copy} aria-label="Copy token">
                    {copied ? <IconCheck size={16} aria-hidden /> : <IconCopy size={16} aria-hidden />}
                  </ActionIcon>
                </Tooltip>
              )}
            </CopyButton>
          </Group>
          <Group justify="flex-end">
            <Button onClick={close}>Done</Button>
          </Group>
        </Stack>
      ) : (
        <form onSubmit={submit} noValidate>
          <Stack>
            {create.error && !(create.error instanceof ApiError && create.error.status === 422) ? (
              <ErrorAlert error={create.error} title="Could not create token" />
            ) : null}
            <TextInput
              label="Name"
              description="What will use this token? For example, “CI deploy script”."
              required
              maxLength={100}
              value={name}
              onChange={(e) => {
                setName(e.currentTarget.value);
              }}
              error={fieldErrors.name}
              data-autofocus
            />
            <Checkbox.Group
              label="Permissions"
              value={scopes}
              onChange={(v) => {
                setScopes(v);
              }}
              error={fieldErrors.scopes}
            >
              <Stack gap="xs" mt="xs">
                {SCOPES.map((s) => (
                  <Checkbox key={s.value} value={s.value} label={`${s.label} (${s.value})`} />
                ))}
              </Stack>
            </Checkbox.Group>
            <NumberInput
              label="Expires in (days)"
              min={1}
              max={365}
              value={days}
              onChange={(v) => {
                setDays(typeof v === "number" ? v : 30);
              }}
              error={fieldErrors.expiresInDays}
            />
            <Group justify="flex-end">
              <Button variant="default" onClick={close}>
                Cancel
              </Button>
              <Button type="submit" loading={create.isPending} disabled={!name.trim() || scopes.length === 0}>
                Create token
              </Button>
            </Group>
          </Stack>
        </form>
      )}
    </Modal>
  );
}
