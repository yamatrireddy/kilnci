// SPDX-License-Identifier: Apache-2.0
import { ApiError, type APIToken, type Permission } from "@kiln/api-client";
import { formatDateTime, formatRelative } from "@kiln/core";
import { IconCheck, IconCopy, IconKey, IconTrash } from "@tabler/icons-react";
import { useEffect, useState, type SyntheticEvent } from "react";

import { ConfirmModal } from "../components/ConfirmModal";
import { ErrorAlert } from "../components/ErrorAlert";
import { EmptyState, QueryState } from "../components/QueryState";
import {
  Alert,
  Button,
  Checkbox,
  CheckboxGroup,
  Code,
  IconButton,
  Modal,
  PageHeader,
  Table,
  Td,
  TextField,
  Th,
  Tooltip,
  useDisclosure,
  useNotify,
} from "../components/ui";
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
  const notify = useNotify();
  const [createOpened, create] = useDisclosure(false);
  const [toRevoke, setToRevoke] = useState<APIToken | null>(null);

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="API tokens"
        subtitle={
          <p className="max-w-prose">
            Personal tokens for scripts and the CLI. They act as you, limited to the permissions you choose, and are
            read-only for now. Treat them like passwords.
          </p>
        }
        actions={
          <Button leftSection={<IconKey size={16} aria-hidden />} onClick={create.open}>
            New token
          </Button>
        }
      />
      <QueryState
        query={tokens}
        label="API tokens"
        isEmpty={(d) => d.items.length === 0}
        empty={<EmptyState title="No API tokens" description="Use New token to create one." />}
      >
        {(data) => (
          <Table>
            <thead>
              <tr>
                <Th>Name</Th>
                <Th>Token</Th>
                <Th>Permissions</Th>
                <Th>Last used</Th>
                <Th>Expires</Th>
                <Th className="w-12">
                  <span className="sr-only">Actions</span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((t) => (
                <tr key={t.id}>
                  <Td className="whitespace-nowrap font-medium">{t.name}</Td>
                  <Td className="whitespace-nowrap">
                    <Code>{t.prefix}…</Code>
                  </Td>
                  <Td className="min-w-48 text-xs">{t.scopes.join(", ")}</Td>
                  <Td className="whitespace-nowrap text-dimmed">
                    {t.lastUsedAt ? formatRelative(t.lastUsedAt) : "Never"}
                  </Td>
                  <Td className="whitespace-nowrap">{formatDateTime(t.expiresAt)}</Td>
                  <Td className="text-right">
                    <Tooltip label="Revoke token" describe={false}>
                      <IconButton
                        variant="subtle-danger"
                        aria-label={`Revoke ${t.name}`}
                        onClick={() => {
                          setToRevoke(t);
                        }}
                      >
                        <IconTrash size={16} aria-hidden />
                      </IconButton>
                    </Tooltip>
                  </Td>
                </tr>
              ))}
            </tbody>
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
              notify({ color: "green", message: `Revoked ${toRevoke.name}` });
              setToRevoke(null);
            },
          });
        }}
      >
        Revoke {toRevoke?.name}? Anything using it stops working immediately.
      </ConfirmModal>
    </div>
  );
}

const MIN_DAYS = 1;
const MAX_DAYS = 365;

function CreateTokenModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const create = useCreateToken();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<Permission[]>(["orgs:list", "orgs:read", "projects:list", "projects:read"]);
  const [daysText, setDaysText] = useState("30");
  const [secret, setSecret] = useState<string | null>(null);
  const fieldErrors = create.error instanceof ApiError ? create.error.fieldErrors() : {};
  const days = Number(daysText);
  const daysValid = Number.isInteger(days) && days >= MIN_DAYS && days <= MAX_DAYS;

  // Leaving the page with the secret on screen skips close(); drop the
  // mutation result (which holds the token) from the cache then too.
  const { reset } = create;
  useEffect(() => reset, [reset]);

  const close = () => {
    // Drop the secret from memory as soon as the dialog closes.
    setSecret(null);
    setName("");
    create.reset();
    onClose();
  };
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    if (!daysValid) return;
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
    <Modal opened={opened} onClose={close} title={secret ? "Copy your new token" : "New API token"} size="lg">
      {secret ? (
        <div className="flex flex-col gap-4">
          <Alert tone="yellow">This is the only time the token is shown. Store it in a password manager or secret store.</Alert>
          <div className="flex items-start gap-2">
            <div
              role="textbox"
              aria-readonly="true"
              aria-label="New API token"
              tabIndex={0}
              className="min-w-0 flex-1 whitespace-pre-wrap break-all rounded-md border border-line bg-subtle px-3 py-2 font-mono text-sm text-fg"
            >
              {secret}
            </div>
            <CopyButton value={secret} />
          </div>
          <div className="flex justify-end">
            <Button onClick={close}>Done</Button>
          </div>
        </div>
      ) : (
        <form onSubmit={submit} noValidate>
          <div className="flex flex-col gap-4">
            {create.error && !(create.error instanceof ApiError && create.error.status === 422) ? (
              <ErrorAlert error={create.error} title="Could not create token" />
            ) : null}
            <TextField
              label="Name"
              description="What will use this token? For example, “CI deploy script”."
              required
              maxLength={100}
              autoComplete="off"
              value={name}
              onChange={(e) => {
                setName(e.currentTarget.value);
              }}
              error={fieldErrors.name}
              data-autofocus
            />
            <CheckboxGroup legend="Permissions" error={fieldErrors.scopes}>
              {SCOPES.map((s) => (
                <Checkbox
                  key={s.value}
                  value={s.value}
                  checked={scopes.includes(s.value)}
                  onChange={(e) => {
                    const on = e.currentTarget.checked;
                    setScopes((cur) => (on ? [...cur, s.value] : cur.filter((v) => v !== s.value)));
                  }}
                  label={
                    <>
                      {s.label} <span className="font-mono text-xs text-dimmed">({s.value})</span>
                    </>
                  }
                />
              ))}
            </CheckboxGroup>
            <TextField
              label="Expires in (days)"
              type="number"
              inputMode="numeric"
              min={MIN_DAYS}
              max={MAX_DAYS}
              step={1}
              className="sm:max-w-40"
              value={daysText}
              onChange={(e) => {
                setDaysText(e.currentTarget.value);
              }}
              error={daysValid ? fieldErrors.expiresInDays : `Enter a whole number from ${String(MIN_DAYS)} to ${String(MAX_DAYS)}`}
            />
            <div className="mt-2 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <Button variant="default" onClick={close}>
                Cancel
              </Button>
              <Button type="submit" loading={create.isPending} disabled={!name.trim() || scopes.length === 0 || !daysValid}>
                Create token
              </Button>
            </div>
          </div>
        </form>
      )}
    </Modal>
  );
}

function CopyButton({ value }: { value: string }) {
  const notify = useNotify();
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => {
      setCopied(false);
    }, 2000);
    return () => {
      clearTimeout(t);
    };
  }, [copied]);

  return (
    <Tooltip label={copied ? "Copied" : "Copy"} describe={false}>
      <IconButton
        variant="light"
        aria-label={copied ? "Token copied" : "Copy token"}
        onClick={() => {
          // The token is shown only once, so a failed copy must be visible.
          // Wrapped in a promise: navigator.clipboard is undefined outside
          // secure contexts, which would otherwise throw synchronously.
          Promise.resolve()
            .then(() => navigator.clipboard.writeText(value))
            .then(
            () => {
              setCopied(true);
            },
            () => {
              notify({ color: "red", title: "Copy failed", message: "Select the token and copy it manually." });
            },
          );
        }}
      >
        {copied ? <IconCheck size={16} aria-hidden /> : <IconCopy size={16} aria-hidden />}
      </IconButton>
    </Tooltip>
  );
}
