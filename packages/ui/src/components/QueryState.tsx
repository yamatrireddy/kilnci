// SPDX-License-Identifier: Apache-2.0
import { Center, Loader, Stack, Text, ThemeIcon, Title } from "@mantine/core";
import { IconInbox } from "@tabler/icons-react";
import type { ReactNode } from "react";

import { ErrorAlert } from "./ErrorAlert";

export interface QueryLike<T> {
  isPending: boolean;
  isError: boolean;
  error: unknown;
  data: T | undefined;
}

/**
 * Renders the loading, error, and empty states of a query, and the children
 * only when data is present (coding-standards §11: every async UI shows all
 * three states).
 */
export function QueryState<T>({
  query,
  isEmpty,
  empty,
  label,
  children,
}: {
  query: QueryLike<T>;
  isEmpty?: (data: T) => boolean;
  empty?: ReactNode;
  label: string;
  children: (data: T) => ReactNode;
}) {
  if (query.isPending) {
    return (
      <Center py="xl">
        <Loader aria-label={`Loading ${label}`} role="status" />
      </Center>
    );
  }
  if (query.isError || query.data === undefined) {
    return <ErrorAlert error={query.error} title={`Could not load ${label}`} />;
  }
  if (isEmpty?.(query.data)) {
    return <>{empty ?? <EmptyState title={`No ${label} yet`} />}</>;
  }
  return <>{children(query.data)}</>;
}

export function EmptyState({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return (
    <Center py="xl">
      <Stack align="center" gap="xs" maw={420}>
        <ThemeIcon size="xl" variant="light" radius="xl" aria-hidden>
          <IconInbox />
        </ThemeIcon>
        <Title order={3} size="h4" ta="center">
          {title}
        </Title>
        {description ? (
          <Text c="dimmed" ta="center" size="sm">
            {description}
          </Text>
        ) : null}
        {action}
      </Stack>
    </Center>
  );
}
