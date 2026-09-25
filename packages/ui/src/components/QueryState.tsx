// SPDX-License-Identifier: Apache-2.0
import { IconInbox } from "@tabler/icons-react";
import type { ReactNode } from "react";

import { ErrorAlert } from "./ErrorAlert";
import { RoundIcon, Spinner } from "./ui";

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
      <div className="flex justify-center py-12">
        <Spinner label={`Loading ${label}`} />
      </div>
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
    <div className="flex justify-center px-4 py-12">
      <div className="flex max-w-[420px] flex-col items-center gap-2 text-center">
        <RoundIcon>
          <IconInbox size={24} />
        </RoundIcon>
        <h3 className="mt-1 text-lg text-fg">{title}</h3>
        {description ? <p className="text-sm text-dimmed">{description}</p> : null}
        {action ? <div className="mt-2">{action}</div> : null}
      </div>
    </div>
  );
}
