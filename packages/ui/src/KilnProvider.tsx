// SPDX-License-Identifier: Apache-2.0
import { ApiError } from "@kiln/api-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";

import { ToastProvider } from "./components/ui";
import { PlatformProvider, type Platform } from "./platform";

/** Client errors (4xx) are final; network and 5xx errors are retried twice. */
function shouldRetry(failureCount: number, error: unknown): boolean {
  if (error instanceof ApiError && error.status < 500) return false;
  return failureCount < 2;
}

export function createQueryClient(opts: { retry?: boolean } = {}): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: opts.retry === false ? false : shouldRetry, staleTime: 15_000, refetchOnWindowFocus: true },
      mutations: { retry: false },
    },
  });
}

export interface KilnProviderProps {
  platform: Platform;
  children: ReactNode;
  queryClient?: QueryClient;
}

/**
 * Root provider for every Kiln client: server state, the platform adapter,
 * and notifications. Styling is a static stylesheet imported by the host app
 * via "@kiln/ui/styles.css"; nothing is injected at runtime (ADR-0004).
 */
export function KilnProvider({ platform, children, queryClient }: KilnProviderProps) {
  const [client] = useState(() => queryClient ?? createQueryClient());
  return (
    <QueryClientProvider client={client}>
      <PlatformProvider platform={platform}>
        <ToastProvider>{children}</ToastProvider>
      </PlatformProvider>
    </QueryClientProvider>
  );
}
