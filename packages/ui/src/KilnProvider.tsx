// SPDX-License-Identifier: Apache-2.0
import { ApiError } from "@kiln/api-client";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";

import { PlatformProvider, type Platform } from "./platform";
import { kilnTheme } from "./theme";

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
  /** "test" disables transitions and portals (Mantine test mode). */
  env?: "default" | "test";
}

/**
 * Root provider for every Kiln client. Mantine runs with runtime style
 * injection disabled (ADR-0002): theme variables come from the static
 * theme-vars.css imported via "@kiln/ui/styles.css".
 */
export function KilnProvider({ platform, children, queryClient, env = "default" }: KilnProviderProps) {
  const [client] = useState(() => queryClient ?? createQueryClient());
  return (
    <MantineProvider
      theme={kilnTheme}
      withCssVariables={false}
      withGlobalClasses={false}
      defaultColorScheme="auto"
      env={env}
    >
      <Notifications position="top-right" />
      <QueryClientProvider client={client}>
        <PlatformProvider platform={platform}>{children}</PlatformProvider>
      </QueryClientProvider>
    </MantineProvider>
  );
}
