// SPDX-License-Identifier: Apache-2.0
import type { KilnClient } from "@kiln/api-client";
import { createContext, useContext, type ReactNode } from "react";

/**
 * What a host app (web, desktop) provides to the shared UI. The UI never
 * decides how to authenticate or where tokens live; the platform does.
 */
export interface Platform {
  /** Name shown in the UI, e.g. "Kiln" or "Kiln Desktop". */
  name: string;
  client: KilnClient;
  /** Begins sign-in and eventually returns the user to `returnTo`. */
  signIn: (returnTo: string) => void | Promise<void>;
  /** Called after the server session or grant has been revoked. */
  afterSignOut?: () => void | Promise<void>;
}

const PlatformContext = createContext<Platform | null>(null);

export function PlatformProvider({ platform, children }: { platform: Platform; children: ReactNode }) {
  return <PlatformContext.Provider value={platform}>{children}</PlatformContext.Provider>;
}

export function usePlatform(): Platform {
  const p = useContext(PlatformContext);
  if (!p) throw new Error("usePlatform must be used inside <KilnProvider>");
  return p;
}
