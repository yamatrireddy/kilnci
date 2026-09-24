// SPDX-License-Identifier: Apache-2.0
//
// The desktop app: the shared @kiln/ui screens inside Tauri. Credentials live
// only in Rust (memory + OS keychain); see src-tauri/src/lib.rs.
import "@kiln/ui/styles.css";

import { createKilnClient } from "@kiln/api-client";
import { queryKeys } from "@kiln/core";
import { createQueryClient, KilnProvider, kilnRoutes, type Platform } from "@kiln/ui";
import { MantineProvider } from "@mantine/core";
import { invoke } from "@tauri-apps/api/core";
import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { createHashRouter, RouterProvider } from "react-router";

import { ServerSetup } from "./ServerSetup";
import { IPC_BASE_URL, tauriFetch } from "./tauriFetch";

const queryClient = createQueryClient();
// Tauri serves a single document, so client routes live in the URL hash.
const router = createHashRouter(kilnRoutes);

const client = createKilnClient({
  baseUrl: IPC_BASE_URL,
  // Rust attaches the token; the webview has none to give.
  auth: { kind: "bearer", getAccessToken: () => Promise.resolve(null) },
  fetch: tauriFetch,
  onUnauthenticated: () => {
    void queryClient.invalidateQueries({ queryKey: queryKeys.session() });
  },
});

const platform: Platform = {
  name: "Kiln",
  client,
  signIn: async (returnTo) => {
    await invoke("sign_in");
    queryClient.clear();
    await router.navigate(returnTo);
  },
  afterSignOut: async () => {
    await invoke("sign_out");
    await router.navigate("/signin");
  },
};

function App() {
  const [server, setServer] = useState<string | null | undefined>(undefined);
  useEffect(() => {
    invoke<string | null>("get_server_url")
      .then(setServer)
      .catch(() => {
        setServer(null);
      });
  }, []);

  if (server === undefined) return null;
  if (server === null) {
    return (
      <MantineProvider withCssVariables={false} withGlobalClasses={false} defaultColorScheme="auto">
        <ServerSetup
          onSave={async (url) => {
            setServer(await invoke<string>("set_server_url", { url }));
          }}
        />
      </MantineProvider>
    );
  }
  return (
    <KilnProvider platform={platform} queryClient={queryClient}>
      <RouterProvider router={router} />
    </KilnProvider>
  );
}

const root = document.getElementById("root");
if (!root) throw new Error("missing #root element");
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
