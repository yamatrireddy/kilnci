// SPDX-License-Identifier: Apache-2.0
//
// The web app: a thin shell around @kiln/ui. It authenticates with the
// server's HttpOnly session cookie (the app never sees the session secret)
// and signs in by navigating the browser to the server's OIDC login.
import "@kiln/ui/styles.css";

import { createKilnClient } from "@kiln/api-client";
import { queryKeys } from "@kiln/core";
import { createQueryClient, KilnProvider, kilnRoutes, type Platform } from "@kiln/ui";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router";

const queryClient = createQueryClient();
const router = createBrowserRouter(kilnRoutes);

const client = createKilnClient({
  baseUrl: "",
  auth: { kind: "session" },
  // A 401 anywhere means the session ended: re-check it, and the session
  // guard sends the user to sign in.
  onUnauthenticated: () => {
    void queryClient.invalidateQueries({ queryKey: queryKeys.session() });
  },
});

const platform: Platform = {
  name: "Kiln",
  client,
  signIn: (returnTo) => {
    const q = new URLSearchParams({ client: "web", returnTo });
    window.location.assign(`/api/v1/auth/login?${q.toString()}`);
  },
  afterSignOut: async () => {
    await router.navigate("/signin");
  },
};

const root = document.getElementById("root");
if (!root) throw new Error("missing #root element");

createRoot(root).render(
  <StrictMode>
    <KilnProvider platform={platform} queryClient={queryClient}>
      <RouterProvider router={router} />
    </KilnProvider>
  </StrictMode>,
);
