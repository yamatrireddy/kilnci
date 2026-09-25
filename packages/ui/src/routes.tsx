// SPDX-License-Identifier: Apache-2.0
import { ApiError } from "@kiln/api-client";
import { Navigate, useLocation, type RouteObject } from "react-router";

import { AppLayout } from "./components/AppLayout";
import { ErrorAlert } from "./components/ErrorAlert";
import { Spinner, TextLink } from "./components/ui";
import { OrgPage } from "./pages/OrgPage";
import { OrgsPage } from "./pages/OrgsPage";
import { ProjectPage } from "./pages/ProjectPage";
import { SignInPage } from "./pages/SignInPage";
import { TokensPage } from "./pages/TokensPage";
import { useSession } from "./queries";

/** Loads the session; unauthenticated users are sent to sign in. */
function RequireSession() {
  const session = useSession();
  const location = useLocation();
  if (session.isPending) {
    return (
      <div className="grid min-h-screen place-items-center">
        <Spinner label="Loading your session" />
      </div>
    );
  }
  if (session.error instanceof ApiError && session.error.status === 401) {
    const returnTo = location.pathname + location.search;
    return <Navigate to={`/signin?returnTo=${encodeURIComponent(returnTo)}`} replace />;
  }
  if (session.isError) {
    return (
      <main className="grid min-h-screen place-items-center p-4">
        <div className="w-full max-w-md">
          <ErrorAlert error={session.error} title="Could not reach Kiln" />
        </div>
      </main>
    );
  }
  return <AppLayout session={session.data} />;
}

export function NotFoundPage() {
  return (
    <div className="flex flex-col items-center gap-2 px-4 py-16 text-center">
      <h2 className="text-2xl text-fg">Page not found</h2>
      <p className="text-dimmed">This page does not exist, or you do not have access to it.</p>
      <TextLink to="/orgs" className="mt-2 font-medium">
        Go to your organizations
      </TextLink>
    </div>
  );
}

/** Route table shared by the web and desktop apps. */
export const kilnRoutes: RouteObject[] = [
  { path: "/signin", element: <SignInPage /> },
  {
    element: <RequireSession />,
    children: [
      { index: true, element: <Navigate to="/orgs" replace /> },
      { path: "/orgs", element: <OrgsPage /> },
      { path: "/orgs/:orgSlug", element: <OrgPage /> },
      { path: "/orgs/:orgSlug/projects/:projectSlug", element: <ProjectPage /> },
      { path: "/settings/tokens", element: <TokensPage /> },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
];
