// SPDX-License-Identifier: Apache-2.0
import { ApiError } from "@kiln/api-client";
import { Anchor, Center, Loader, Stack, Text, Title } from "@mantine/core";
import { Link, Navigate, useLocation, type RouteObject } from "react-router";

import { AppLayout } from "./components/AppLayout";
import { ErrorAlert } from "./components/ErrorAlert";
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
      <Center mih="100vh">
        <Loader aria-label="Loading your session" role="status" />
      </Center>
    );
  }
  if (session.error instanceof ApiError && session.error.status === 401) {
    const returnTo = location.pathname + location.search;
    return <Navigate to={`/signin?returnTo=${encodeURIComponent(returnTo)}`} replace />;
  }
  if (session.isError) {
    return (
      <Center mih="100vh" p="md">
        <ErrorAlert error={session.error} title="Could not reach Kiln" />
      </Center>
    );
  }
  return <AppLayout session={session.data} />;
}

export function NotFoundPage() {
  return (
    <Center py="xl">
      <Stack align="center" gap="xs">
        <Title order={2}>Page not found</Title>
        <Text c="dimmed">This page does not exist, or you do not have access to it.</Text>
        <Anchor component={Link} to="/orgs">
          Go to your organizations
        </Anchor>
      </Stack>
    </Center>
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
