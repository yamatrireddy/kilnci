// SPDX-License-Identifier: Apache-2.0
//
// @kiln/ui: the shared UI for Kiln's web and desktop apps, styled with
// Tailwind CSS (ADR-0004). Import the stylesheet once from the host app:
// `import "@kiln/ui/styles.css"`.

export { KilnProvider, createQueryClient, type KilnProviderProps } from "./KilnProvider";
export { usePlatform, type Platform } from "./platform";
export { kilnRoutes, NotFoundPage } from "./routes";
export { ErrorAlert, errorMessage } from "./components/ErrorAlert";
export { EmptyState, QueryState } from "./components/QueryState";
// UI primitives, for host-app screens that render outside the router (e.g.
// the desktop first-run setup).
export * from "./components/ui";
export * from "./queries";
