// SPDX-License-Identifier: Apache-2.0
//
// @kiln/ui: the shared Mantine UI for Kiln's web and desktop apps. Import the
// stylesheet once from the host app: `import "@kiln/ui/styles.css"`.

export { KilnProvider, createQueryClient, type KilnProviderProps } from "./KilnProvider";
export { usePlatform, type Platform } from "./platform";
export { kilnRoutes, NotFoundPage } from "./routes";
export { kilnTheme } from "./theme";
export { ErrorAlert, errorMessage } from "./components/ErrorAlert";
export { EmptyState, QueryState } from "./components/QueryState";
export * from "./queries";
