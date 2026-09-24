// SPDX-License-Identifier: Apache-2.0
//
// The Kiln Mantine theme. Its CSS variables are compiled to theme-vars.css by
// scripts/build-theme-css.ts (ADR-0002) so the app needs no runtime <style>
// injection and runs under a strict `style-src 'self'` CSP. After editing this
// file run `pnpm --filter @kiln/ui generate`; a test fails if you forget.
import { createTheme, type MantineColorsTuple } from "@mantine/core";

// Warm "kiln" orange; index 6 is the primary shade (4.6:1 on white for text
// on filled buttons, see the contrast test).
const kiln: MantineColorsTuple = [
  "#fff4e6",
  "#ffe6cc",
  "#fdc998",
  "#fbaa61",
  "#fa8f34",
  "#f97e17",
  "#c2410c",
  "#a8380a",
  "#8f2f08",
  "#752705",
];

export const kilnTheme = createTheme({
  primaryColor: "kiln",
  primaryShade: 6,
  colors: { kiln },
  defaultRadius: "md",
  fontFamily:
    'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif',
  fontFamilyMonospace: 'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
  headings: { fontWeight: "650" },
  focusRing: "auto",
  cursorType: "pointer",
});
