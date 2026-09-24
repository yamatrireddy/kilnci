// SPDX-License-Identifier: Apache-2.0
//
// Renders the Kiln theme's Mantine CSS variables to src/theme-vars.css.
// MantineProvider runs with withCssVariables={false}, so this static file is
// the only source of theme variables and no <style> tag is injected at
// runtime (ADR-0002: strict CSP without 'unsafe-inline').
//
// Run: pnpm --filter @kiln/ui generate   (Node 22.18+/24 strips types natively)
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { renderThemeCss } from "../src/themeCss.ts";

const out = fileURLToPath(new URL("../src/theme-vars.css", import.meta.url));
writeFileSync(out, renderThemeCss());
console.log(`wrote ${out}`);
