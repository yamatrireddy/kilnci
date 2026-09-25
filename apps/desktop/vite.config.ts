// SPDX-License-Identifier: Apache-2.0
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Tauri serves the built files from its own asset protocol; the dev server
// is only used by `pnpm tauri dev`.
export default defineConfig({
  // Tailwind compiles @kiln/ui/styles.css to a static stylesheet at build
  // time; nothing is injected at runtime (ADR-0004, strict CSP).
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: {
    target: "es2022",
    sourcemap: false,
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
  },
});
