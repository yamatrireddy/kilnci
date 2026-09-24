// SPDX-License-Identifier: Apache-2.0
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Tauri serves the built files from its own asset protocol; the dev server
// is only used by `pnpm tauri dev`.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: {
    target: "es2022",
    sourcemap: false,
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
  },
});
