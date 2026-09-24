// SPDX-License-Identifier: Apache-2.0
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In development the Vite server proxies the API, so the browser sees one
// origin (http://localhost:5173) and cookies stay first-party. Set
// KILN_PUBLIC_URL=http://localhost:5173 on the server to match.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": { target: "http://localhost:8080", changeOrigin: false },
      "/healthz": "http://localhost:8080",
      "/readyz": "http://localhost:8080",
    },
  },
  build: {
    target: "es2022",
    sourcemap: true,
    // No inline scripts: the strict CSP (script-src 'self') would block them.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
  },
});
