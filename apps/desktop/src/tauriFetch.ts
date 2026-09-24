// SPDX-License-Identifier: Apache-2.0
//
// A `fetch` that sends API calls over Tauri IPC to the Rust `api_request`
// command. The webview never holds a credential and never talks to the
// network directly (its CSP only allows `connect-src ipc:`); Rust attaches the
// access token and only forwards /api/v1/* paths to the configured server.
import { invoke } from "@tauri-apps/api/core";

interface ApiResponse {
  status: number;
  body: string;
  contentType: string | null;
}

/** Placeholder base URL for the API client; only the path is used. */
export const IPC_BASE_URL = "http://kiln.ipc";

export async function tauriFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const req = new Request(input, init);
  const url = new URL(req.url);
  const hasBody = req.method !== "GET" && req.method !== "HEAD";
  const body = hasBody ? await req.text() : "";
  const res = await invoke<ApiResponse>("api_request", {
    request: {
      method: req.method,
      path: url.pathname + url.search,
      body: hasBody && body !== "" ? body : null,
      contentType: req.headers.get("Content-Type"),
    },
  });
  // Response rejects bodies for these statuses.
  const nullBody = res.status === 204 || res.status === 205 || res.status === 304;
  return new Response(nullBody ? null : res.body, {
    status: res.status,
    headers: res.contentType ? { "Content-Type": res.contentType } : {},
  });
}
