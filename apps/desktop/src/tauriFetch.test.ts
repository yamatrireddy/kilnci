// SPDX-License-Identifier: Apache-2.0
import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invoke(...args) as unknown }));

const { IPC_BASE_URL, tauriFetch } = await import("./tauriFetch");

describe("tauriFetch", () => {
  beforeEach(() => {
    invoke.mockReset();
  });

  it("sends only method, path, body, and content type over IPC", async () => {
    invoke.mockResolvedValue({ status: 201, body: '{"ok":true}', contentType: "application/json" });
    const res = await tauriFetch(`${IPC_BASE_URL}/api/v1/orgs?limit=5`, {
      method: "POST",
      body: '{"slug":"a","name":"A"}',
      headers: { "Content-Type": "application/json", Authorization: "Bearer should-not-be-forwarded" },
    });
    expect(invoke).toHaveBeenCalledWith("api_request", {
      request: { method: "POST", path: "/api/v1/orgs?limit=5", body: '{"slug":"a","name":"A"}', contentType: "application/json" },
    });
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("sends no body for GET and handles 204", async () => {
    invoke.mockResolvedValue({ status: 204, body: "", contentType: null });
    const res = await tauriFetch(new Request(`${IPC_BASE_URL}/api/v1/session`, { method: "DELETE" }));
    expect(res.status).toBe(204);
    invoke.mockResolvedValue({ status: 200, body: "{}", contentType: "application/json" });
    await tauriFetch(`${IPC_BASE_URL}/api/v1/orgs`);
    expect(invoke).toHaveBeenLastCalledWith("api_request", {
      request: { method: "GET", path: "/api/v1/orgs", body: null, contentType: null },
    });
  });

  it("propagates IPC rejections (e.g. a path Rust refused)", async () => {
    invoke.mockRejectedValue("this request is not allowed");
    await expect(tauriFetch(`${IPC_BASE_URL}/api/v1/auth/token`, { method: "POST", body: "{}" })).rejects.toBe(
      "this request is not allowed",
    );
  });
});
