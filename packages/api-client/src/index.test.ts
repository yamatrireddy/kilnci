// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";

import { ApiError, createKilnClient, pathParam } from "./index";

function jsonResponse(status: number, body: unknown, contentType = "application/json"): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": contentType },
  });
}

const session = {
  user: { id: "01ARZ3NDEKTSV4RRFFQ69G5FAV", email: "a@example.com", displayName: "A" },
  instanceAdmin: false,
  authMethod: "session",
  csrfToken: "fake-csrf-token",
};

function recorder(responses: Response[]) {
  const calls: Request[] = [];
  const fetch = vi.fn((input: Request) => {
    calls.push(input);
    const next = responses.shift();
    if (!next) throw new Error("unexpected request");
    return Promise.resolve(next);
  });
  return { calls, fetch: fetch as unknown as typeof globalThis.fetch };
}

describe("session auth", () => {
  it("sends the CSRF token from the session on unsafe requests only", async () => {
    const { calls, fetch } = recorder([
      jsonResponse(200, session),
      jsonResponse(200, { items: [] }),
      jsonResponse(201, { id: "01ARZ3NDEKTSV4RRFFQ69G5FAV", slug: "acme", name: "Acme", role: "owner", createdAt: "2026-01-01T00:00:00Z" }),
    ]);
    const c = createKilnClient({ baseUrl: "https://kiln.test", auth: { kind: "session" }, fetch });

    await c.getSession();
    await c.listOrgs();
    await c.createOrg({ slug: "acme", name: "Acme" });

    expect(calls[1]?.headers.get("X-CSRF-Token")).toBeNull();
    expect(calls[2]?.headers.get("X-CSRF-Token")).toBe("fake-csrf-token");
    expect(calls[2]?.credentials).toBe("same-origin");
    expect(calls.every((r) => r.headers.get("Authorization") === null)).toBe(true);
  });

  it("forgets the CSRF token after sign-out", async () => {
    const { calls, fetch } = recorder([jsonResponse(200, session), new Response(null, { status: 204 }), jsonResponse(201, {})]);
    const c = createKilnClient({ baseUrl: "https://kiln.test", auth: { kind: "session" }, fetch });
    await c.getSession();
    await c.signOut();
    await c.createOrg({ slug: "acme", name: "Acme" });
    expect(calls[2]?.headers.get("X-CSRF-Token")).toBeNull();
  });
});

describe("bearer auth", () => {
  it("attaches the current access token and never sends cookies", async () => {
    let token: string | null = "fake-access-1";
    const { calls, fetch } = recorder([jsonResponse(200, { items: [] }), jsonResponse(200, { items: [] })]);
    const c = createKilnClient({
      baseUrl: "https://kiln.test",
      auth: { kind: "bearer", getAccessToken: () => Promise.resolve(token) },
      fetch,
    });
    await c.listOrgs();
    token = null;
    await c.listOrgs();
    expect(calls[0]?.headers.get("Authorization")).toBe("Bearer fake-access-1");
    expect(calls[0]?.credentials).toBe("omit");
    expect(calls[1]?.headers.get("Authorization")).toBeNull();
  });
});

describe("errors", () => {
  it("throws ApiError with the problem and field errors", async () => {
    const problem = {
      type: "urn:kiln:problem:validation",
      title: "Request validation failed",
      status: 422,
      requestId: "r1",
      errors: [{ field: "slug", message: "bad" }],
    };
    const { fetch } = recorder([jsonResponse(422, problem, "application/problem+json")]);
    const c = createKilnClient({ baseUrl: "https://kiln.test", auth: { kind: "session" }, fetch });
    const err = await c.createOrg({ slug: "x", name: "X" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    const apiErr = err as ApiError;
    expect(apiErr.status).toBe(422);
    expect(apiErr.problem?.type).toBe("urn:kiln:problem:validation");
    expect(apiErr.fieldErrors()).toEqual({ slug: "bad" });
  });

  it("calls onUnauthenticated on 401", async () => {
    const onUnauthenticated = vi.fn();
    const { fetch } = recorder([
      jsonResponse(401, { type: "urn:kiln:problem:unauthenticated", title: "x", status: 401, requestId: "r" }, "application/problem+json"),
    ]);
    const c = createKilnClient({ baseUrl: "https://kiln.test", auth: { kind: "session" }, fetch, onUnauthenticated });
    await expect(c.getSession()).rejects.toBeInstanceOf(ApiError);
    expect(onUnauthenticated).toHaveBeenCalledOnce();
  });

  it("tolerates non-problem error bodies", async () => {
    const { fetch } = recorder([new Response("bad gateway", { status: 502, headers: { "Content-Type": "text/plain" } })]);
    const c = createKilnClient({ baseUrl: "https://kiln.test", auth: { kind: "session" }, fetch });
    const err = (await c.listOrgs().catch((e: unknown) => e)) as ApiError;
    expect(err.status).toBe(502);
    expect(err.problem).toBeUndefined();
    expect(err.fieldErrors()).toEqual({});
  });
});

describe("path parameters", () => {
  it("rejects dot segments and separators before any request is sent", async () => {
    const { calls, fetch } = recorder([]);
    const c = createKilnClient({ baseUrl: "https://kiln.test", auth: { kind: "session" }, fetch });
    for (const bad of ["", ".", "..", "a/b", "a\\b"]) {
      expect(() => pathParam(bad)).toThrow(ApiError);
    }
    await expect(c.getOrg("..")).rejects.toBeInstanceOf(ApiError);
    await expect(c.listProjects(".")).rejects.toBeInstanceOf(ApiError);
    expect(calls).toHaveLength(0);
    expect(pathParam("acme")).toBe("acme");
  });
});
