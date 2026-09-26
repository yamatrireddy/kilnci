// SPDX-License-Identifier: Apache-2.0
import { ApiError, type Job, type KilnClient, type LogStreamEvent, type Org, type Run, type RunDetail, type Session } from "@kiln/api-client";
import { render } from "@testing-library/react";
import axe from "axe-core";
import { createMemoryRouter, RouterProvider } from "react-router";
import { vi } from "vitest";

import { createQueryClient, KilnProvider } from "../KilnProvider";
import type { Platform } from "../platform";
import { kilnRoutes } from "../routes";

export const session: Session = {
  user: { id: "01ARZ3NDEKTSV4RRFFQ69G5FA1", email: "ada@example.com", displayName: "Ada Lovelace" },
  instanceAdmin: true,
  authMethod: "session",
  csrfToken: "fake-csrf",
};

export const acme: Org = { id: "01ARZ3NDEKTSV4RRFFQ69G5FA2", slug: "acme", name: "Acme", role: "owner", createdAt: "2026-01-01T00:00:00Z" };

export const run1: Run = {
  id: "01ARZ3NDEKTSV4RRFFQ69G5FB1",
  number: 42,
  status: "running",
  event: "pull_request",
  ref: "refs/pull/7/head",
  branch: "feature/<b>bold</b>",
  commitSha: "0123456789abcdef0123456789abcdef01234567",
  title: "Fix the <script>alert(1)</script> bug",
  prNumber: 7,
  isFork: true,
  trusted: false,
  actorLogin: "octocat",
  createdAt: "2026-01-01T00:00:00Z",
  startedAt: "2026-01-01T00:00:05Z",
  finishedAt: null,
};

function job(id: string, name: string, status: Job["status"]): Job {
  return {
    id, name, status, needs: [], image: "golang:1.27", labels: [], steps: [{ name: "test" }], attempt: 1, maxAttempts: 2,
    timeoutSeconds: 3600, failureReason: "", exitCode: null, queuedAt: null, startedAt: "2026-01-01T00:00:05Z", finishedAt: null,
  };
}

export const runDetail: RunDetail = {
  run: run1,
  jobs: [job("01ARZ3NDEKTSV4RRFFQ69G5FC1", "lint", "succeeded"), job("01ARZ3NDEKTSV4RRFFQ69G5FC2", "build", "running"), job("01ARZ3NDEKTSV4RRFFQ69G5FC3", "deploy", "pending")],
};

const enc = new TextEncoder();

/** A log stream event carrying `text` as chunk `seq` of `attempt`. */
export function chunk(attempt: number, seq: number, text: string): LogStreamEvent {
  return { type: "chunk", id: `${String(attempt)}.${String(seq)}`, attempt, seq, data: enc.encode(text) };
}

/** A fake streamJobLog that yields `events`, then ends the stream. */
export function streamOf(...events: LogStreamEvent[]) {
  return async function* () {
    await Promise.resolve();
    for (const ev of events) yield ev;
  };
}

export function problem(status: number): ApiError {
  return new ApiError(status, { type: "urn:kiln:problem:x", title: "x", status, requestId: "req-123" });
}

/** A fake API client; override any method per test. */
export function fakeClient(overrides: Partial<Record<keyof KilnClient, unknown>> = {}) {
  const base = {
    raw: {},
    getSession: vi.fn(() => Promise.resolve(session)),
    signOut: vi.fn(() => Promise.resolve()),
    exchangeToken: vi.fn(),
    listOrgs: vi.fn(() => Promise.resolve({ items: [acme] })),
    createOrg: vi.fn((b: { slug: string; name: string }) => Promise.resolve({ ...acme, ...b, id: "01ARZ3NDEKTSV4RRFFQ69G5FA9" })),
    getOrg: vi.fn(() => Promise.resolve(acme)),
    listMembers: vi.fn(() =>
      Promise.resolve({
        items: [
          { userId: session.user.id, email: session.user.email, displayName: session.user.displayName, role: "owner" },
          { userId: "01ARZ3NDEKTSV4RRFFQ69G5FA3", email: "bob@example.com", displayName: "Bob", role: "developer" },
        ],
      }),
    ),
    addMember: vi.fn(),
    updateMember: vi.fn(() => Promise.resolve({})),
    removeMember: vi.fn(() => Promise.resolve()),
    listProjects: vi.fn(() => Promise.resolve({ items: [{ id: "01ARZ3NDEKTSV4RRFFQ69G5FA4", slug: "web", name: "Web", createdAt: "2026-01-01T00:00:00Z" }] })),
    createProject: vi.fn(),
    getProject: vi.fn(() => Promise.resolve({ id: "01ARZ3NDEKTSV4RRFFQ69G5FA4", slug: "web", name: "Web", createdAt: "2026-01-01T00:00:00Z" })),
    listAuditEvents: vi.fn(() =>
      Promise.resolve({
        items: [
          {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FA5", occurredAt: "2026-01-01T00:00:00Z", actorKind: "user", actorId: session.user.id,
            action: "members:add", targetType: "membership", targetId: "x", result: "success", requestId: "r", sourceIp: "203.0.113.1",
          },
        ],
      }),
    ),
    listRuns: vi.fn(() => Promise.resolve({ items: [run1], nextCursor: null })),
    getRun: vi.fn(() => Promise.resolve(runDetail)),
    cancelRun: vi.fn(() => Promise.resolve({ ...runDetail, run: { ...run1, status: "canceled" } })),
    approveRun: vi.fn(() => Promise.resolve({ ...runDetail, run: { ...run1, status: "queued" } })),
    getJobLog: vi.fn(() => Promise.resolve("\x1b[32mok\x1b[0m stored\n")),
    streamJobLog: vi.fn(
      streamOf({ type: "attempt", attempt: 1 }, chunk(1, 0, "\x1b[1;31mFAIL\x1b[0m live\n"), { type: "end", status: "failed" }),
    ),
    listTokens: vi.fn(() => Promise.resolve({ items: [] })),
    createToken: vi.fn(() =>
      Promise.resolve({
        token: "kiln_pat_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK",
        apiToken: { id: "01ARZ3NDEKTSV4RRFFQ69G5FA6", name: "ci", prefix: "kiln_pat_FAKE", scopes: ["orgs:list"], createdAt: "2026-01-01T00:00:00Z", expiresAt: "2026-02-01T00:00:00Z" },
      }),
    ),
    revokeToken: vi.fn(() => Promise.resolve()),
  };
  // Plain mock functions (not KilnClient methods), so tests can assert on them.
  return { ...base, ...overrides } as typeof base;
}

export type FakeClient = ReturnType<typeof fakeClient>;

export function renderApp(path: string, client: FakeClient = fakeClient(), platform?: Partial<Platform>) {
  const router = createMemoryRouter(kilnRoutes, { initialEntries: [path] });
  const signIn = vi.fn();
  const utils = render(
    <KilnProvider platform={{ name: "Kiln", client: client as unknown as KilnClient, signIn, ...platform }} queryClient={createQueryClient({ retry: false })}>
      <RouterProvider router={router} />
    </KilnProvider>,
  );
  return { ...utils, router, client, signIn };
}

/** Runs axe on the document. Color contrast needs real layout, which jsdom lacks. */
export async function axeViolations(): Promise<string[]> {
  const res = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
  return res.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(" ")).join(", ")})`);
}
