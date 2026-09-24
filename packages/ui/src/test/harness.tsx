// SPDX-License-Identifier: Apache-2.0
import { ApiError, type KilnClient, type Org, type Session } from "@kiln/api-client";
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
    <KilnProvider platform={{ name: "Kiln", client: client as unknown as KilnClient, signIn, ...platform }} queryClient={createQueryClient({ retry: false })} env="test">
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
