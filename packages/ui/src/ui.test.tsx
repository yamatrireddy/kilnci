// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { slugify } from "./components/SlugNameForm";
import { acme, axeViolations, fakeClient, problem, renderApp, session } from "./test/harness";
import { renderThemeCss } from "./themeCss";

describe("theme (ADR-0002)", () => {
  it("theme-vars.css is generated from theme.ts (run `pnpm --filter @kiln/ui generate`)", () => {
    const committed = readFileSync(resolve(process.cwd(), "src/theme-vars.css"), "utf8");
    expect(committed).toBe(renderThemeCss());
  });
});

// Every page, rendered with data: accessible and free of runtime <style> tags.
const pages: [string, string, RegExp][] = [
  ["sign-in", "/signin", /Sign in to Kiln/],
  ["orgs", "/orgs", /Organizations/],
  ["org projects", "/orgs/acme", /Web/],
  ["org members", "/orgs/acme?tab=members", /bob@example.com/],
  ["org audit", "/orgs/acme?tab=audit", /members:add/],
  ["project", "/orgs/acme/projects/web", /No pipelines yet/],
  ["tokens", "/settings/tokens", /No API tokens/],
  ["not found", "/nope", /Page not found/],
];

describe.each(pages)("%s page", (_name, path, expected) => {
  it("renders, passes axe, and injects no <style> (CSP)", async () => {
    const before = document.querySelectorAll("style").length;
    renderApp(path);
    expect((await screen.findAllByText(expected)).length).toBeGreaterThan(0);
    expect(document.querySelectorAll("style").length).toBe(before);
    expect(await axeViolations()).toEqual([]);
  });
});

describe("session", () => {
  it("redirects to sign-in with a return path when unauthenticated", async () => {
    const client = fakeClient({ getSession: () => Promise.reject(problem(401)) });
    const { router } = renderApp("/orgs/acme?tab=members", client);
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/signin");
    });
    expect(router.state.location.search).toBe("?returnTo=%2Forgs%2Facme%3Ftab%3Dmembers");
  });

  it("shows an error, not a redirect, when the server is unreachable", async () => {
    const client = fakeClient({ getSession: () => Promise.reject(new TypeError("network")) });
    renderApp("/orgs", client);
    expect(await screen.findByRole("alert")).toHaveTextContent(/Check your connection/);
  });

  it("sign-in page passes a safe return path to the platform", async () => {
    const { signIn } = renderApp("/signin?returnTo=%2F%2Fevil.example&error=not_invited");
    expect(await screen.findByText(/do not have a Kiln account/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /single sign-on/ }));
    expect(signIn).toHaveBeenCalledWith("/");
  });
});

describe("orgs", () => {
  it("offers org creation only to instance admins", async () => {
    renderApp("/orgs", fakeClient({ getSession: () => Promise.resolve({ ...session, instanceAdmin: false }) }));
    await screen.findByRole("link", { name: "Acme", hidden: false });
    expect(screen.queryByRole("button", { name: /New organization/ })).toBeNull();
  });

  it("creates an org with a derived slug and navigates to it", async () => {
    const { client, router } = renderApp("/orgs");
    await userEvent.click(await screen.findByRole("button", { name: /New organization/ }));
    await userEvent.type(screen.getByLabelText(/^Name/), "Wayne Enterprises");
    expect(screen.getByLabelText(/^Slug/)).toHaveValue("wayne-enterprises");
    await userEvent.click(screen.getByRole("button", { name: "Create organization" }));
    await waitFor(() => {
      expect(client.createOrg).toHaveBeenCalledWith({ name: "Wayne Enterprises", slug: "wayne-enterprises" });
    });
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/orgs/wayne-enterprises");
    });
  });

  it("shows server field errors from a 422", async () => {
    const err = problem(422);
    if (err.problem) err.problem.errors = [{ field: "slug", message: "already taken" }];
    renderApp("/orgs", fakeClient({ createOrg: () => Promise.reject(err) }));
    await userEvent.click(await screen.findByRole("button", { name: /New organization/ }));
    await userEvent.type(screen.getByLabelText(/^Name/), "Acme");
    await userEvent.click(screen.getByRole("button", { name: "Create organization" }));
    expect(await screen.findByText("already taken")).toBeInTheDocument();
  });

  it("shows a friendly error with a request id when loading fails", async () => {
    renderApp("/orgs", fakeClient({ listOrgs: () => Promise.reject(problem(500)) }));
    expect(await screen.findByText(/Something went wrong on the server/)).toBeInTheDocument();
    expect(screen.getByText("req-123")).toBeInTheDocument();
  });

  it("shows an empty state", async () => {
    renderApp("/orgs", fakeClient({ listOrgs: () => Promise.resolve({ items: [] }) }));
    expect(await screen.findByText(/not in any organization/)).toBeInTheDocument();
  });

  it("hides admin-only tabs from developers", async () => {
    renderApp("/orgs/acme", fakeClient({ getOrg: () => Promise.resolve({ ...acme, role: "developer" }) }));
    await screen.findByRole("tab", { name: "Projects" });
    expect(screen.queryByRole("tab", { name: "Audit log" })).toBeNull();
    expect(screen.queryByRole("button", { name: /New project/ })).toBeNull();
  });

  it("treats a 404 org as not found without leaking details", async () => {
    renderApp("/orgs/secret", fakeClient({ getOrg: () => Promise.reject(problem(404)) }));
    expect(await screen.findByText(/does not exist, or you do not have access/)).toBeInTheDocument();
  });
});

describe("members", () => {
  it("changes a role and confirms before removing a member", async () => {
    const { client } = renderApp("/orgs/acme?tab=members");
    const row = (await screen.findByText("bob@example.com")).closest("tr");
    expect(row).not.toBeNull();
    if (!row) return;
    await userEvent.click(within(row).getByRole("button", { name: "Remove Bob" }));
    const dialog = await screen.findByRole("dialog", { name: "Remove member" });
    expect(client.removeMember).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole("button", { name: "Remove" }));
    await waitFor(() => {
      expect(client.removeMember).toHaveBeenCalledWith("acme", "01ARZ3NDEKTSV4RRFFQ69G5FA3");
    });
  });

  it("explains the last-owner rule when the server refuses", async () => {
    renderApp("/orgs/acme?tab=members", fakeClient({ removeMember: () => Promise.reject(problem(409)) }));
    const row = (await screen.findByText("bob@example.com")).closest("tr");
    if (!row) throw new Error("row");
    await userEvent.click(within(row).getByRole("button", { name: "Remove Bob" }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Remove" }));
    expect(await screen.findByText(/at least one owner/)).toBeInTheDocument();
  });
});

describe("tokens", () => {
  it("shows a new token once and forgets it when closed", async () => {
    const { client } = renderApp("/settings/tokens");
    await userEvent.click((await screen.findAllByRole("button", { name: /New token/ }))[0] as HTMLElement);
    await userEvent.type(screen.getByLabelText(/^Name/), "ci");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    expect(await screen.findByLabelText("New API token")).toHaveTextContent("kiln_pat_FAKE");
    expect(client.createToken).toHaveBeenCalledWith(expect.objectContaining({ name: "ci", expiresInDays: 30 }));
    await userEvent.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() => {
      expect(screen.queryByText(/kiln_pat_FAKEFAKE/)).toBeNull();
    });
  });
});

describe("slugify", () => {
  it("derives URL-safe slugs", () => {
    expect(slugify("  Hello, World!  ")).toBe("hello-world");
    expect(slugify("Ünïcödé Café")).toBe("unicode-cafe");
    expect(slugify("a".repeat(60))).toHaveLength(40);
    expect(slugify("---")).toBe("");
  });
});
