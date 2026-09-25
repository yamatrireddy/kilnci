// SPDX-License-Identifier: Apache-2.0
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { slugify } from "./components/SlugNameForm";
import { acme, axeViolations, fakeClient, problem, renderApp, session } from "./test/harness";

// Every page, rendered with data: accessible and free of runtime <style> tags
// (ADR-0004: all styling is a static, build-time stylesheet).
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

// Every way out of the dialog must discard the one-time secret (security review L2/L3).
const closePaths: [string, (dialog: HTMLElement) => Promise<void>][] = [
  ["Done", (d) => userEvent.click(within(d).getByRole("button", { name: "Done" }))],
  ["the close button", (d) => userEvent.click(within(d).getByRole("button", { name: "Close" }))],
  [
    "Escape (cancel)",
    (d) => {
      fireEvent(d, new Event("cancel", { cancelable: true }));
      return Promise.resolve();
    },
  ],
  [
    "a backdrop click",
    (d) => {
      fireEvent.mouseDown(d);
      return Promise.resolve();
    },
  ],
  [
    "a native close",
    (d) => {
      fireEvent(d, new Event("close"));
      return Promise.resolve();
    },
  ],
];

describe.each(closePaths)("token dialog closed via %s", (_name, closeVia) => {
  it("removes the secret and reopens on a fresh form", async () => {
    renderApp("/settings/tokens");
    await userEvent.click((await screen.findAllByRole("button", { name: /New token/ }))[0] as HTMLElement);
    await userEvent.type(screen.getByLabelText(/^Name/), "ci");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    await screen.findByLabelText("New API token");
    await closeVia(screen.getByRole("dialog"));
    await waitFor(() => {
      expect(screen.queryByText(/kiln_pat_/)).toBeNull();
    });
    await userEvent.click(screen.getAllByRole("button", { name: /New token/ })[0] as HTMLElement);
    expect(screen.getByRole("dialog", { name: "New API token" })).toBeInTheDocument();
    expect(screen.queryByText(/kiln_pat_/)).toBeNull();
  });
});

describe("token copy", () => {
  const stubClipboard = (writeText: (text: string) => Promise<void>) => {
    const mock = vi.fn(writeText);
    Object.defineProperty(navigator, "clipboard", { value: { writeText: mock }, configurable: true });
    return mock;
  };

  it("tells the user when copying fails and keeps the token on screen", async () => {
    renderApp("/settings/tokens");
    await userEvent.click((await screen.findAllByRole("button", { name: /New token/ }))[0] as HTMLElement);
    await userEvent.type(screen.getByLabelText(/^Name/), "ci");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    await screen.findByLabelText("New API token");
    // Fail like a denied permission or an unfocused document.
    stubClipboard(() => Promise.reject(new DOMException("denied", "NotAllowedError")));
    await userEvent.click(screen.getByRole("button", { name: "Copy token" }));
    expect(await screen.findByText(/copy it manually/)).toBeInTheDocument();
    expect(screen.getByLabelText("New API token")).toHaveTextContent("kiln_pat_FAKE");
  });

  it("confirms a successful copy", async () => {
    renderApp("/settings/tokens");
    await userEvent.click((await screen.findAllByRole("button", { name: /New token/ }))[0] as HTMLElement);
    await userEvent.type(screen.getByLabelText(/^Name/), "ci");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    await screen.findByLabelText("New API token");
    const writeText = stubClipboard(() => Promise.resolve());
    await userEvent.click(screen.getByRole("button", { name: "Copy token" }));
    expect(await screen.findByRole("button", { name: "Token copied" })).toBeInTheDocument();
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining("kiln_pat_FAKE"));
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

describe("primitives", () => {
  it("moves between org tabs with the arrow keys and keeps the URL in sync", async () => {
    const { router } = renderApp("/orgs/acme");
    const projects = await screen.findByRole("tab", { name: "Projects" });
    expect(projects).toHaveAttribute("aria-selected", "true");
    projects.focus();
    await userEvent.keyboard("{ArrowRight}");
    const members = screen.getByRole("tab", { name: "Members" });
    expect(members).toHaveAttribute("aria-selected", "true");
    expect(members).toHaveFocus();
    expect(router.state.location.search).toBe("?tab=members");
    expect(await screen.findByRole("tabpanel")).toHaveTextContent("bob@example.com");
    await userEvent.keyboard("{End}");
    expect(screen.getByRole("tab", { name: "Audit log" })).toHaveFocus();
  });

  it("falls back to the projects tab when a developer opens the audit tab link", async () => {
    renderApp("/orgs/acme?tab=audit", fakeClient({ getOrg: () => Promise.resolve({ ...acme, role: "developer" }) }));
    expect(await screen.findByRole("tab", { name: "Projects" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByText("Web")).toBeInTheDocument();
  });

  it("opens the account menu, moves with arrows, and closes on Escape", async () => {
    renderApp("/orgs");
    const trigger = await screen.findByRole("button", { name: /Account menu/ });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    await userEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    const items = within(screen.getByRole("menu")).getAllByRole("menuitem");
    expect(items.map((i) => i.textContent)).toEqual(["API tokens", "Sign out"]);
    expect(items[0]).toHaveFocus();
    await userEvent.keyboard("{ArrowDown}");
    expect(items[1]).toHaveFocus();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).toBeNull();
    expect(trigger).toHaveFocus();
  });

  it("signs out from the account menu", async () => {
    const afterSignOut = vi.fn();
    const { client } = renderApp("/orgs", fakeClient(), { afterSignOut });
    await userEvent.click(await screen.findByRole("button", { name: /Account menu/ }));
    await userEvent.click(screen.getByRole("menuitem", { name: "Sign out" }));
    await waitFor(() => {
      expect(client.signOut).toHaveBeenCalled();
    });
    expect(afterSignOut).toHaveBeenCalled();
  });

  it("toggles the mobile navigation", async () => {
    renderApp("/orgs");
    const burger = await screen.findByRole("button", { name: "Toggle navigation" });
    expect(burger).toHaveAttribute("aria-expanded", "false");
    await userEvent.click(burger);
    expect(burger).toHaveAttribute("aria-expanded", "true");
    await userEvent.keyboard("{Escape}");
    expect(burger).toHaveAttribute("aria-expanded", "false");
    expect(burger).toHaveFocus();
  });

  it("marks the current page in the navigation", async () => {
    renderApp("/orgs/acme");
    const nav = await screen.findByRole("navigation", { name: "Main navigation" });
    await within(nav).findByRole("link", { name: /Acme/ });
    expect(within(nav).getByRole("link", { name: /Acme/ })).toHaveAttribute("aria-current", "page");
    expect(within(nav).getByRole("link", { name: "Organizations" })).not.toHaveAttribute("aria-current");
  });

  it("closes a modal with its close button, returning focus to the opener", async () => {
    renderApp("/orgs");
    const opener = await screen.findByRole("button", { name: /New organization/ });
    await userEvent.click(opener);
    const dialog = screen.getByRole("dialog", { name: "New organization" });
    expect(within(dialog).getByLabelText(/^Name/)).toHaveFocus();
    await userEvent.click(within(dialog).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(opener).toHaveFocus();
  });

  it("describes a role badge with a tooltip shown on focus", async () => {
    renderApp("/orgs");
    const table = await screen.findByRole("table");
    const badge = within(table).getByText("Owner");
    const tooltip = document.getElementById(badge.getAttribute("aria-describedby") ?? "");
    expect(tooltip).toHaveTextContent(/manage owners/);
    expect(tooltip).toHaveClass("invisible");
    act(() => {
      badge.focus();
    });
    expect(tooltip).toHaveClass("visible");
    await userEvent.keyboard("{Escape}");
    expect(tooltip).toHaveClass("invisible");
  });

  it("validates the token lifetime before submitting", async () => {
    const { client } = renderApp("/settings/tokens");
    await userEvent.click((await screen.findAllByRole("button", { name: /New token/ }))[0] as HTMLElement);
    await userEvent.type(screen.getByLabelText(/^Name/), "ci");
    const days = screen.getByLabelText(/Expires in/);
    await userEvent.clear(days);
    await userEvent.type(days, "400");
    expect(screen.getByText(/whole number from 1 to 365/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create token" })).toBeDisabled();
    await userEvent.clear(days);
    await userEvent.type(days, "90");
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    await waitFor(() => {
      expect(client.createToken).toHaveBeenCalledWith(expect.objectContaining({ expiresInDays: 90 }));
    });
  });

  it("shows a success notification that can be dismissed", async () => {
    renderApp("/orgs/acme?tab=members");
    const row = (await screen.findByText("bob@example.com")).closest("tr");
    if (!row) throw new Error("row");
    await userEvent.selectOptions(within(row).getByRole("combobox", { name: "Role for Bob" }), "admin");
    const region = screen.getByRole("region", { name: "Notifications" });
    expect(await within(region).findByText("Bob is now Admin")).toBeInTheDocument();
    await userEvent.click(within(region).getByRole("button", { name: "Dismiss notification" }));
    expect(within(region).queryByText("Bob is now Admin")).toBeNull();
  });
});
