// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  base64Url,
  createPkcePair,
  formatDateTime,
  formatRelative,
  pkceChallenge,
  queryKeys,
  randomToken,
  ROLES,
  roleAtLeast,
  roleDescription,
  roleLabel,
  safeReturnPath,
  signInErrorMessage,
} from "./index";

describe("roles", () => {
  it("orders roles and labels them", () => {
    expect(ROLES).toEqual(["viewer", "developer", "admin", "owner"]);
    expect(roleAtLeast("admin", "developer")).toBe(true);
    expect(roleAtLeast("developer", "admin")).toBe(false);
    expect(roleAtLeast("owner", "owner")).toBe(true);
    for (const r of ROLES) {
      expect(roleLabel(r)).toMatch(/^[A-Z]/);
      expect(roleDescription(r).length).toBeGreaterThan(5);
    }
  });
});

describe("queryKeys", () => {
  it("nests org resources under the org key", () => {
    const org = queryKeys.org("acme");
    expect(queryKeys.projects("acme").slice(0, org.length)).toEqual(org);
    expect(queryKeys.project("acme", "web").slice(0, org.length)).toEqual(org);
    expect(queryKeys.members("acme").slice(0, 2)).toEqual(org);
    expect(queryKeys.auditEvents("acme").slice(0, 2)).toEqual(org);
    expect(queryKeys.session()).toEqual(["session"]);
    expect(queryKeys.orgs()).toEqual(["orgs"]);
    expect(queryKeys.tokens()).toEqual(["tokens"]);
  });
});

describe("format", () => {
  const now = new Date("2026-01-01T12:00:00Z");
  it("formats relative times", () => {
    expect(formatRelative("2026-01-01T11:57:00Z", now, "en")).toBe("3 minutes ago");
    expect(formatRelative("2026-01-03T12:00:00Z", now, "en")).toBe("in 2 days");
    expect(formatRelative("2026-01-01T12:00:00Z", now, "en")).toBe("now");
    expect(formatRelative("not a date", now)).toBe("");
  });
  it("formats absolute times", () => {
    expect(formatDateTime("2026-01-01T12:00:00Z", "en")).toMatch(/2026/);
    expect(formatDateTime("nope")).toBe("");
  });
});

describe("sign-in", () => {
  it("maps server error codes to messages", () => {
    expect(signInErrorMessage(null)).toBeNull();
    expect(signInErrorMessage("")).toBeNull();
    expect(signInErrorMessage("not_invited")).toMatch(/invite/);
    expect(signInErrorMessage("failed")).toMatch(/try again/);
    expect(signInErrorMessage("<script>")).toMatch(/try again/);
  });

  it("only returns to same-origin paths", () => {
    expect(safeReturnPath("/orgs/acme?tab=members")).toBe("/orgs/acme?tab=members");
    for (const bad of [null, undefined, "", "//evil.example", "https://evil.example", "/\\evil", "javascript:alert(1)", "/a\nb", "/signin?error=x"]) {
      expect(safeReturnPath(bad)).toBe("/");
    }
    expect(safeReturnPath("/" + "a".repeat(600))).toBe("/");
  });
});

describe("pkce", () => {
  it("matches the RFC 7636 test vector", async () => {
    expect(await pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });
  it("creates random, well-formed pairs", async () => {
    const a = await createPkcePair();
    const b = await createPkcePair();
    expect(a.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.verifier).not.toBe(b.verifier);
    expect(randomToken()).not.toBe(randomToken());
    expect(base64Url(new Uint8Array([251, 255]))).toBe("-_8");
  });
});
