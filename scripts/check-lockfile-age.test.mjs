// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for the lockfile release-age gate. No network: the registry is
// replaced with an in-memory fake. Run with `node --test "scripts/*.test.mjs"`.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  LockfileError,
  MAX_NEW_ENTRIES,
  MIN_AGE_MS,
  checkEntries,
  diffEntries,
  escapeAnnotation,
  fetchRegistryInfo,
  packumentUrl,
  parseLockfilePackages,
} from "./check-lockfile-age.mjs";

const INTEGRITY = "sha512-" + "A".repeat(86) + "==";
const OTHER_INTEGRITY = "sha512-" + "B".repeat(86) + "==";
const NOW = Date.parse("2026-09-26T00:00:00Z");
const DAY = 86_400_000;

// A minimal lockfile in pnpm 10's v9 layout. `extraPackageLines` and
// `snapshots` let tests inject content.
function lockfile(keys, { snapshots, resolution = `{integrity: ${INTEGRITY}}` } = {}) {
  const pkgs = keys.map((k) => `  ${k}:\n    resolution: ${resolution}\n    engines: {node: '>=18'}\n`).join("\n");
  const snaps = snapshots ?? keys.map((k) => `  ${k}: {}\n`).join("\n");
  return (
    "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: false\n\nimporters:\n\n  .:\n    devDependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\n\n" +
    `packages:\n\n${pkgs}\nsnapshots:\n\n${snaps}`
  );
}
const BASIC = lockfile(["a@1.0.0", "'@scope/b@2.0.0-rc.1'"]);

test("parses plain and scoped keys with their integrity", () => {
  const m = parseLockfilePackages(BASIC);
  assert.deepEqual([...m.keys()], ["a@1.0.0", "@scope/b@2.0.0-rc.1"]);
  assert.deepEqual(m.get("@scope/b@2.0.0-rc.1"), { name: "@scope/b", version: "2.0.0-rc.1", integrity: INTEGRITY });
});

test("accepts CRLF line endings, peer-suffixed snapshots, and nested dependency maps", () => {
  const snapshots =
    "  a@1.0.0:\n    dependencies:\n      '@scope/b': 2.0.0-rc.1(a@1.0.0)\n    transitivePeerDependencies:\n      - supports-color\n\n" +
    "  '@scope/b@2.0.0-rc.1(a@1.0.0)':\n    optional: true\n";
  const text = lockfile(["a@1.0.0", "'@scope/b@2.0.0-rc.1'"], { snapshots }).replaceAll("\n", "\r\n");
  assert.equal(parseLockfilePackages(text).size, 2);
});

test("rejects malformed or evasive lockfiles", async (t) => {
  const resolutionB = `{integrity: ${OTHER_INTEGRITY}}`;
  const cases = {
    "wrong lockfile version": BASIC.replace("'9.0'", "'6.0'"),
    "flow-style packages": "lockfileVersion: '9.0'\npackages: {a@1.0.0: {}}\n",
    "double-quoted packages section": BASIC.replace("\npackages:", '\n"packages":'),
    "single-quoted packages section": BASIC.replace("\npackages:", "\n'packages':"),
    "explicit-key packages section": BASIC.replace("\npackages:", "\n? packages\n:"),
    "unknown top-level key": BASIC + "extra:\n  x: 1\n",
    "duplicate packages section": BASIC + "packages:\n  c@1.0.0:\n",
    "aliased top-level value": BASIC.replace("settings:", "settings: &s"),
    "duplicate key": lockfile(["a@1.0.0", "a@1.0.0"]),
    "git source": lockfile(["a@git+https://example.com/a.git"]),
    "tarball source": lockfile(["a@https://example.com/a.tgz"]),
    "invalid name": lockfile(["'a b@1.0.0'"]),
    "no version": lockfile(["a"]),
    "double-quoted key": lockfile(['"a@1.0.0"']),
    "complex key": lockfile(["? a@1.0.0"]),
    "comment": BASIC.replace("packages:\n", "packages:\n  # hidden\n"),
    "tab": BASIC.replace("    engines", "\tengines"),
    "lone CR hides a key": BASIC.replace("    engines: {node: '>=18'}\n", `    engines: {node: '>=18'}\r  evil@6.6.6:\r    resolution: ${resolutionB}\n`),
    "BOM": "\uFEFF" + BASIC,
    "unicode line separator": BASIC.replace("    engines", "\u2028    engines"),
    "odd indentation": BASIC.replace("    engines", "   engines"),
    "fields at indent 6": BASIC.replace("    engines", "      engines"),
    "anchor": BASIC.replace("engines: {", "engines: &x {"),
    "alias inside flow": BASIC.replace("{node: '>=18'}", "{node: *x}"),
    "merge key": BASIC.replace("    engines", "    <<: *x\n    engines"),
    "tag": BASIC.replace("engines: {", "engines: !!map {"),
    "block scalar": BASIC.replace("engines: {node: '>=18'}", "deprecated: |\n      text"),
    "second document": BASIC + "---\npackages:\n",
    "duplicate resolution": BASIC.replace("    engines", `    resolution: ${resolutionB}\n    engines`),
    "version override field": BASIC.replace("    engines", "    version: 9.9.9\n    engines"),
    "name override field": BASIC.replace("    engines", "    name: other\n    engines"),
    "unknown package field": BASIC.replace("    engines", "    tarball: https://evil.example/a.tgz\n    engines"),
    "missing resolution": BASIC.replace(`    resolution: {integrity: ${INTEGRITY}}\n    engines: {node: '>=18'}\n`, "    engines: {node: '>=18'}\n"),
    "non-registry resolution": lockfile(["a@1.0.0"], { resolution: "{tarball: https://evil.example/a.tgz}" }),
    "resolution in block form": BASIC.replace(`resolution: {integrity: ${INTEGRITY}}`, `resolution:\n      integrity: ${INTEGRITY}`),
    "snapshot without a package": lockfile(["a@1.0.0"], { snapshots: "  a@1.0.0: {}\n  evil@6.6.6:\n    optional: true\n" }),
    "snapshot carrying a resolution": lockfile(["a@1.0.0"], { snapshots: `  a@1.0.0:\n    resolution: ${resolutionB}\n` }),
    "snapshot carrying a version": lockfile(["a@1.0.0"], { snapshots: "  a@1.0.0:\n    version: 9.9.9\n" }),
    "snapshot with malformed peer suffix": lockfile(["a@1.0.0"], { snapshots: "  'a@1.0.0(b@1.0.0':\n    optional: true\n" }),
    "empty package entry": BASIC.replace(`  a@1.0.0:\n    resolution: {integrity: ${INTEGRITY}}\n    engines: {node: '>=18'}\n`, "  a@1.0.0: {}\n"),
    "multi-line flow value": BASIC.replace("{node: '>=18'}", "{node: '>=18',\n      npm: '>=9'}"),
    // Values left open across lines: js-yaml would swallow the next lines, so
    // `catalogs:` is not a section to pnpm and `bar@2.0.1` lands in snapshots.
    "single-quoted value spanning lines": BASIC + `  bar@2.0.0:\n    transitivePeerDependencies:\n      - 'x\ncatalogs:\n  q: y'\n  bar@2.0.1:\n    resolution: {integrity: ${OTHER_INTEGRITY}}\n`,
    "double-quoted value spanning lines": BASIC + `  a@1.0.0(x@1.0.0):\n    optional: "x\ncatalogs:\n  q: y"\n  bar@2.0.1:\n    resolution: {integrity: ${OTHER_INTEGRITY}}\n`,
    "flow sequence spanning lines": BASIC + `  a@1.0.0(x@1.0.0):\n    transitivePeerDependencies: [x,\ncatalogs:\n  y]\n  bar@2.0.1:\n    resolution: {integrity: ${OTHER_INTEGRITY}}\n`,
    "top-level flow opener": BASIC.replace("settings:\n  autoInstallPeers: false", "overrides: {a: 1,\n  b: 2}\nsettings:\n  autoInstallPeers: false"),
    "open quote in importers": BASIC.replace("specifier: 1.0.0", "specifier: '1.0.0"),
    "alias hidden between quote-like plain scalars": lockfile(["a@1.0.0"], { snapshots: "  a@1.0.0:\n    dependencies:\n      bar: [a'b, *z, c'd]\n" }),
    "double-quoted value": BASIC.replace("{node: '>=18'}", '{node: ">=18"}'),
    "trailing comment": BASIC.replace("autoInstallPeers: false", "autoInstallPeers: false # x"),
    "nested peer suffix junk": lockfile(["a@1.0.0"], { snapshots: "  'a@1.0.0(x)b@2.0.0(y)':\n    optional: true\n" }),
  };
  for (const [name, text] of Object.entries(cases)) {
    await t.test(name, () => assert.throws(() => parseLockfilePackages(text), LockfileError));
  }
});

test("only new name@version entries are checked", () => {
  const base = parseLockfilePackages(lockfile(["a@1.0.0", "b@1.0.0"]));
  const head = parseLockfilePackages(lockfile(["a@1.0.0", "b@1.1.0", "c@3.0.0"]));
  const { added, problems } = diffEntries(base, head);
  assert.deepEqual(added.map((e) => `${e.name}@${e.version}`), ["b@1.1.0", "c@3.0.0"]);
  assert.deepEqual(problems, []);
});

test("flags a changed integrity on an existing entry", () => {
  const base = parseLockfilePackages(lockfile(["a@1.0.0"]));
  const head = parseLockfilePackages(lockfile(["a@1.0.0"], { resolution: `{integrity: ${OTHER_INTEGRITY}}` }));
  const { added, problems } = diffEntries(base, head);
  assert.equal(added.length, 0);
  assert.match(problems[0], /integrity changed/);
});

test("checkEntries enforces age and integrity, and fails closed", async () => {
  const at = (ms) => ({ time: { "1.0.0": new Date(ms).toISOString() }, integrity: new Map([["1.0.0", INTEGRITY]]) });
  const info = {
    old: at(NOW - 30 * DAY),
    edge: at(NOW - MIN_AGE_MS),
    young: at(NOW - 2 * DAY),
    future: at(NOW + DAY),
    missing: { time: {}, integrity: new Map([["1.0.0", INTEGRITY]]) },
    mismatch: { ...at(NOW - 30 * DAY), integrity: new Map([["1.0.0", OTHER_INTEGRITY]]) },
    nohash: { ...at(NOW - 30 * DAY), integrity: new Map() },
    proto: { time: {}, integrity: new Map() },
  };
  const fetchInfo = async (name) => {
    if (name === "down") throw new Error("registry returned HTTP 503");
    return info[name];
  };
  const entries = ["old", "edge", "young", "future", "missing", "mismatch", "nohash", "down"].map((name) => ({
    name,
    version: "1.0.0",
    integrity: INTEGRITY,
  }));
  entries.push({ name: "proto", version: "constructor", integrity: INTEGRITY });
  const v = await checkEntries(entries, { now: NOW, fetchInfo });
  const about = (n) => v.filter((m) => m.startsWith(`${n}@`));
  assert.deepEqual(about("old"), []);
  assert.deepEqual(about("edge"), []);
  assert.match(about("young")[0], /2\.0 days ago/);
  assert.equal(about("future").length, 1);
  assert.match(about("missing")[0], /no publish time/);
  assert.match(about("mismatch")[0], /integrity does not match/);
  assert.match(about("nohash")[0], /no integrity hash/);
  assert.match(about("down")[0], /cannot verify/);
  assert.equal(about("proto").length, 2);
});

test("checkEntries refuses oversized changes without fetching", async () => {
  const entries = Array.from({ length: MAX_NEW_ENTRIES + 1 }, (_, i) => ({ name: `p${i}`, version: "1.0.0", integrity: INTEGRITY }));
  const v = await checkEntries(entries, {
    fetchInfo: async () => assert.fail("must not fetch"),
  });
  assert.match(v[0], /exceed the limit/);
});

test("packumentUrl encodes scoped names and rejects bad names", () => {
  assert.equal(packumentUrl("@rolldown/binding-darwin-x64"), "https://registry.npmjs.org/@rolldown%2Fbinding-darwin-x64");
  assert.equal(packumentUrl("vite"), "https://registry.npmjs.org/vite");
  assert.throws(() => packumentUrl("../../evil"));
  assert.throws(() => packumentUrl("a?b=1"));
});

test("fetchRegistryInfo: 5xx retried with backoff, 404 fatal, redirects refused", async () => {
  const delays = [];
  const delay = async (ms) => void delays.push(ms);
  let calls = 0;
  let redirectMode;
  const flaky = async (_url, init) => {
    redirectMode = init.redirect;
    if (++calls < 2) return new Response("", { status: 503 });
    return new Response(JSON.stringify({ time: { "1.0.0": "2026-01-01T00:00:00Z" }, versions: { "1.0.0": { dist: { integrity: INTEGRITY } } } }));
  };
  const info = await fetchRegistryInfo("a", { fetchImpl: flaky, delay });
  assert.deepEqual(info.time, { "1.0.0": "2026-01-01T00:00:00Z" });
  assert.equal(info.integrity.get("1.0.0"), INTEGRITY);
  assert.equal(calls, 2);
  assert.equal(redirectMode, "error");
  assert.deepEqual(delays, [1000]);

  let notFoundCalls = 0;
  const notFound = async () => (notFoundCalls++, new Response("", { status: 404 }));
  await assert.rejects(fetchRegistryInfo("a", { fetchImpl: notFound, delay }), /not found/);
  assert.equal(notFoundCalls, 1);

  const noTime = async () => new Response(JSON.stringify({ name: "a" }));
  await assert.rejects(fetchRegistryInfo("a", { fetchImpl: noTime, delay }), /no publish times/);

  const garbage = async () => new Response("<html>\n::error::x");
  await assert.rejects(fetchRegistryInfo("a", { fetchImpl: garbage, delay }), /^Error: registry returned invalid JSON$/);
});

test("escapeAnnotation neutralises workflow-command sequences", () => {
  assert.equal(escapeAnnotation("a\n::error::b%\r"), "a%0A::error::b%25%0D");
});
