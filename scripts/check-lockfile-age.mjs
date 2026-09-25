// SPDX-License-Identifier: Apache-2.0
//
// Lockfile release-age gate (security-standards §13, threat T-48).
//
// pnpm enforces `minimumReleaseAge` only when it resolves versions;
// `pnpm install --frozen-lockfile` trusts whatever pnpm-lock.yaml pins. A PR that
// edits the lockfile directly could therefore pin a package published minutes
// ago. This script compares the `packages:` section of pnpm-lock.yaml at HEAD
// with the same file at a base revision and, for every newly added
// name@version, requires that the npm registry
//   - published that version at least seven days ago, and
//   - lists the same integrity hash the lockfile pins.
//
// The lockfile is attacker-controlled input and pnpm reads it with a full YAML
// parser (js-yaml), so this script accepts only a strict subset of pnpm's own
// v9 output and fails closed on everything else. Every line of the file must be
// a complete single-line construct (no value may continue onto another line),
// so indentation alone determines structure and both parsers agree on it. On
// top of that: allow-listed top-level keys and entry fields, every snapshot
// must map to a `packages:` entry, no anchors/aliases/tags/double quotes, no
// stray carriage returns, and only default-registry resolutions. The integrity
// cross-check ensures that, for every entry the gate sees, what pnpm fetches
// is byte-identical to the npm version whose age was checked.
//
// Usage: node scripts/check-lockfile-age.mjs --base <git-rev> [--lockfile pnpm-lock.yaml]
//
// Dependency-free: Node standard library only (Node >= 22).
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { pathToFileURL } from "node:url";

// Seven days, matching `minimumReleaseAge: 10080` (minutes) in
// pnpm-workspace.yaml. Hard-coded rather than read from the PR's workspace file,
// because a PR could otherwise lower the threshold in the same change.
export const MIN_AGE_MS = 10080 * 60 * 1000;
// More new versions than this in one PR needs a security owner to look at it
// rather than a few thousand registry requests.
export const MAX_NEW_ENTRIES = 2000;

export const REGISTRY = "https://registry.npmjs.org/";
const FETCH_TIMEOUT_MS = 30_000;
const MAX_PACKUMENT_BYTES = 64 * 1024 * 1024;
const MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;
const CONCURRENCY = 4;
const RETRY_DELAYS_MS = [1_000, 4_000];

// npm package names, including legacy mixed-case names. Validated before a name
// is placed in a URL or printed as a GitHub annotation.
const NAME_RE = /^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*\/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$/;
// Plain semver as the npm registry publishes it. Anything else (git URLs,
// tarballs, file:, link:) cannot be age-checked, so it is rejected.
const SEMVER_RE =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
// The only resolution form pnpm writes for packages from the default registry.
const RESOLUTION_RE = /^\{integrity: (sha512-[A-Za-z0-9+/]+={0,2})\}$/;

// Control characters, C1 controls, Unicode line/paragraph separators, BOM, and
// tab. js-yaml treats a lone CR as a line break; this parser splits on LF only,
// so every CR not part of CRLF is rejected rather than interpreted.
const FORBIDDEN_CHARS_RE = /[\u0000-\u0009\u000B-\u001F\u007F-\u009F\u2028\u2029\uFEFF]/;
// Top-level keys pnpm 10 writes. Anything else is refused.
const TOP_LEVEL_KEYS = new Set([
  "lockfileVersion",
  "settings",
  "catalogs",
  "overrides",
  "packageExtensionsChecksum",
  "pnpmfileChecksum",
  "patchedDependencies",
  "ignoredOptionalDependencies",
  "importers",
  "packages",
  "snapshots",
]);
// Fields allowed on a `packages:` entry. Notably absent: `version`, `name`, `id`,
// which pnpm would use in place of the key when building the tarball URL.
const PACKAGE_FIELDS = new Set([
  "resolution",
  "engines",
  "cpu",
  "os",
  "libc",
  "hasBin",
  "deprecated",
  "peerDependencies",
  "peerDependenciesMeta",
  "bundledDependencies",
]);
// Fields allowed on a `snapshots:` entry. Notably absent: `resolution`,
// `version`, `name`, `id`, which pnpm would merge into the install graph.
const SNAPSHOT_FIELDS = new Set(["dependencies", "optionalDependencies", "transitivePeerDependencies", "optional"]);

/** Error for lockfile content the parser refuses to interpret. */
export class LockfileError extends Error {}

function splitKey(key, where) {
  const at = key.lastIndexOf("@");
  if (at <= 0) throw new LockfileError(`${where}: package key without a version`);
  const name = key.slice(0, at);
  const version = key.slice(at + 1);
  if (!NAME_RE.test(name)) throw new LockfileError(`${where}: invalid package name`);
  if (!SEMVER_RE.test(version)) {
    throw new LockfileError(`${where}: ${name} is not pinned to a registry semver version`);
  }
  return { name, version };
}

// Single-line grammar every lockfile line must match. js-yaml lets quoted
// strings and flow collections continue across lines (even to column 0), which
// would let one line swallow the lines after it and make the two parsers
// disagree on structure. Requiring each line to be complete on its own leaves
// indentation as the only structure, which both parsers read the same way.
// Plain scalars exclude every YAML indicator that could start an anchor, alias,
// tag, comment, block scalar, flow collection, or quoted string.
const PLAIN_CHAR = String.raw`[A-Za-z0-9._~^<=>/+()@|-]`;
const PLAIN_START = String.raw`[A-Za-z0-9._~^<=/+()]`;
// `:*` covers `workspace:*`; a `*` that starts a token (an alias) stays excluded.
const PLAIN = `${PLAIN_START}(?:${PLAIN_CHAR}|:\\*|:(?=${PLAIN_CHAR})| (?=${PLAIN_CHAR}))*`;
const SQUOTED = `'(?:[^']|'')*'`;
const KEY = `(?:[A-Za-z0-9._~][A-Za-z0-9._~@/+()-]*|${SQUOTED})`;
const SCALAR = `(?:${PLAIN}|${SQUOTED})`;
const FLOW_MAP = String.raw`\{${KEY}: ${SCALAR}(?:, ${KEY}: ${SCALAR})*\}`;
const FLOW_SEQ = String.raw`\[${SCALAR}(?:, ${SCALAR})*\]`;
const VALUE = String.raw`(?:${SCALAR}|\{\}|\[\]|${FLOW_MAP}|${FLOW_SEQ})`;
const LINE_RE = new RegExp(`^(?:  )*(?:${KEY}:(?: ${VALUE})?|- ${VALUE})$`);

// Validates a snapshot key's peer suffix: zero or more balanced `(...)` groups,
// back to back, directly after name@version. Returns name@version.
function snapshotBase(key, where) {
  const paren = key.indexOf("(");
  if (paren === -1) return key;
  let depth = 0;
  for (let i = paren; i < key.length; i++) {
    const c = key[i];
    if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (depth === 0 || !/[A-Za-z0-9@/._~+-]/.test(c)) depth = -1;
    if (depth < 0) break;
  }
  if (depth !== 0) throw new LockfileError(`${where}: malformed snapshot key`);
  return key.slice(0, paren);
}

/**
 * Parses a block-mapping section (`packages:` or `snapshots:`) of a pnpm v9
 * lockfile into key → {fields: Map<field, inlineValue|null>, line}.
 */
function parseSection(lines, start, end, allowedFields, allowEmptyEntry) {
  const entries = new Map();
  let current = null;
  let lastFieldInline = true;
  for (let i = start; i < end; i++) {
    const line = lines[i];
    const where = `pnpm-lock.yaml:${i + 1}`;
    if (line === "") continue;

    let m;
    if ((m = /^ {2}(?:'([^']+)'|([A-Za-z0-9~][^\s'"]*)):( \{\})?$/.exec(line))) {
      const key = m[1] ?? m[2];
      if (entries.has(key)) throw new LockfileError(`${where}: duplicate key ${key}`);
      if (m[3] !== undefined && !allowEmptyEntry) throw new LockfileError(`${where}: empty package entry`);
      current = { fields: new Map(), line: i + 1 };
      lastFieldInline = true;
      entries.set(key, current);
    } else if (current !== null && (m = /^ {4}([A-Za-z]+):(?: (.+))?$/.exec(line))) {
      const [, field, value] = m;
      if (!allowedFields.has(field)) throw new LockfileError(`${where}: field "${field}" is not allowed here`);
      if (current.fields.has(field)) throw new LockfileError(`${where}: duplicate field "${field}"`);
      current.fields.set(field, value ?? null);
      lastFieldInline = value !== undefined;
    } else if (current !== null && /^ {6,}\S/.test(line) && !lastFieldInline) {
      // Nested block content under the preceding field (e.g. a dependency map).
    } else {
      throw new LockfileError(`${where}: unexpected line in lockfile section`);
    }
  }
  return entries;
}

/**
 * Parses and validates a pnpm v9 lockfile.
 *
 * @param {string} text lockfile contents
 * @returns {Map<string, {name: string, version: string, integrity: string}>}
 *   the `packages:` section keyed by `name@version`
 */
export function parseLockfilePackages(text) {
  const normalized = text.replaceAll("\r\n", "\n");
  const bad = FORBIDDEN_CHARS_RE.exec(normalized);
  if (bad !== null) {
    const line = normalized.slice(0, bad.index).split("\n").length;
    throw new LockfileError(`pnpm-lock.yaml:${line}: forbidden character U+${bad[0].charCodeAt(0).toString(16).padStart(4, "0")}`);
  }
  const lines = normalized.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] !== "" && !LINE_RE.test(lines[i])) {
      throw new LockfileError(`pnpm-lock.yaml:${i + 1}: line is not in the single-line form pnpm writes`);
    }
  }

  // Locate top-level sections. Every non-indented line must be a known key.
  const sections = new Map();
  let open = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === "" || line.startsWith(" ")) continue;
    const where = `pnpm-lock.yaml:${i + 1}`;
    const m = /^([A-Za-z]+):(?: (.+))?$/.exec(line);
    if (!m || !TOP_LEVEL_KEYS.has(m[1])) throw new LockfileError(`${where}: unexpected top-level line`);
    if (sections.has(m[1])) throw new LockfileError(`${where}: duplicate top-level key ${m[1]}`);
    if ((m[1] === "packages" || m[1] === "snapshots") && m[2] !== undefined) {
      throw new LockfileError(`${where}: ${m[1]} section not in block form`);
    }
    if (open !== null) open.end = i;
    open = { start: i + 1, end: lines.length, value: m[2] };
    sections.set(m[1], open);
  }

  if (sections.get("lockfileVersion")?.value !== "'9.0'") {
    throw new LockfileError("unsupported or missing lockfileVersion (expected '9.0')");
  }

  const pkgSection = sections.get("packages");
  const snapSection = sections.get("snapshots");
  const rawPackages = pkgSection ? parseSection(lines, pkgSection.start, pkgSection.end, PACKAGE_FIELDS, false) : new Map();
  const rawSnapshots = snapSection ? parseSection(lines, snapSection.start, snapSection.end, SNAPSHOT_FIELDS, true) : new Map();

  const packages = new Map();
  for (const [key, entry] of rawPackages) {
    const where = `pnpm-lock.yaml:${entry.line}`;
    const { name, version } = splitKey(key, where);
    const m = RESOLUTION_RE.exec(entry.fields.get("resolution") ?? "");
    if (!m) throw new LockfileError(`${where}: ${key} resolution is not a default-registry integrity hash`);
    packages.set(key, { name, version, integrity: m[1] });
  }

  // pnpm builds the install graph from snapshots and merges the matching
  // packages entry into each; a snapshot without one would be installed from
  // whatever it carries itself, bypassing the packages check above.
  for (const [key, entry] of rawSnapshots) {
    const where = `pnpm-lock.yaml:${entry.line}`;
    const base = snapshotBase(key, where);
    splitKey(base, where);
    if (!packages.has(base)) throw new LockfileError(`${where}: snapshot ${base} has no packages entry`);
  }

  return packages;
}

/**
 * Returns the entries that are new in `head` relative to `base`, plus problems
 * for entries whose integrity changed for the same name@version (npm versions
 * are immutable, so that is never legitimate).
 */
export function diffEntries(base, head) {
  const added = [];
  const problems = [];
  for (const [key, entry] of head) {
    const old = base.get(key);
    if (old === undefined) added.push(entry);
    else if (old.integrity !== entry.integrity) problems.push(`${key}: integrity changed for an already-locked version`);
  }
  return { added, problems };
}

/** Registry URL for a validated package name. */
export function packumentUrl(name) {
  if (!NAME_RE.test(name)) throw new Error(`invalid package name`);
  const path = name.startsWith("@") ? "@" + encodeURIComponent(name.slice(1)) : encodeURIComponent(name);
  return REGISTRY + path;
}

async function readCapped(res, limit) {
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      throw new Error(`response exceeds ${limit} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const fatal = (msg) => Object.assign(new Error(msg), { fatal: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Fetches publish times and integrity hashes for a package from the npm
 * registry. The full packument is needed; the abbreviated install format
 * omits `time`.
 *
 * @returns {Promise<{time: Record<string,string>, integrity: Map<string,string>}>}
 */
export async function fetchRegistryInfo(name, { fetchImpl = fetch, delay = sleep } = {}) {
  const url = packumentUrl(name);
  let lastErr;
  for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
    if (attempt > 0) await delay(RETRY_DELAYS_MS[attempt - 1]);
    try {
      const res = await fetchImpl(url, {
        headers: { accept: "application/json" },
        redirect: "error",
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (res.status === 404) throw fatal("not found on the npm registry");
      if (!res.ok) throw new Error(`registry returned HTTP ${res.status}`);
      let doc;
      try {
        doc = JSON.parse(await readCapped(res, MAX_PACKUMENT_BYTES));
      } catch (err) {
        if (err instanceof SyntaxError) throw new Error("registry returned invalid JSON");
        throw err;
      }
      if (doc === null || typeof doc.time !== "object" || doc.time === null) throw fatal("registry response has no publish times");
      const integrity = new Map();
      for (const [v, meta] of Object.entries(doc.versions ?? {})) {
        if (typeof meta?.dist?.integrity === "string") integrity.set(v, meta.dist.integrity);
      }
      return { time: doc.time, integrity };
    } catch (err) {
      lastErr = err;
      if (err.fatal) break;
    }
  }
  throw lastErr;
}

/**
 * Checks each entry against the registry. Fails closed: an entry whose age or
 * integrity cannot be established is reported as a violation.
 *
 * @returns {Promise<string[]>} violation messages
 */
export async function checkEntries(entries, { now = Date.now(), minAgeMs = MIN_AGE_MS, fetchInfo = fetchRegistryInfo } = {}) {
  if (entries.length > MAX_NEW_ENTRIES) {
    return [`${entries.length} new package versions exceed the limit of ${MAX_NEW_ENTRIES}; needs security-owner review`];
  }
  const byName = new Map();
  for (const e of entries) {
    if (!byName.has(e.name)) byName.set(e.name, []);
    byName.get(e.name).push(e);
  }
  const names = [...byName.keys()];
  const violations = [];
  let next = 0;
  const worker = async () => {
    while (next < names.length) {
      const name = names[next++];
      let info;
      try {
        info = await fetchInfo(name);
      } catch (err) {
        for (const e of byName.get(name)) violations.push(`${name}@${e.version}: cannot verify on the npm registry (${err.message})`);
        continue;
      }
      for (const { version: v, integrity } of byName.get(name)) {
        const published = Date.parse(Object.hasOwn(info.time, v) ? info.time[v] : "");
        const npmIntegrity = info.integrity.get(v);
        if (Number.isNaN(published)) {
          violations.push(`${name}@${v}: no publish time on the npm registry`);
        } else if (now - published < minAgeMs) {
          const days = Math.max(0, (now - published) / 86_400_000).toFixed(1);
          violations.push(
            `${name}@${v}: published ${new Date(published).toISOString()} (${days} days ago), minimum is ${minAgeMs / 86_400_000} days`,
          );
        }
        if (npmIntegrity === undefined) {
          violations.push(`${name}@${v}: no integrity hash on the npm registry`);
        } else if (npmIntegrity !== integrity) {
          violations.push(`${name}@${v}: lockfile integrity does not match the npm registry`);
        }
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, names.length) }, worker));
  return violations.sort();
}

function git(args) {
  return execFileSync("git", args, { encoding: "utf8", maxBuffer: MAX_LOCKFILE_BYTES, stdio: ["ignore", "pipe", "pipe"] });
}

function readBaseLockfile(baseRev, path) {
  const commit = git(["rev-parse", "--verify", "--end-of-options", `${baseRev}^{commit}`]).trim();
  try {
    git(["cat-file", "-e", `${commit}:${path}`]);
  } catch {
    return ""; // no lockfile at base: every entry is new
  }
  return git(["show", `${commit}:${path}`]);
}

function parseArgs(argv) {
  const opts = { base: null, lockfile: "pnpm-lock.yaml" };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--base") opts.base = argv[++i];
    else if (argv[i] === "--lockfile") opts.lockfile = argv[++i];
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  if (!opts.base) throw new Error("--base <git-rev> is required");
  if (opts.base.startsWith("-")) throw new Error("--base must be a revision, not an option");
  if (!/^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/.test(opts.lockfile) || opts.lockfile.includes("..")) {
    throw new Error("--lockfile must be a relative path inside the repository");
  }
  return opts;
}

/** Escapes a message for a GitHub workflow command. */
export function escapeAnnotation(msg) {
  return msg.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
}

function annotate(msg) {
  if (process.env.GITHUB_ACTIONS === "true") console.log(`::error file=pnpm-lock.yaml::${escapeAnnotation(msg)}`);
  else console.error(`  ${msg}`);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const parse = (text) => (text === "" ? new Map() : parseLockfilePackages(text));
  const base = parse(readBaseLockfile(opts.base, opts.lockfile));
  const head = parse(existsSync(opts.lockfile) ? readFileSync(opts.lockfile, "utf8") : "");

  const { added, problems } = diffEntries(base, head);
  const violations = [...problems, ...(await checkEntries(added))];
  if (violations.length > 0) {
    console.error(`Lockfile release-age gate failed (${violations.length} finding(s)):`);
    for (const v of violations) annotate(v);
    process.exit(1);
  }
  console.log(`lockfile release age OK (${added.length} new package version(s) checked)`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((err) => {
    console.error(`check-lockfile-age: ${escapeAnnotation(err.message)}`);
    process.exit(1);
  });
}
