// SPDX-License-Identifier: Apache-2.0
//
// Fails if any installed npm dependency has a license outside the allowlist in
// docs/engineering/security-standards.md §13. Go modules are checked by
// go-licenses in the Makefile.
import { execFileSync } from "node:child_process";

const ALLOWED = new Set([
  "Apache-2.0",
  "MIT",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "MPL-2.0",
  // Public-domain-equivalent licenses used by a few tiny packages. Adding to
  // this list requires security-owner approval.
  "0BSD",
  "CC0-1.0",
  "BlueOak-1.0.0",
]);

// SPDX expressions: an OR is acceptable if any branch is allowed; an AND needs all.
function isAllowed(expr) {
  const e = expr.replace(/[()]/g, "").trim();
  if (e.includes(" OR ")) return e.split(" OR ").some((p) => isAllowed(p));
  if (e.includes(" AND ")) return e.split(" AND ").every((p) => isAllowed(p));
  return ALLOWED.has(e);
}

const out = execFileSync("pnpm", ["licenses", "list", "--json", "--prod=false"], {
  encoding: "utf8",
  shell: process.platform === "win32",
});
const byLicense = JSON.parse(out);
const violations = [];
for (const [license, pkgs] of Object.entries(byLicense)) {
  if (isAllowed(license)) continue;
  for (const p of pkgs) violations.push(`${p.name}@${p.versions.join(",")}: ${license}`);
}
if (violations.length > 0) {
  console.error("Disallowed dependency licenses:\n  " + violations.join("\n  "));
  process.exit(1);
}
console.log(`npm licenses OK (${Object.keys(byLicense).length} license kinds checked)`);
