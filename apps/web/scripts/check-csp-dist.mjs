// SPDX-License-Identifier: Apache-2.0
//
// usage: node check-csp-dist.mjs [distDir]   (default: ./dist)
//
// Fails the build if <dist>/index.html contains anything the production CSP
// (script-src 'self'; style-src 'self') would block: inline scripts, inline
// <style>, style attributes, or inline event handlers (ADR-0002).
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const dist = resolve(process.argv[2] ?? "dist");
const html = readFileSync(resolve(dist, "index.html"), "utf8");
const problems = [];
for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
  const [, attrs = "", body = ""] = m;
  if (!/\bsrc=/.test(attrs) || body.trim() !== "") problems.push("inline <script>");
}
if (/<style\b/i.test(html)) problems.push("inline <style>");
if (/\sstyle\s*=/i.test(html)) problems.push("style= attribute");
if (/\son[a-z]+\s*=/i.test(html)) problems.push("inline event handler");
if (problems.length > 0) {
  console.error("dist/index.html violates the CSP:\n  " + problems.join("\n  "));
  process.exit(1);
}
console.log(`${dist}/index.html is CSP-clean`);
