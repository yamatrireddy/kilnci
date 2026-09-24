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
// Walk every "<script" start tag without trying to match end tags with a
// regex (browsers accept variants like "</script >", which a regex can miss).
// Each script must have a src attribute and nothing but whitespace before the
// next "</script" (however that end tag is spelled).
const lower = html.toLowerCase();
for (let i = lower.indexOf("<script"); i !== -1; i = lower.indexOf("<script", i + 1)) {
  const tagEnd = lower.indexOf(">", i);
  if (tagEnd === -1) {
    problems.push("unterminated <script> tag");
    break;
  }
  const attrs = lower.slice(i + "<script".length, tagEnd);
  const close = lower.indexOf("</script", tagEnd);
  const body = close === -1 ? lower.slice(tagEnd + 1) : lower.slice(tagEnd + 1, close);
  if (!/\bsrc\s*=/.test(attrs) || body.trim() !== "") problems.push("inline <script>");
}
if (/<style\b/i.test(html)) problems.push("inline <style>");
if (/\sstyle\s*=/i.test(html)) problems.push("style= attribute");
if (/\son[a-z]+\s*=/i.test(html)) problems.push("inline event handler");
if (problems.length > 0) {
  console.error("dist/index.html violates the CSP:\n  " + problems.join("\n  "));
  process.exit(1);
}
console.log(`${dist}/index.html is CSP-clean`);
