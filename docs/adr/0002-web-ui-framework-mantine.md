<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-0002: Mantine as the UI framework for web and desktop

- **Status:** Superseded by [ADR-0004](0004-web-ui-tailwind-css.md) (2026-09-26)
- **Date:** 2026-09-24

## Context

Kiln needs one accessible, themeable React component library shared by the web
app and the desktop app (Tauri webview), with mobile to follow later. The
maintainer chose Mantine. Kiln's web CSP forbids `'unsafe-inline'` styles and
scripts (security-standards §10), and Tauri's privileged window must not load
remote content (T-35).

By default `MantineProvider` injects a `<style>` element with the theme's CSS
variables at runtime, and some features inject more `<style>` elements
(global `hiddenFrom`/`visibleFrom` classes, responsive style props). A strict
`style-src 'self'` policy blocks all of these.

## Decision

1. Use **Mantine 9** (`@mantine/core`, `@mantine/hooks`,
   `@mantine/notifications`; MIT) for all DOM UI. Components, the theme, and
   screens live in `packages/ui`; `apps/web` and `apps/desktop` are thin shells
   that provide a platform adapter (API client, sign-in, navigation).
2. **No runtime style injection.** The theme's CSS variables are compiled at
   build time by `packages/ui/scripts/build-theme-css.ts` (using Mantine's own
   `defaultCssVariablesResolver` and `convertCssVariables`) into
   `theme-vars.css`, shipped as a static stylesheet. The provider runs with
   `withCssVariables={false}` and `withGlobalClasses={false}`. A unit test
   fails if the generated file drifts from `theme.ts`.
3. UI code must not use features that inject `<style>` at runtime:
   `AppShell`, `Grid`, `SimpleGrid`, and `Flex` (verified in Mantine 9's source:
   they render `InlineStyles`), responsive object values for style props,
   `hiddenFrom`/`visibleFrom`, and `lightHidden`/`darkHidden`. Use CSS modules
   instead. ESLint (`no-restricted-imports`) blocks the components, and a
   component test renders every page and fails if any `<style>` element is
   added to the document.
4. Styles set through React's `style` prop are applied via the CSSOM, which
   CSP does not restrict, so ordinary Mantine style props remain usable.
5. The resulting policy for both web and desktop is
   `style-src 'self'` with no nonce, no hash, and no `'unsafe-inline'`.
   `ColorSchemeScript` (an inline script) is not used.

## Consequences

- One CSP works for web (served by kiln-server) and desktop (Tauri) without
  per-request nonce plumbing.
- Theme changes require `pnpm --filter @kiln/ui generate` (enforced by test).
- A few convenience props are off-limits; CSS modules cover those cases.
- Mantine and its peers are MIT-licensed and actively maintained, satisfying
  the dependency policy (security-standards §13).

## Security considerations

- *Tampering / XSS (B5, T-09):* keeping `style-src` and `script-src` free of
  `'unsafe-inline'` limits the damage of any HTML injection bug; React escaping
  remains the primary control and `dangerouslySetInnerHTML` stays banned by
  ESLint and Semgrep.
- *Elevation (T-35):* the desktop webview gets the same strict CSP, reducing
  the chance that injected content can reach Tauri IPC.
- No trust boundary moves; this ADR constrains how the UI is built.
