<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-0004: Tailwind CSS and native-element primitives for web and desktop UI

- **Status:** Proposed (requested by the maintainer, 2026-09-26; pending review)
- **Date:** 2026-09-26
- **Supersedes:** ADR-0002

## Context

ADR-0002 adopted Mantine 9 and made it work under Kiln's strict CSP
(`style-src 'self'`, no `'unsafe-inline'`) by compiling Mantine's theme
variables at build time, turning off its runtime style injection, and banning
the components that still inject `<style>` (`AppShell`, `Grid`, `Flex`, ...).
That works, but it means fighting the library: a generated `theme-vars.css`
that must be kept in sync, a list of forbidden components and props, and a
PostCSS preset that exists only for Mantine. The maintainer asked to move the
React UI to Tailwind CSS while keeping behaviour and overall design.

## Decision

1. Style all DOM UI (`packages/ui`, `apps/web`, `apps/desktop`) with
   **Tailwind CSS 4** (`tailwindcss`, `@tailwindcss/vite`; MIT). Mantine and
   its PostCSS preset are removed.
2. **Build-time CSS only.** `packages/ui/src/styles.css` holds the Tailwind
   entry point, the Kiln theme (`@theme`: the "kiln" orange scale, fonts) and
   semantic light/dark tokens (`bg-body`, `text-fg`, `border-line`,
   `text-dimmed`, ...). The Vite plugin compiles it to one static stylesheet.
   Nothing is injected at runtime, so the CSP stays `style-src 'self'`.
3. **Primitives on native elements**, in `packages/ui/src/components/ui/`,
   with no new runtime dependency: `<dialog>` + `showModal()` for modals
   (focus trap, inert background, Escape), native `<select>`/checkbox/number
   inputs, and WAI-ARIA APG patterns for tabs and the menu button. Tooltips
   are positioned through the `style` property (CSSOM), which CSP does not
   restrict (ADR-0002 §4 still holds).
4. Dark mode follows `prefers-color-scheme`, as before.
5. The existing guards stay: the component test renders every page and fails
   if any `<style>` element appears, `check-csp-dist.mjs` checks the built
   `index.html`, and ESLint now bans `@mantine/*` imports and `<style>` JSX.

## Consequences

- No generated theme file, no forbidden-component list, no PostCSS config.
  Theme changes are edits to `styles.css`.
- Kiln owns ~600 lines of primitives (modal, menu, tabs, tooltip, toasts,
  fields, table) and their accessibility; they are covered by axe checks and
  keyboard tests in `ui.test.tsx`.
- Tailwind 4 targets current engines (Chrome/Edge 111+, Safari 16.4+,
  Firefox 128+). Desktop inherits this: Windows WebView2 is evergreen, macOS
  needs 13.3+, Linux needs a current WebKitGTK.
- The shipped CSS dropped from Mantine's full stylesheet to ~33 kB (7.7 kB gzip).

## Security considerations

- *Tampering / XSS (B5, T-09):* unchanged. `style-src` and `script-src` stay
  free of `'unsafe-inline'`; React escaping and the `dangerouslySetInnerHTML`
  ban remain the primary controls.
- *Supply chain (§13, T-48):* the new packages are build-time only
  (`tailwindcss`, `@tailwindcss/vite`, `lightningcss`, `@tailwindcss/oxide`
  native binaries); none ship in the browser bundle except the generated CSS.
  Licenses are MIT, ISC, and MPL-2.0 (lightningcss, file-level, allowlisted).
  Removing Mantine drops ~35 runtime packages (`@floating-ui/*`,
  `react-remove-scroll`, `react-number-format`, ...).
- The `style` prop (CSSOM) may carry only values the code computes itself
  (e.g. tooltip coordinates), never server- or user-supplied strings.
- The ESLint `<style>` JSX ban does not catch `document.createElement("style")`;
  the runtime "no `<style>` injected" test and `check-csp-dist.mjs` are the
  real controls, and the browser CSP is the backstop.
- No trust boundary moves.
