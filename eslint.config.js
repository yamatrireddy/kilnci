// SPDX-License-Identifier: Apache-2.0
//
// Shared ESLint flat config for every TS package. Security-relevant rules are
// errors; see docs/engineering/coding-standards.md §11 and CLAUDE.md.
import js from "@eslint/js";
import jsxA11y from "eslint-plugin-jsx-a11y";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "**/coverage/**",
      "**/src/gen/**",
      "**/src-tauri/**",
      "server/**",
      "tools/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      globals: { ...globals.browser },
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-non-null-assertion": "error",
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "No dangerouslySetInnerHTML (CLAUDE.md). Render through React escaping only.",
        },
        {
          selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/]",
          message: "Do not write raw HTML into the DOM.",
        },
        {
          selector: "JSXOpeningElement[name.name='style']",
          message: "No <style> elements: the CSP forbids inline styles (ADR-0004). Use Tailwind classes.",
        },
      ],
      "no-restricted-globals": [
        "error",
        { name: "localStorage", message: "Never store credentials in web storage; use @kiln/core preferences for non-sensitive UI state." },
        { name: "sessionStorage", message: "Never store credentials in web storage." },
      ],
    },
  },
  {
    // ADR-0004: styling is Tailwind compiled at build time. Runtime style
    // injection is blocked by the strict CSP, and Mantine was replaced.
    files: ["packages/ui/**/*.{ts,tsx}", "apps/**/*.{ts,tsx}"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["@mantine/*"],
              message: "Mantine was replaced by Tailwind CSS (ADR-0004). Use @kiln/ui primitives.",
            },
          ],
        },
      ],
    },
  },
  {
    files: ["**/*.tsx"],
    plugins: { "react-hooks": reactHooks, "jsx-a11y": jsxA11y },
    rules: {
      ...reactHooks.configs.recommended.rules,
      ...jsxA11y.flatConfigs.strict.rules,
    },
  },
  {
    files: ["**/*.config.{js,ts}", "**/vite.config.ts", "**/vitest.config.ts", "scripts/**"],
    languageOptions: { globals: { ...globals.node } },
    ...tseslint.configs.disableTypeChecked,
  },
);
