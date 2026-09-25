// SPDX-License-Identifier: Apache-2.0

/**
 * Joins class names, skipping falsy parts. Class strings are always written
 * out in full (never assembled from fragments) so Tailwind can find them.
 */
export function cn(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}
