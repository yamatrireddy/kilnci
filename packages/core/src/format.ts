// SPDX-License-Identifier: Apache-2.0

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
  ["second", 1],
];

/** "3 minutes ago" / "in 2 days". `now` is injectable for tests. */
export function formatRelative(iso: string, now: Date = new Date(), locale?: string): string {
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return "";
  const diff = Math.round((then.getTime() - now.getTime()) / 1000);
  const fmt = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  for (const [unit, secs] of UNITS) {
    if (Math.abs(diff) >= secs || unit === "second") {
      return fmt.format(Math.round(diff / secs), unit);
    }
  }
  return "";
}

/** Absolute timestamp in the user's locale, for titles and tooltips. */
export function formatDateTime(iso: string, locale?: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(d);
}
