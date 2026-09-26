// SPDX-License-Identifier: Apache-2.0
//
// Presentation helpers for runs and jobs. They describe what the server
// reported; they make no decisions about what a user may do.

/** Run statuses, mirroring the API's RunStatus. */
export type RunStatusName = "awaiting_approval" | "queued" | "running" | "succeeded" | "failed" | "canceled";

/** Job statuses, mirroring the API's JobStatus. */
export type JobStatusName = "pending" | "queued" | "running" | "succeeded" | "failed" | "canceled" | "skipped";

const FINISHED = new Set<string>(["succeeded", "failed", "canceled", "skipped"]);

/** True once a run or job can no longer change, so polling can stop. */
export function isFinishedStatus(status: RunStatusName | JobStatusName): boolean {
  return FINISHED.has(status);
}

/** True while a job has not started on a runner (it has no log yet). */
export function isWaitingJob(status: JobStatusName): boolean {
  return status === "pending" || status === "queued";
}

const LABELS: Record<RunStatusName | JobStatusName, string> = {
  awaiting_approval: "Awaiting approval",
  pending: "Pending",
  queued: "Queued",
  running: "Running",
  succeeded: "Succeeded",
  failed: "Failed",
  canceled: "Canceled",
  skipped: "Skipped",
};

/** A human label for a run or job status. */
export function statusLabel(status: RunStatusName | JobStatusName): string {
  return LABELS[status];
}

/** "1m 05s" style duration between two timestamps; empty when not started. */
export function formatDuration(startIso: string | null | undefined, endIso: string | null | undefined, now: Date = new Date()): string {
  if (!startIso) return "";
  const start = new Date(startIso).getTime();
  const end = endIso ? new Date(endIso).getTime() : now.getTime();
  if (Number.isNaN(start) || Number.isNaN(end)) return "";
  const total = Math.max(0, Math.round((end - start) / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  if (h > 0) return `${String(h)}h ${pad(m)}m`;
  if (m > 0) return `${String(m)}m ${pad(s)}s`;
  return `${String(s)}s`;
}

/** The first 7 characters of a commit SHA. */
export function shortSha(sha: string): string {
  return sha.slice(0, 7);
}

// C0/C1 controls, DEL, and bidirectional embeddings, overrides, and isolates.
// eslint-disable-next-line no-control-regex -- matching control characters is the point.
const UNSAFE_DISPLAY = /[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g;

/**
 * Untrusted VCS or pipeline text (run titles, branches, job names) made safe
 * to show: control characters and bidi overrides, which could make a fork's
 * branch look like "main", become U+FFFD. The server does the same; this is
 * defense in depth for the approval screen.
 */
export function displayText(s: string): string {
  return s.replace(UNSAFE_DISPLAY, "�");
}
