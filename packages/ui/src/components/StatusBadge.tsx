// SPDX-License-Identifier: Apache-2.0
import type { JobStatus, RunStatus } from "@kiln/api-client";
import { statusLabel } from "@kiln/core";

import { Badge, type BadgeColor } from "./ui";

const COLORS: Record<RunStatus | JobStatus, BadgeColor> = {
  awaiting_approval: "purple",
  pending: "gray",
  queued: "gray",
  running: "blue",
  succeeded: "green",
  failed: "red",
  canceled: "gray",
  skipped: "gray",
};

/** A run's or job's status as a colored label. */
export function StatusBadge({ status }: { status: RunStatus | JobStatus }) {
  return <Badge color={COLORS[status]}>{statusLabel(status)}</Badge>;
}
