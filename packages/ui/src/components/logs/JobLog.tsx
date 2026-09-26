// SPDX-License-Identifier: Apache-2.0
import type { Job } from "@kiln/api-client";
import { displayText, isFinishedStatus, isWaitingJob, LogBuffer, statusLabel } from "@kiln/core";
import { useEffect, useMemo, useRef, useState } from "react";

import { usePlatform } from "../../platform";
import { useStoredJobLog } from "../../queries";
import { ErrorAlert } from "../ErrorAlert";
import { Button, Spinner } from "../ui";
import { LogViewer } from "./LogViewer";
import { useLiveJobLog } from "./useLiveJobLog";

interface JobLogProps {
  orgSlug: string;
  projectSlug: string;
  runId: string;
  job: Job;
}

/**
 * A job's log: followed live where the platform can stream, otherwise read
 * from storage (and re-read while the job runs).
 */
export function JobLog(props: JobLogProps) {
  const { liveLogs } = usePlatform();
  const [retry, setRetry] = useState(0);
  const label = `Log for ${displayText(props.job.name)}`;
  if (isWaitingJob(props.job.status)) {
    return (
      <LogViewer
        label={label}
        lines={[]}
        empty={props.job.status === "pending" ? "Waiting for the jobs this one needs." : "Waiting for a runner to pick up this job."}
      />
    );
  }
  if (liveLogs) {
    return (
      <LiveJobLog
        key={`${props.job.id}:${String(retry)}`}
        {...props}
        label={label}
        onRetry={() => {
          setRetry((n) => n + 1);
        }}
      />
    );
  }
  return <StoredJobLog key={props.job.id} {...props} label={label} />;
}

function LiveJobLog({ orgSlug, projectSlug, runId, job, label, onRetry }: JobLogProps & { label: string; onRetry: () => void }) {
  const { buffer, version, state, attempt } = useLiveJobLog(orgSlug, projectSlug, runId, job.id);
  if (state.phase === "error") {
    return (
      <div className="flex flex-col gap-3">
        <ErrorAlert error={state.error} title="Could not load the log" />
        <div>
          <Button variant="default" onClick={onRetry}>
            Try again
          </Button>
        </div>
      </div>
    );
  }
  const footer =
    state.phase === "connecting" ? (
      <Spinner size="sm" label="Connecting to the log" />
    ) : state.phase === "reconnecting" ? (
      <span role="status">Connection lost. Reconnecting…</span>
    ) : state.phase === "live" ? (
      <span className="inline-flex items-center gap-2">
        <span aria-hidden="true" className="size-2 animate-pulse rounded-full bg-green-500" />
        Following live output{attempt !== null && attempt > 1 ? ` (attempt ${String(attempt)})` : ""}
      </span>
    ) : (
      <span role="status">Job {statusLabel(state.status).toLowerCase()}.</span>
    );
  return (
    <LogViewer
      label={label}
      lines={buffer.lines}
      pending={buffer.pending()}
      dropped={buffer.dropped}
      version={version}
      empty={state.phase === "ended" ? "This job produced no output." : "No output yet."}
      footer={footer}
    />
  );
}

function StoredJobLog({ orgSlug, projectSlug, runId, job, label }: JobLogProps & { label: string }) {
  const running = !isFinishedStatus(job.status);
  const log = useStoredJobLog(orgSlug, projectSlug, runId, job.id, { enabled: true, live: running });
  const { refetch } = log;
  // Read the complete log once more when the job finishes.
  const wasRunning = useRef(running);
  useEffect(() => {
    if (wasRunning.current && !running) void refetch();
    wasRunning.current = running;
  }, [running, refetch]);
  const buffer = useMemo(() => {
    const b = new LogBuffer();
    if (log.data !== undefined) b.pushText(log.data);
    return b;
  }, [log.data]);
  if (log.isPending) {
    return (
      <div className="flex justify-center py-12">
        <Spinner label="Loading the log" />
      </div>
    );
  }
  if (log.isError) return <ErrorAlert error={log.error} title="Could not load the log" />;
  return (
    <LogViewer
      label={label}
      lines={buffer.lines}
      pending={buffer.pending()}
      dropped={buffer.dropped}
      empty={running ? "No output yet." : "This job produced no output."}
      footer={
        running ? (
          <span className="flex flex-wrap items-center gap-3">
            Refreshes every 30 seconds while the job runs.
            <Button
              size="sm"
              variant="default"
              loading={log.isFetching}
              onClick={() => {
                void refetch();
              }}
            >
              Refresh now
            </Button>
          </span>
        ) : null
      }
    />
  );
}
