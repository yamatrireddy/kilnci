// SPDX-License-Identifier: Apache-2.0
import { ApiError, LogStreamError, type LogStreamJobStatus } from "@kiln/api-client";
import { LogBuffer } from "@kiln/core";
import { useEffect, useState } from "react";

import { usePlatform } from "../../platform";

export type LiveLogPhase =
  | { phase: "connecting" }
  | { phase: "live" }
  | { phase: "reconnecting" }
  | { phase: "ended"; status: LogStreamJobStatus }
  | { phase: "error"; error: unknown };

/** Consecutive failed connections before the viewer gives up and offers a retry. */
export const MAX_STREAM_FAILURES = 6;

// Render at most this often while chunks arrive quickly.
const RENDER_INTERVAL_MS = 100;

// A connection that stayed open this long counts as healthy even if the job
// printed nothing.
const HEALTHY_MS = 30_000;

/** Delay before reconnecting: at least 1 s, doubling per failure, jittered. */
function backoff(failures: number): number {
  const base = Math.min(30_000, 1_000 * 2 ** failures);
  return base / 2 + Math.random() * (base / 2) + 500;
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const t = setTimeout(done, ms);
    function done() {
      clearTimeout(t);
      signal.removeEventListener("abort", done);
      resolve();
    }
    signal.addEventListener("abort", done);
  });
}

/** Errors that another attempt cannot fix. */
function isFinal(e: unknown): boolean {
  if (e instanceof LogStreamError) return true;
  return e instanceof ApiError && e.status < 500 && e.status !== 429;
}

/**
 * Follows a job's log over Server-Sent Events. It resumes from the last chunk
 * after a disconnect (including the server's 30-minute stream limit), starts
 * over when the job begins a new attempt, and stops at the `end` event.
 * Mount it with a `key` per job (and per retry): state is not reset when the
 * arguments change.
 */
export function useLiveJobLog(orgSlug: string, projectSlug: string, runId: string, jobId: string) {
  const { client } = usePlatform();
  // One mutable buffer per hook instance; `version` tells React it changed.
  const [buf] = useState(() => new LogBuffer());
  const [version, setVersion] = useState(0);
  const [state, setState] = useState<LiveLogPhase>({ phase: "connecting" });
  const [attempt, setAttempt] = useState<number | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    // A function, so type narrowing does not assume it stays false across awaits.
    const aborted = () => ctrl.signal.aborted;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const render = () => {
      timer ??= setTimeout(() => {
        timer = undefined;
        setVersion((v) => v + 1);
      }, RENDER_INTERVAL_MS);
    };

    const run = async () => {
      let lastEventId: string | undefined;
      let current: number | undefined;
      let failures = 0;
      while (!aborted()) {
        // Only output or the end counts as progress: the server sends the
        // attempt event before reading storage, so a stream that fails right
        // after it must not reset the backoff (security review).
        let progressed = false;
        let retryAfter: number | undefined;
        const opened = Date.now();
        try {
          const events = client.streamJobLog(orgSlug, projectSlug, runId, jobId, {
            ...(lastEventId ? { lastEventId } : {}),
            signal: ctrl.signal,
          });
          for await (const ev of events) {
            if (aborted()) return;
            if (ev.type !== "attempt" && !progressed) {
              progressed = true;
              failures = 0;
            }
            setState((s) => (s.phase === "live" ? s : { phase: "live" }));
            if (ev.type === "attempt") {
              if (current !== ev.attempt) {
                // A retried job's log starts from scratch.
                if (current !== undefined) buf.reset();
                current = ev.attempt;
                setAttempt(ev.attempt);
                render();
              }
            } else if (ev.type === "chunk") {
              if (ev.attempt !== current) continue;
              buf.pushBytes(ev.data);
              lastEventId = ev.id;
              render();
            } else {
              setState({ phase: "ended", status: ev.status });
              render();
              return;
            }
          }
          if (aborted()) return;
          // Closed without an end event (stream time limit or a proxy):
          // resume if it was healthy, back off if it was not.
          if (!progressed && Date.now() - opened < HEALTHY_MS) failures++;
        } catch (e) {
          if (aborted()) return;
          if (isFinal(e)) {
            setState({ phase: "error", error: e });
            return;
          }
          if (e instanceof ApiError) retryAfter = e.retryAfter;
          failures++;
        }
        if (failures >= MAX_STREAM_FAILURES) {
          setState({ phase: "error", error: new Error("log stream unavailable") });
          return;
        }
        setState({ phase: "reconnecting" });
        await sleep(Math.max(backoff(failures), Math.min(retryAfter ?? 0, 300) * 1000), ctrl.signal);
      }
    };
    void run();

    return () => {
      ctrl.abort();
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [buf, client, orgSlug, projectSlug, runId, jobId]);

  return { buffer: buf, version, state, attempt };
}
