// SPDX-License-Identifier: Apache-2.0
//
// A reader for the job log Server-Sent Events stream (ADR-0007). It uses
// fetch rather than EventSource so the same authentication middleware
// applies on every platform, and it validates every event it yields: the
// stream carries build output that a fork PR's author controls, so nothing in
// it is trusted beyond "bytes to display".

/** Job statuses the `end` event reports. */
export type LogStreamJobStatus = "pending" | "queued" | "running" | "succeeded" | "failed" | "canceled" | "skipped";

/** One event from a job's log stream. */
export type LogStreamEvent =
  /** A (new) attempt's log starts; chunk numbering restarts at 0. */
  | { type: "attempt"; attempt: number }
  /** Raw output bytes, already masked by the runner. `id` is the resume point. */
  | { type: "chunk"; id: string; attempt: number; seq: number; data: Uint8Array }
  /** The job finished; the server closes the stream. */
  | { type: "end"; status: LogStreamJobStatus };

// A chunk is at most 256 KiB, about 350 KiB as base64 inside JSON. A longer
// line means the server or a proxy is misbehaving.
const MAX_LINE_CHARS = 1 << 20;

const STATUSES = new Set<string>(["pending", "queued", "running", "succeeded", "failed", "canceled", "skipped"]);

/** Raised when the stream violates the protocol. */
export class LogStreamError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LogStreamError";
  }
}

function isCount(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

function decodeBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Turns one dispatched SSE message into a typed event, or null to ignore it. */
export function toLogStreamEvent(event: string, data: string, id: string): LogStreamEvent | null {
  // Unknown event types are ignored, before parsing, so the server can add
  // new ones without breaking older clients.
  if (event !== "attempt" && event !== "chunk" && event !== "end") return null;
  let body: unknown;
  try {
    body = JSON.parse(data);
  } catch {
    throw new LogStreamError(`malformed ${event} event`);
  }
  if (typeof body !== "object" || body === null) throw new LogStreamError(`malformed ${event} event`);
  const b = body as Record<string, unknown>;
  switch (event) {
    case "attempt":
      if (!isCount(b.attempt)) throw new LogStreamError("malformed attempt event");
      return { type: "attempt", attempt: b.attempt };
    case "chunk": {
      if (!isCount(b.attempt) || !isCount(b.seq) || typeof b.data !== "string") throw new LogStreamError("malformed chunk event");
      let bytes: Uint8Array;
      try {
        bytes = decodeBase64(b.data);
      } catch {
        throw new LogStreamError("malformed chunk event");
      }
      return { type: "chunk", id, attempt: b.attempt, seq: b.seq, data: bytes };
    }
    case "end":
      if (typeof b.status !== "string" || !STATUSES.has(b.status)) throw new LogStreamError("malformed end event");
      return { type: "end", status: b.status as LogStreamJobStatus };
  }
}

/**
 * Parses a `text/event-stream` body (WHATWG HTML §9.2) into log events.
 * Comments (the server's keep-alive pings) and unknown events are skipped.
 */
export async function* readLogStream(body: ReadableStream<Uint8Array>, signal?: AbortSignal): AsyncGenerator<LogStreamEvent> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let event = "";
  let data: string[] = [];
  let dataChars = 0;
  let id = "";
  let lastId = "";
  let finished = false;
  const onAbort = () => {
    void reader.cancel().catch(() => undefined);
  };
  signal?.addEventListener("abort", onAbort);
  try {
    for (;;) {
      const { done, value } = await reader.read();
      buf += done ? decoder.decode() : decoder.decode(value, { stream: true });
      for (;;) {
        const nl = buf.search(/\r\n|\r|\n/);
        if (nl < 0) break;
        // A lone \r at the end of the buffer may be the first half of \r\n.
        if (buf[nl] === "\r" && nl === buf.length - 1 && !done) break;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + (buf.startsWith("\r\n", nl) ? 2 : 1));
        if (line === "") {
          if (id !== "") lastId = id;
          if (data.length > 0) {
            const ev = toLogStreamEvent(event === "" ? "message" : event, data.join("\n"), lastId);
            if (ev) yield ev;
          }
          event = "";
          data = [];
          dataChars = 0;
          id = "";
          continue;
        }
        if (line.startsWith(":")) continue;
        const colon = line.indexOf(":");
        const field = colon < 0 ? line : line.slice(0, colon);
        let value = colon < 0 ? "" : line.slice(colon + 1);
        if (value.startsWith(" ")) value = value.slice(1);
        if (field === "event") event = value;
        else if (field === "data") {
          dataChars += value.length;
          if (dataChars > MAX_LINE_CHARS) throw new LogStreamError("log stream event too large");
          data.push(value);
        }
        else if (field === "id" && !value.includes("\0")) id = value;
      }
      if (buf.length > MAX_LINE_CHARS) throw new LogStreamError("log stream line too long");
      if (done) {
        finished = true;
        return;
      }
    }
  } finally {
    signal?.removeEventListener("abort", onAbort);
    // A consumer that stops early (or an error) must not leave the
    // connection, and the server's stream slot, open.
    if (!finished) await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}
