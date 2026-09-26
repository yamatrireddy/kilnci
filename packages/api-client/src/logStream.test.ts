// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";

import { ApiError, createKilnClient, LogStreamError, readLogStream, type LogStreamEvent } from "./index";

const enc = new TextEncoder();

/** A body delivered in the given pieces, to exercise chunk boundaries. */
function body(...parts: string[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(c) {
      for (const p of parts) c.enqueue(enc.encode(p));
      c.close();
    },
  });
}

async function collect(it: AsyncIterable<LogStreamEvent>): Promise<LogStreamEvent[]> {
  const out: LogStreamEvent[] = [];
  for await (const ev of it) out.push(ev);
  return out;
}

const b64 = (s: string) => btoa(s);

describe("readLogStream", () => {
  it("parses attempt, chunk, and end events and skips pings", async () => {
    const events = await collect(
      readLogStream(
        body(
          'event: attempt\ndata: {"attempt":1}\n\n',
          ": ping\n\n",
          `id: 1.0\nevent: chunk\ndata: {"attempt":1,"seq":0,"data":"${b64("hi\n")}"}\n\n`,
          'event: end\ndata: {"status":"succeeded"}\n\n',
        ),
      ),
    );
    expect(events).toEqual([
      { type: "attempt", attempt: 1 },
      { type: "chunk", id: "1.0", attempt: 1, seq: 0, data: enc.encode("hi\n") },
      { type: "end", status: "succeeded" },
    ]);
  });

  it("handles events split across reads and CRLF line endings", async () => {
    const frame = `id: 2.3\r\nevent: chunk\r\ndata: {"attempt":2,"seq":3,"data":"${b64("x")}"}\r\n\r\n`;
    const parts = frame.split("");
    const events = await collect(readLogStream(body(...parts)));
    expect(events).toEqual([{ type: "chunk", id: "2.3", attempt: 2, seq: 3, data: enc.encode("x") }]);
  });

  it("ignores unknown events and a trailing partial event", async () => {
    const events = await collect(readLogStream(body('event: future\ndata: {"x":1}\n\n', 'event: end\ndata: {"status":"failed"}')));
    expect(events).toEqual([]);
  });

  const malformed: [string, string][] = [
    ["non-JSON data", "event: attempt\ndata: nope\n\n"],
    ["a negative attempt", 'event: attempt\ndata: {"attempt":-1}\n\n'],
    ["a non-object", "event: attempt\ndata: 3\n\n"],
    ["chunk data that is not base64", 'event: chunk\ndata: {"attempt":1,"seq":0,"data":"***"}\n\n'],
    ["a chunk without data", 'event: chunk\ndata: {"attempt":1,"seq":0}\n\n'],
    ["an unknown status", 'event: end\ndata: {"status":"exploded"}\n\n'],
  ];
  it.each(malformed)("rejects %s", async (_name, raw) => {
    await expect(collect(readLogStream(body(raw)))).rejects.toBeInstanceOf(LogStreamError);
  });

  it("skips unknown events even when their data is not JSON", async () => {
    expect(await collect(readLogStream(body("event: future\ndata: not-json\n\n")))).toEqual([]);
  });

  it("cancels the body when the consumer stops early", async () => {
    let canceled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(enc.encode('event: attempt\ndata: {"attempt":1}\n\n'));
      },
      cancel() {
        canceled = true;
      },
    });
    for await (const ev of readLogStream(stream)) {
      expect(ev.type).toBe("attempt");
      break;
    }
    expect(canceled).toBe(true);
  });

  it("refuses unbounded lines and events", async () => {
    await expect(collect(readLogStream(body(`data: ${"a".repeat(1 << 20)}`)))).rejects.toThrow(/too long/);
    const many = Array.from({ length: 20 }, () => `data: ${"a".repeat(60_000)}\n`).join("");
    await expect(collect(readLogStream(body(many)))).rejects.toThrow(/too large/);
  });

  it("stops when aborted", async () => {
    const ctrl = new AbortController();
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(enc.encode('event: attempt\ndata: {"attempt":1}\n\n'));
      },
    });
    const it = readLogStream(stream, ctrl.signal);
    expect((await it.next()).value).toEqual({ type: "attempt", attempt: 1 });
    const pending = it.next();
    ctrl.abort();
    expect((await pending).done).toBe(true);
  });
});

describe("streamJobLog", () => {
  const path = "/api/v1/orgs/acme/projects/web/runs/r1/jobs/j1/logs/stream";

  it("sends Last-Event-ID and the bearer token, and yields events", async () => {
    const calls: Request[] = [];
    const fetch = vi.fn((req: Request) => {
      calls.push(req);
      return Promise.resolve(new Response('event: end\ndata: {"status":"canceled"}\n\n', { headers: { "Content-Type": "text/event-stream" } }));
    });
    const c = createKilnClient({ baseUrl: "https://kiln.test", auth: { kind: "bearer", getAccessToken: () => Promise.resolve("t0k") }, fetch: fetch as unknown as typeof globalThis.fetch });
    const events = await collect(c.streamJobLog("acme", "web", "r1", "j1", { lastEventId: "1.4" }));
    expect(events).toEqual([{ type: "end", status: "canceled" }]);
    expect(new URL(calls[0]?.url ?? "").pathname).toBe(path);
    expect(calls[0]?.headers.get("Last-Event-ID")).toBe("1.4");
    expect(calls[0]?.headers.get("Authorization")).toBe("Bearer t0k");
  });

  it("throws ApiError with the problem on failure", async () => {
    const problem = { type: "urn:kiln:problem:rate-limited", title: "Too many", status: 429, requestId: "r" };
    const fetch = vi.fn(() => Promise.resolve(new Response(JSON.stringify(problem), { status: 429, headers: { "Content-Type": "application/problem+json" } })));
    const c = createKilnClient({ baseUrl: "https://kiln.test", auth: { kind: "session" }, fetch: fetch });
    const err: unknown = await collect(c.streamJobLog("acme", "web", "r1", "j1")).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(429);
    expect((err as ApiError).retryAfter).toBeUndefined();
  });

  it("exposes Retry-After", async () => {
    const fetch = vi.fn(() => Promise.resolve(new Response("", { status: 503, headers: { "Retry-After": "12" } })));
    const c = createKilnClient({ baseUrl: "https://kiln.test", auth: { kind: "session" }, fetch: fetch });
    const err: unknown = await collect(c.streamJobLog("acme", "web", "r1", "j1")).catch((e: unknown) => e);
    expect((err as ApiError).retryAfter).toBe(12);
  });

  it("rejects a response that is not an event stream", async () => {
    const fetch = vi.fn(() => Promise.resolve(new Response("<html>", { headers: { "Content-Type": "text/html" } })));
    const c = createKilnClient({ baseUrl: "https://kiln.test", auth: { kind: "session" }, fetch: fetch });
    await expect(collect(c.streamJobLog("acme", "web", "r1", "j1"))).rejects.toBeInstanceOf(LogStreamError);
  });

  it("refuses path traversal in ids before any request", async () => {
    const fetch = vi.fn();
    const c = createKilnClient({ baseUrl: "https://kiln.test", auth: { kind: "session" }, fetch: fetch });
    await expect(collect(c.streamJobLog("acme", "web", "..", "j1"))).rejects.toBeInstanceOf(ApiError);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("run helpers", () => {
  it("calls the run endpoints and returns the stored log as text", async () => {
    const calls: Request[] = [];
    const responses = [
      new Response(JSON.stringify({ items: [] }), { headers: { "Content-Type": "application/json" } }),
      new Response(JSON.stringify({ run: {}, jobs: [] }), { headers: { "Content-Type": "application/json" } }),
      new Response(JSON.stringify({ run: {}, jobs: [] }), { headers: { "Content-Type": "application/json" } }),
      new Response(JSON.stringify({ run: {}, jobs: [] }), { headers: { "Content-Type": "application/json" } }),
      new Response("\x1b[31mred\x1b[0m\n", { headers: { "Content-Type": "text/plain; charset=utf-8" } }),
    ];
    const fetch = vi.fn((req: Request) => {
      calls.push(req);
      const r = responses.shift();
      if (!r) throw new Error("unexpected request");
      return Promise.resolve(r);
    });
    const c = createKilnClient({ baseUrl: "https://kiln.test", auth: { kind: "session" }, fetch: fetch as unknown as typeof globalThis.fetch });
    await c.listRuns("acme", "web", { limit: 20 });
    await c.getRun("acme", "web", "r1");
    await c.cancelRun("acme", "web", "r1");
    await c.approveRun("acme", "web", "r1");
    expect(await c.getJobLog("acme", "web", "r1", "j1")).toBe("\x1b[31mred\x1b[0m\n");
    expect(calls.map((r) => `${r.method} ${new URL(r.url).pathname}${new URL(r.url).search}`)).toEqual([
      "GET /api/v1/orgs/acme/projects/web/runs?limit=20",
      "GET /api/v1/orgs/acme/projects/web/runs/r1",
      "POST /api/v1/orgs/acme/projects/web/runs/r1/cancel",
      "POST /api/v1/orgs/acme/projects/web/runs/r1/approve",
      "GET /api/v1/orgs/acme/projects/web/runs/r1/jobs/j1/logs",
    ]);
  });
});
