// SPDX-License-Identifier: Apache-2.0
import { ApiError, type LogStreamEvent } from "@kiln/api-client";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { RENDER_LINES, spanClass } from "./components/logs/LogViewer";
import { MAX_STREAM_FAILURES } from "./components/logs/useLiveJobLog";
import { acme, axeViolations, chunk, fakeClient, problem, renderApp, run1, runDetail, streamOf } from "./test/harness";

const runPath = `/orgs/acme/projects/web/runs/${run1.id}`;
const live = { liveLogs: true };

function logRegion(name = "Log for build") {
  return screen.findByRole("region", { name });
}

describe("runs list", () => {
  it("neutralizes bidi overrides in branch names", async () => {
    renderApp("/orgs/acme/projects/web", fakeClient({ listRuns: () => Promise.resolve({ items: [{ ...run1, branch: "\u202Eniam" }] }) }));
    expect(await screen.findByText("\ufffdniam")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("\u202E");
  });

  it("lists runs with untrusted text rendered as text", async () => {
    renderApp("/orgs/acme/projects/web");
    const link = await screen.findByRole("link", { name: "#42" });
    expect(link).toHaveAttribute("href", runPath);
    expect(screen.getByText(/Fix the <script>alert\(1\)<\/script> bug/)).toBeInTheDocument();
    expect(screen.getByText("feature/<b>bold</b>")).toBeInTheDocument();
    expect(document.querySelector("script, b")).toBeNull();
    expect(screen.getByText("0123456")).toBeInTheDocument();
    expect(screen.getByText("octocat").closest("td")).toHaveTextContent("Pull request (fork) by octocat");
  });

  it("shows an empty state", async () => {
    renderApp("/orgs/acme/projects/web", fakeClient({ listRuns: () => Promise.resolve({ items: [] }) }));
    expect(await screen.findByText("No runs yet")).toBeInTheDocument();
  });

  it("loads the next page with the cursor", async () => {
    const listRuns = vi.fn((_o: string, _p: string, q: { cursor?: string }) =>
      Promise.resolve(q.cursor ? { items: [{ ...run1, id: "01ARZ3NDEKTSV4RRFFQ69G5FB2", number: 41 }] } : { items: [run1], nextCursor: "c1" }),
    );
    renderApp("/orgs/acme/projects/web", fakeClient({ listRuns }));
    await userEvent.click(await screen.findByRole("button", { name: "Load more runs" }));
    expect(await screen.findByRole("link", { name: "#41" })).toBeInTheDocument();
    expect(listRuns).toHaveBeenLastCalledWith("acme", "web", { limit: 25, cursor: "c1" });
    expect(screen.queryByRole("button", { name: "Load more runs" })).toBeNull();
  });

  it("does not disclose whether another org's project exists", async () => {
    renderApp("/orgs/acme/projects/web", fakeClient({ listRuns: () => Promise.reject(problem(404)) }));
    expect(await screen.findByText(/does not exist, or you do not have access/)).toBeInTheDocument();
  });
});

describe("run page", () => {
  it("selects the running job and lists every job", async () => {
    renderApp(runPath);
    const nav = await screen.findByRole("navigation", { name: "Jobs" });
    expect(within(nav).getAllByRole("link").map((l) => l.textContent)).toEqual(["lintSucceeded", "buildRunning", "deployPending"]);
    expect(within(nav).getByRole("link", { name: /build/ })).toHaveAttribute("aria-current", "page");
    expect(await logRegion()).toHaveTextContent("ok stored");
    expect(screen.getByText("Fork")).toBeInTheDocument();
  });

  it("switches jobs through the URL", async () => {
    const { router } = renderApp(runPath);
    await userEvent.click(await screen.findByRole("link", { name: /deploy/ }));
    expect(router.state.location.search).toBe("?job=01ARZ3NDEKTSV4RRFFQ69G5FC3");
    expect(await logRegion("Log for deploy")).toHaveTextContent("Waiting for the jobs this one needs.");
  });

  it("shows why a run failed before any job ran", async () => {
    renderApp(runPath, fakeClient({ getRun: () => Promise.resolve({ run: { ...run1, status: "failed", error: "pipeline.yaml: line 3: unknown key" }, jobs: [] }) }));
    expect(await screen.findByRole("alert")).toHaveTextContent("unknown key");
  });

  it("returns 404 text for a run the user cannot see", async () => {
    renderApp(runPath, fakeClient({ getRun: () => Promise.reject(problem(404)) }));
    expect(await screen.findByText(/does not exist, or you do not have access/)).toBeInTheDocument();
  });

  it("confirms before canceling", async () => {
    const { client } = renderApp(runPath);
    await userEvent.click(await screen.findByRole("button", { name: "Cancel run" }));
    const dialog = await screen.findByRole("dialog", { name: "Cancel run" });
    expect(client.cancelRun).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel run" }));
    await waitFor(() => {
      expect(client.cancelRun).toHaveBeenCalledWith("acme", "web", run1.id);
    });
    expect(await screen.findByText("Canceling run #42")).toBeInTheDocument();
  });

  it("warns before approving a fork run", async () => {
    const client = fakeClient({ getRun: () => Promise.resolve({ ...runDetail, run: { ...run1, status: "awaiting_approval" } }) });
    renderApp(runPath, client);
    expect(await screen.findByText("Waiting for approval")).toBeInTheDocument();
    await userEvent.click(await screen.findByRole("button", { name: "Approve run" }));
    const dialog = await screen.findByRole("dialog", { name: "Approve run" });
    expect(dialog).toHaveTextContent(/code from a fork/);
    await userEvent.click(within(dialog).getByRole("button", { name: "Approve and run" }));
    await waitFor(() => {
      expect(client.approveRun).toHaveBeenCalledWith("acme", "web", run1.id);
    });
  });

  it("shows the server's refusal", async () => {
    renderApp(runPath, fakeClient({ cancelRun: () => Promise.reject(problem(409)) }));
    await userEvent.click(await screen.findByRole("button", { name: "Cancel run" }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Cancel run" }));
    expect(await screen.findByText("Could not cancel the run")).toBeInTheDocument();
  });

  it("hides run actions from viewers", async () => {
    renderApp(runPath, fakeClient({ getOrg: () => Promise.resolve({ ...acme, role: "viewer" }) }));
    await screen.findByRole("navigation", { name: "Jobs" });
    expect(screen.queryByRole("button", { name: "Cancel run" })).toBeNull();
  });

  it("passes axe with a live log", async () => {
    renderApp(runPath, fakeClient(), live);
    await screen.findByText("Job failed.");
    expect(await axeViolations()).toEqual([]);
  });
});

describe("live log", () => {
  it("renders colors as classes and ends with the job status", async () => {
    const { client } = renderApp(runPath, fakeClient(), live);
    const region = await logRegion();
    await waitFor(() => {
      expect(region).toHaveTextContent("FAIL live");
    });
    const fail = within(region).getByText("FAIL");
    expect(fail).toHaveClass("text-red-400", "font-bold");
    expect(fail.getAttribute("style")).toBeNull();
    expect(await screen.findByText("Job failed.")).toBeInTheDocument();
    expect(client.streamJobLog).toHaveBeenCalledWith("acme", "web", run1.id, "01ARZ3NDEKTSV4RRFFQ69G5FC2", expect.objectContaining({ signal: expect.any(AbortSignal) as unknown }));
    expect(client.getJobLog).not.toHaveBeenCalled();
  });

  // T-09: hostile output stays inert text.
  it("never turns log bytes into markup, links, or styles", async () => {
    const hostile = [
      '<img src=x onerror="alert(1)"><script>alert(2)</script>\n',
      "\x1b]8;;javascript:alert(3)\x07click me\x1b]8;;\x07\n",
      "\x1b]0;title\x07\x1b[2J\x1b[H‮evil\n",
    ].join("");
    const client = fakeClient({ streamJobLog: vi.fn(streamOf({ type: "attempt", attempt: 1 }, chunk(1, 0, hostile), { type: "end", status: "succeeded" })) });
    renderApp(runPath, client, live);
    const region = await logRegion();
    await waitFor(() => {
      expect(region).toHaveTextContent("click me");
    });
    expect(region.querySelector("img, script, a, [style], [href], [onerror]")).toBeNull();
    expect(region).toHaveTextContent('<img src=x onerror="alert(1)"><script>alert(2)</script>');
    expect(region.textContent).not.toContain("javascript:");
    expect(region.textContent).not.toContain("title");
    expect(region.textContent).toContain("�evil");
  });

  it("resumes from the last chunk after the stream closes", async () => {
    const calls: (string | undefined)[] = [];
    const streams: LogStreamEvent[][] = [
      [{ type: "attempt", attempt: 1 }, chunk(1, 0, "one\n"), chunk(1, 1, "two\n")],
      [{ type: "attempt", attempt: 1 }, chunk(1, 2, "three\n"), { type: "end", status: "succeeded" }],
    ];
    const streamJobLog = vi.fn(async function* (_o: string, _p: string, _r: string, _j: string, opts: { lastEventId?: string }) {
      calls.push(opts.lastEventId);
      await Promise.resolve();
      yield* streams.shift() ?? [];
    });
    renderApp(runPath, fakeClient({ streamJobLog }), live);
    const region = await logRegion();
    await waitFor(
      () => {
        expect(region).toHaveTextContent("three");
      },
      { timeout: 4000 },
    );
    expect(region).toHaveTextContent(/one.*two.*three/);
    expect(calls).toEqual([undefined, "1.1"]);
    expect(await screen.findByText("Job succeeded.")).toBeInTheDocument();
  });

  it("starts over when the job begins a new attempt", async () => {
    const client = fakeClient({
      streamJobLog: vi.fn(
        streamOf({ type: "attempt", attempt: 1 }, chunk(1, 0, "first try\n"), { type: "attempt", attempt: 2 }, chunk(2, 0, "second try\n"), chunk(1, 1, "stale\n"), {
          type: "end",
          status: "succeeded",
        }),
      ),
    });
    renderApp(runPath, client, live);
    const region = await logRegion();
    await waitFor(() => {
      expect(region).toHaveTextContent("second try");
    });
    expect(region).not.toHaveTextContent("first try");
    expect(region).not.toHaveTextContent("stale");
  });

  it("stops on a final error and retries on request", async () => {
    let fail = true;
    const streamJobLog = vi.fn(async function* () {
      await Promise.resolve();
      if (fail) throw problem(404);
      yield* [{ type: "attempt", attempt: 1 }, chunk(1, 0, "back\n")] as LogStreamEvent[];
    });
    renderApp(runPath, fakeClient({ streamJobLog }), live);
    expect(await screen.findByText("Could not load the log")).toBeInTheDocument();
    expect(streamJobLog).toHaveBeenCalledTimes(1);
    fail = false;
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await logRegion()).toHaveTextContent("back");
  });

  it("backs off on server errors and gives up after repeated failures", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const streamJobLog = vi.fn(async function* () {
        await Promise.resolve();
        throw new ApiError(503, undefined);
        yield* [] as LogStreamEvent[];
      });
      renderApp(runPath, fakeClient({ streamJobLog }), live);
      expect(await screen.findByText(/Reconnecting/)).toBeInTheDocument();
      for (let i = 0; i < MAX_STREAM_FAILURES; i++) {
        await act(async () => {
          await vi.advanceTimersByTimeAsync(31_000);
        });
      }
      expect(await screen.findByText("Could not load the log")).toBeInTheDocument();
      expect(streamJobLog).toHaveBeenCalledTimes(MAX_STREAM_FAILURES);
    } finally {
      vi.useRealTimers();
    }
  });

  it("backs off when streams close right after the attempt event", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const streamJobLog = vi.fn(streamOf({ type: "attempt", attempt: 1 }));
      renderApp(runPath, fakeClient({ streamJobLog }), live);
      await screen.findByText(/Reconnecting/);
      for (let i = 0; i < MAX_STREAM_FAILURES; i++) {
        await act(async () => {
          await vi.advanceTimersByTimeAsync(31_000);
        });
      }
      expect(await screen.findByText("Could not load the log")).toBeInTheDocument();
      expect(streamJobLog).toHaveBeenCalledTimes(MAX_STREAM_FAILURES);
    } finally {
      vi.useRealTimers();
    }
  });

  it("waits as long as Retry-After asks", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const streamJobLog = vi.fn(async function* () {
        await Promise.resolve();
        throw new ApiError(429, undefined, 60);
        yield* [] as LogStreamEvent[];
      });
      renderApp(runPath, fakeClient({ streamJobLog }), live);
      await screen.findByText(/Reconnecting/);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(30_000);
      });
      expect(streamJobLog).toHaveBeenCalledTimes(1);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(31_000);
      });
      expect(streamJobLog).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("renders a bounded number of lines for a huge log", async () => {
    const big = `${Array.from({ length: 5000 }, (_, i) => `\x1b[31mr\x1b[32mg line ${String(i)}`).join("\n")}\n`;
    const client = fakeClient({ streamJobLog: vi.fn(streamOf({ type: "attempt", attempt: 1 }, chunk(1, 0, big), { type: "end", status: "running" })) });
    renderApp(runPath, client, live);
    const region = await logRegion();
    await waitFor(() => {
      expect(region).toHaveTextContent("line 4999");
    });
    expect(region.querySelectorAll("span").length).toBeLessThan(4 * RENDER_LINES + 100);
    await userEvent.click(within(region).getByRole("button", { name: /Show 2,000 earlier lines/ }));
    expect(region).toHaveTextContent("line 2999");
    expect(screen.getByRole("button", { name: "Cancel run" })).toBeEnabled();
  });

  it("shows a waiting message instead of streaming a queued job", async () => {
    const client = fakeClient({ getRun: () => Promise.resolve({ ...runDetail, jobs: runDetail.jobs.map((j) => ({ ...j, status: "queued" as const })) }) });
    renderApp(runPath, client, live);
    expect(await logRegion("Log for lint")).toHaveTextContent("Waiting for a runner");
    expect(client.streamJobLog).not.toHaveBeenCalled();
  });
});

describe("stored log (no streaming)", () => {
  it("offers a manual refresh while the job runs", async () => {
    const { client } = renderApp(runPath);
    await userEvent.click(await screen.findByRole("button", { name: "Refresh now" }));
    await waitFor(() => {
      expect(client.getJobLog).toHaveBeenCalledTimes(2);
    });
  });

  it("reads the stored log and says when a finished job printed nothing", async () => {
    const client = fakeClient({ getJobLog: vi.fn(() => Promise.resolve("")) });
    renderApp(`${runPath}?job=01ARZ3NDEKTSV4RRFFQ69G5FC1`, client);
    expect(await logRegion("Log for lint")).toHaveTextContent("This job produced no output.");
    expect(client.getJobLog).toHaveBeenCalledWith("acme", "web", run1.id, "01ARZ3NDEKTSV4RRFFQ69G5FC1");
    expect(client.streamJobLog).not.toHaveBeenCalled();
  });

  it("shows an error when the log cannot be read", async () => {
    renderApp(runPath, fakeClient({ getJobLog: () => Promise.reject(problem(429)) }));
    expect(await screen.findByText(/Too many requests/)).toBeInTheDocument();
  });
});

describe("spanClass", () => {
  it("maps styles to fixed classes, including inverse video", () => {
    expect(spanClass({})).toBe("");
    expect(spanClass({ fg: 9, bg: 4, italic: true, underline: true, strike: true, dim: true })).toBe(
      "text-red-300 bg-blue-900 opacity-70 italic underline line-through",
    );
    expect(spanClass({ inverse: true })).toBe("text-gray-950 bg-gray-100");
    expect(spanClass({ inverse: true, fg: 1, bg: 2 })).toBe("text-green-400 bg-red-900");
  });
});
