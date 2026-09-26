// SPDX-License-Identifier: Apache-2.0
//
// @kiln/api-client: the only way web, desktop, and mobile talk to the Kiln API
// (coding-standards §11). Types are generated from docs/api/openapi.yaml; this
// file adds authentication handling and unwraps responses into values or
// ApiError. It contains no business logic or authorization decisions: the
// server is the only enforcement point (CLAUDE.md invariant 6).
import createClient, { type Middleware } from "openapi-fetch";

import type { components, paths } from "./gen/schema";
import { LogStreamError, readLogStream, type LogStreamEvent } from "./logStream";

export { LogStreamError, readLogStream, toLogStreamEvent, type LogStreamEvent, type LogStreamJobStatus } from "./logStream";

export type Schemas = components["schemas"];
export type Problem = Schemas["Problem"];
export type Session = Schemas["Session"];
export type User = Schemas["User"];
export type Org = Schemas["Org"];
export type OrgCreate = Schemas["OrgCreate"];
export type Member = Schemas["Member"];
export type MemberAdd = Schemas["MemberAdd"];
export type Role = Schemas["Role"];
export type Project = Schemas["Project"];
export type ProjectCreate = Schemas["ProjectCreate"];
export type AuditEvent = Schemas["AuditEvent"];
export type APIToken = Schemas["APIToken"];
export type APITokenCreate = Schemas["APITokenCreate"];
export type APITokenCreated = Schemas["APITokenCreated"];
export type Permission = Schemas["Permission"];
export type Run = Schemas["Run"];
export type RunStatus = Schemas["RunStatus"];
export type RunDetail = Schemas["RunDetail"];
export type Job = Schemas["Job"];
export type JobStatus = Schemas["JobStatus"];
export type TokenRequest = Schemas["TokenRequest"];
export type TokenResponse = Schemas["TokenResponse"];
export type { components, paths };

/** A page of results with an opaque cursor for the next page. */
export interface Page<T> {
  items: T[];
  nextCursor?: string | null;
}

export interface PageParams {
  cursor?: string;
  limit?: number;
}

/**
 * How requests are authenticated.
 * - `session`: browser cookie session (web). Unsafe requests carry the CSRF
 *   token obtained from GET /api/v1/session.
 * - `bearer`: short-lived access token (desktop), fetched per request so the
 *   caller can refresh it.
 */
export type AuthMode =
  | { kind: "session" }
  | { kind: "bearer"; getAccessToken: () => Promise<string | null> };

export interface KilnClientOptions {
  /** Origin of the Kiln server, e.g. "https://kiln.example.com". Empty for same-origin. */
  baseUrl: string;
  auth: AuthMode;
  /** Called when the server answers 401, e.g. to redirect to sign-in. */
  onUnauthenticated?: () => void;
  fetch?: typeof globalThis.fetch;
}

/** An API failure carrying the RFC 9457 problem body when the server sent one. */
export class ApiError extends Error {
  readonly status: number;
  readonly problem: Problem | undefined;
  /** Seconds the server asked the client to wait (Retry-After), if any. */
  readonly retryAfter: number | undefined;

  constructor(status: number, problem: Problem | undefined, retryAfter?: number) {
    super(problem?.title ?? `Request failed with status ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.problem = problem;
    this.retryAfter = retryAfter;
  }

  /** Field errors for form display, keyed by field name. */
  fieldErrors(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const e of this.problem?.errors ?? []) out[e.field] = e.message;
    return out;
  }
}

/** Parses a delta-seconds Retry-After header (HTTP dates are ignored). */
function retryAfterSeconds(res: Response): number | undefined {
  const v = res.headers.get("Retry-After");
  if (v === null || !/^[0-9]{1,6}$/.test(v)) return undefined;
  return Number(v);
}

const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * Validates a path parameter. Route params come from the URL bar, and "." or
 * ".." would be normalized away by URL parsing, silently targeting a different
 * endpoint (security review, info). The server validates again.
 */
export function pathParam(value: string): string {
  if (value === "" || value === "." || value === ".." || value.includes("/") || value.includes("\\")) {
    throw new ApiError(404, undefined);
  }
  return value;
}

function isProblem(v: unknown): v is Problem {
  return typeof v === "object" && v !== null && "type" in v && "status" in v && "title" in v;
}

/** The result shape openapi-fetch returns. */
interface FetchResult<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

async function unwrap<T>(p: Promise<FetchResult<T>>): Promise<T> {
  const { data, error, response } = await p;
  if (!response.ok) {
    throw new ApiError(response.status, isProblem(error) ? error : undefined);
  }
  return data as T;
}

async function unwrapEmpty(p: Promise<FetchResult<unknown>>): Promise<void> {
  const { error, response } = await p;
  if (!response.ok) {
    throw new ApiError(response.status, isProblem(error) ? error : undefined);
  }
}

/** Creates a typed Kiln API client. */
export function createKilnClient(opts: KilnClientOptions) {
  let csrfToken: string | undefined;

  const raw = createClient<paths>({
    baseUrl: opts.baseUrl,
    // Cookies are only ever sent same-origin; bearer clients never send cookies.
    credentials: opts.auth.kind === "session" ? "same-origin" : "omit",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });

  const auth: Middleware = {
    async onRequest({ request }) {
      if (opts.auth.kind === "session") {
        if (UNSAFE_METHODS.has(request.method) && csrfToken) {
          request.headers.set("X-CSRF-Token", csrfToken);
        }
      } else {
        const token = await opts.auth.getAccessToken();
        if (token) request.headers.set("Authorization", `Bearer ${token}`);
      }
      return request;
    },
    onResponse({ response }) {
      if (response.status === 401) opts.onUnauthenticated?.();
      return response;
    },
  };
  raw.use(auth);

  return {
    /** The underlying openapi-fetch client, for operations without a helper. */
    raw,

    async getSession(): Promise<Session> {
      const s = await unwrap(raw.GET("/api/v1/session"));
      csrfToken = s.csrfToken;
      return s;
    },
    async signOut(): Promise<void> {
      await unwrapEmpty(raw.DELETE("/api/v1/session"));
      csrfToken = undefined;
    },
    async exchangeToken(body: TokenRequest): Promise<TokenResponse> {
      return unwrap(raw.POST("/api/v1/auth/token", { body }));
    },

    async listOrgs(query: PageParams = {}): Promise<Page<Org>> {
      return unwrap(raw.GET("/api/v1/orgs", { params: { query } }));
    },
    async createOrg(body: OrgCreate): Promise<Org> {
      return unwrap(raw.POST("/api/v1/orgs", { body }));
    },
    async getOrg(orgSlug: string): Promise<Org> {
      return unwrap(raw.GET("/api/v1/orgs/{orgSlug}", { params: { path: { orgSlug: pathParam(orgSlug) } } }));
    },

    async listMembers(orgSlug: string, query: PageParams = {}): Promise<Page<Member>> {
      return unwrap(raw.GET("/api/v1/orgs/{orgSlug}/members", { params: { path: { orgSlug: pathParam(orgSlug) }, query } }));
    },
    async addMember(orgSlug: string, body: MemberAdd): Promise<Member> {
      return unwrap(raw.POST("/api/v1/orgs/{orgSlug}/members", { params: { path: { orgSlug: pathParam(orgSlug) } }, body }));
    },
    async updateMember(orgSlug: string, userId: string, role: Role): Promise<Member> {
      return unwrap(
        raw.PUT("/api/v1/orgs/{orgSlug}/members/{userId}", {
          params: { path: { orgSlug: pathParam(orgSlug), userId: pathParam(userId) } },
          body: { role },
        }),
      );
    },
    async removeMember(orgSlug: string, userId: string): Promise<void> {
      return unwrapEmpty(raw.DELETE("/api/v1/orgs/{orgSlug}/members/{userId}", { params: { path: { orgSlug: pathParam(orgSlug), userId: pathParam(userId) } } }));
    },

    async listProjects(orgSlug: string, query: PageParams = {}): Promise<Page<Project>> {
      return unwrap(raw.GET("/api/v1/orgs/{orgSlug}/projects", { params: { path: { orgSlug: pathParam(orgSlug) }, query } }));
    },
    async createProject(orgSlug: string, body: ProjectCreate): Promise<Project> {
      return unwrap(raw.POST("/api/v1/orgs/{orgSlug}/projects", { params: { path: { orgSlug: pathParam(orgSlug) } }, body }));
    },
    async getProject(orgSlug: string, projectSlug: string): Promise<Project> {
      return unwrap(
        raw.GET("/api/v1/orgs/{orgSlug}/projects/{projectSlug}", { params: { path: { orgSlug: pathParam(orgSlug), projectSlug: pathParam(projectSlug) } } }),
      );
    },

    async listAuditEvents(orgSlug: string, query: PageParams = {}): Promise<Page<AuditEvent>> {
      return unwrap(raw.GET("/api/v1/orgs/{orgSlug}/audit-events", { params: { path: { orgSlug: pathParam(orgSlug) }, query } }));
    },

    async listRuns(orgSlug: string, projectSlug: string, query: PageParams = {}): Promise<Page<Run>> {
      return unwrap(
        raw.GET("/api/v1/orgs/{orgSlug}/projects/{projectSlug}/runs", {
          params: { path: { orgSlug: pathParam(orgSlug), projectSlug: pathParam(projectSlug) }, query },
        }),
      );
    },
    async getRun(orgSlug: string, projectSlug: string, runId: string): Promise<RunDetail> {
      return unwrap(
        raw.GET("/api/v1/orgs/{orgSlug}/projects/{projectSlug}/runs/{runId}", {
          params: { path: { orgSlug: pathParam(orgSlug), projectSlug: pathParam(projectSlug), runId: pathParam(runId) } },
        }),
      );
    },
    async cancelRun(orgSlug: string, projectSlug: string, runId: string): Promise<RunDetail> {
      return unwrap(
        raw.POST("/api/v1/orgs/{orgSlug}/projects/{projectSlug}/runs/{runId}/cancel", {
          params: { path: { orgSlug: pathParam(orgSlug), projectSlug: pathParam(projectSlug), runId: pathParam(runId) } },
        }),
      );
    },
    async approveRun(orgSlug: string, projectSlug: string, runId: string): Promise<RunDetail> {
      return unwrap(
        raw.POST("/api/v1/orgs/{orgSlug}/projects/{projectSlug}/runs/{runId}/approve", {
          params: { path: { orgSlug: pathParam(orgSlug), projectSlug: pathParam(projectSlug), runId: pathParam(runId) } },
        }),
      );
    },

    /**
     * A job's stored log (latest attempt) as text. It is untrusted terminal
     * output: render it only through the sanitizing log viewer.
     */
    async getJobLog(orgSlug: string, projectSlug: string, runId: string, jobId: string): Promise<string> {
      return unwrap(
        raw.GET("/api/v1/orgs/{orgSlug}/projects/{projectSlug}/runs/{runId}/jobs/{jobId}/logs", {
          params: { path: { orgSlug: pathParam(orgSlug), projectSlug: pathParam(projectSlug), runId: pathParam(runId), jobId: pathParam(jobId) } },
          parseAs: "text",
        }),
      );
    },

    /**
     * Follows a job's log as Server-Sent Events (ADR-0007). Pass the last
     * chunk `id` seen as `lastEventId` to resume after a disconnect. The
     * generator ends when the server closes the stream (after an `end` event,
     * or at the server's maximum stream duration); abort `signal` to stop.
     * Needs a streaming `fetch`; the desktop IPC fetch buffers whole bodies.
     */
    async *streamJobLog(
      orgSlug: string,
      projectSlug: string,
      runId: string,
      jobId: string,
      opts: { lastEventId?: string; signal?: AbortSignal } = {},
    ): AsyncGenerator<LogStreamEvent> {
      const { data, error, response } = await raw.GET("/api/v1/orgs/{orgSlug}/projects/{projectSlug}/runs/{runId}/jobs/{jobId}/logs/stream", {
        params: {
          path: { orgSlug: pathParam(orgSlug), projectSlug: pathParam(projectSlug), runId: pathParam(runId), jobId: pathParam(jobId) },
          header: opts.lastEventId ? { "Last-Event-ID": opts.lastEventId } : {},
        },
        headers: { Accept: "text/event-stream" },
        parseAs: "stream",
        ...(opts.signal ? { signal: opts.signal } : {}),
      });
      if (!response.ok) throw new ApiError(response.status, isProblem(error) ? error : undefined, retryAfterSeconds(response));
      if (!data) return;
      if (!(response.headers.get("Content-Type") ?? "").startsWith("text/event-stream")) {
        await data.cancel();
        throw new LogStreamError("expected an event stream");
      }
      yield* readLogStream(data, opts.signal);
    },

    async listTokens(): Promise<Page<APIToken>> {
      return unwrap(raw.GET("/api/v1/tokens"));
    },
    async createToken(body: APITokenCreate): Promise<APITokenCreated> {
      return unwrap(raw.POST("/api/v1/tokens", { body }));
    },
    async revokeToken(tokenId: string): Promise<void> {
      return unwrapEmpty(raw.DELETE("/api/v1/tokens/{tokenId}", { params: { path: { tokenId: pathParam(tokenId) } } }));
    },
  };
}

export type KilnClient = ReturnType<typeof createKilnClient>;
