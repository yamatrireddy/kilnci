// SPDX-License-Identifier: Apache-2.0
//
// One run: its jobs and the selected job's log. The run's title, branch, and
// actor come from the VCS event and are untrusted (a fork PR author controls
// them), so they are rendered as text only.
import type { Job, RunDetail } from "@kiln/api-client";
import { displayText, formatDateTime, formatDuration, isFinishedStatus, roleAtLeast, shortSha } from "@kiln/core";
import { IconCheck, IconPlayerStop } from "@tabler/icons-react";
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";

import { ConfirmModal } from "../components/ConfirmModal";
import { ErrorAlert } from "../components/ErrorAlert";
import { JobLog } from "../components/logs/JobLog";
import { QueryState } from "../components/QueryState";
import { StatusBadge } from "../components/StatusBadge";
import { Alert, Badge, Breadcrumbs, Button, Card, Code, cn, PageHeader, useNotify } from "../components/ui";
import { useApproveRun, useCancelRun, useOrg, useRun } from "../queries";
import { EVENT_LABELS } from "./project/RunsTable";

/** The job to show first: a running one, else a failed one, else the first. */
function defaultJob(jobs: Job[]): Job | undefined {
  return jobs.find((j) => j.status === "running") ?? jobs.find((j) => j.status === "failed") ?? jobs[0];
}

export function RunPage() {
  const { orgSlug = "", projectSlug = "", runId = "" } = useParams();
  const run = useRun(orgSlug, projectSlug, runId);
  return (
    <QueryState query={run} label="run">
      {(detail) => <RunView orgSlug={orgSlug} projectSlug={projectSlug} detail={detail} />}
    </QueryState>
  );
}

function RunView({ orgSlug, projectSlug, detail }: { orgSlug: string; projectSlug: string; detail: RunDetail }) {
  const { run, jobs } = detail;
  const [params, setParams] = useSearchParams();
  const selected = jobs.find((j) => j.id === params.get("job")) ?? defaultJob(jobs);
  const org = useOrg(orgSlug);
  // A UX hint only: the server authorizes every action.
  const canAct = org.data !== undefined && roleAtLeast(org.data.role, "developer");

  return (
    <div className="flex flex-col gap-5">
      <Breadcrumbs
        items={[
          { label: "Organizations", to: "/orgs" },
          { label: orgSlug, to: `/orgs/${orgSlug}` },
          { label: projectSlug, to: `/orgs/${orgSlug}/projects/${projectSlug}` },
          { label: `Run #${String(run.number)}` },
        ]}
      />
      <PageHeader
        title={
          <span className="flex flex-wrap items-center gap-3">
            <bdi className="break-words">{run.title ? displayText(run.title) : `Run #${String(run.number)}`}</bdi>
            <StatusBadge status={run.status} />
            {run.isFork ? <Badge color="purple">Fork</Badge> : null}
          </span>
        }
        subtitle={
          <span className="flex flex-wrap gap-x-2">
            <span>#{run.number}</span>·<bdi className="font-mono">{displayText(run.branch)}</bdi>·<Code>{shortSha(run.commitSha)}</Code>·
            <span>
              {EVENT_LABELS[run.event]}
              {run.prNumber != null ? ` #${String(run.prNumber)}` : ""} by <bdi>{displayText(run.actorLogin)}</bdi>
            </span>
            ·<time dateTime={run.createdAt}>{formatDateTime(run.createdAt)}</time>
            {run.startedAt ? <span>· {formatDuration(run.startedAt, run.finishedAt)}</span> : null}
          </span>
        }
        actions={canAct ? <RunActions orgSlug={orgSlug} projectSlug={projectSlug} detail={detail} /> : null}
      />
      {run.status === "awaiting_approval" ? (
        <Alert tone="yellow" title="Waiting for approval">
          This run comes from a fork, so its jobs will not start until a developer approves it. Review the changes
          first: approving runs code from outside your organization.
        </Alert>
      ) : null}
      {run.error ? (
        <Alert tone="red" title="The run could not start" role="alert">
          <span className="whitespace-pre-wrap break-words">{displayText(run.error)}</span>
        </Alert>
      ) : null}
      {jobs.length === 0 ? null : (
        <div className="grid gap-5 lg:grid-cols-[16rem_minmax(0,1fr)]">
          <nav aria-label="Jobs">
            <ul className="flex flex-col gap-1">
              {jobs.map((j) => {
                const current = j.id === selected?.id;
                return (
                  <li key={j.id}>
                    <Link
                      to={{ search: `?job=${encodeURIComponent(j.id)}` }}
                      replace
                      aria-current={current ? "page" : undefined}
                      onClick={(e) => {
                        e.preventDefault();
                        setParams({ job: j.id }, { replace: true });
                      }}
                      className={cn(
                        "flex items-center justify-between gap-2 rounded-md px-3 py-2 text-sm hover:bg-hover",
                        current && "bg-subtle font-semibold",
                      )}
                    >
                      <bdi className="min-w-0 truncate">{displayText(j.name)}</bdi>
                      <StatusBadge status={j.status} />
                    </Link>
                  </li>
                );
              })}
            </ul>
          </nav>
          {selected ? <JobPanel orgSlug={orgSlug} projectSlug={projectSlug} runId={run.id} job={selected} /> : null}
        </div>
      )}
    </div>
  );
}

function JobPanel({ orgSlug, projectSlug, runId, job }: { orgSlug: string; projectSlug: string; runId: string; job: Job }) {
  return (
    <Card className="flex min-w-0 flex-col gap-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="flex items-center gap-3 text-lg text-fg">
          <bdi className="break-words">{displayText(job.name)}</bdi>
          <StatusBadge status={job.status} />
        </h3>
        <span className="text-sm text-dimmed">{formatDuration(job.startedAt, job.finishedAt)}</span>
      </div>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
        <dt className="text-dimmed">Image</dt>
        <dd className="break-all font-mono">{displayText(job.image)}</dd>
        <dt className="text-dimmed">Attempt</dt>
        <dd>
          {job.attempt} of {job.maxAttempts}
        </dd>
        {job.exitCode != null ? (
          <>
            <dt className="text-dimmed">Exit code</dt>
            <dd className="font-mono">{job.exitCode}</dd>
          </>
        ) : null}
        {job.failureReason ? (
          <>
            <dt className="text-dimmed">Failure</dt>
            <dd className="break-words">{displayText(job.failureReason)}</dd>
          </>
        ) : null}
      </dl>
      <JobLog orgSlug={orgSlug} projectSlug={projectSlug} runId={runId} job={job} />
    </Card>
  );
}

function RunActions({ orgSlug, projectSlug, detail }: { orgSlug: string; projectSlug: string; detail: RunDetail }) {
  const { run } = detail;
  const cancel = useCancelRun(orgSlug, projectSlug);
  const approve = useApproveRun(orgSlug, projectSlug);
  const notify = useNotify();
  const [confirm, setConfirm] = useState<"cancel" | "approve" | null>(null);
  const action = confirm === "approve" ? approve : cancel;
  const close = () => {
    setConfirm(null);
    cancel.reset();
    approve.reset();
  };

  return (
    <>
      {run.status === "awaiting_approval" ? (
        <Button
          leftSection={<IconCheck size={16} aria-hidden />}
          onClick={() => {
            setConfirm("approve");
          }}
        >
          Approve run
        </Button>
      ) : null}
      {!isFinishedStatus(run.status) ? (
        <Button
          variant="default"
          leftSection={<IconPlayerStop size={16} aria-hidden />}
          onClick={() => {
            setConfirm("cancel");
          }}
        >
          Cancel run
        </Button>
      ) : null}
      <ConfirmModal
        opened={confirm !== null}
        title={confirm === "approve" ? "Approve run" : "Cancel run"}
        confirmLabel={confirm === "approve" ? "Approve and run" : "Cancel run"}
        loading={action.isPending}
        onClose={close}
        onConfirm={() => {
          action.mutate(run.id, {
            onSuccess: () => {
              notify({ color: "green", message: confirm === "approve" ? `Approved run #${String(run.number)}` : `Canceling run #${String(run.number)}` });
              close();
            },
          });
        }}
      >
        {confirm === "approve" ? (
          <>
            This run&apos;s jobs will execute code from a fork on your runners. Approve only after reviewing commit{" "}
            <Code className="break-all">{run.commitSha}</Code> on <bdi>{displayText(run.branch)}</bdi>.
          </>
        ) : (
          "Queued jobs stop now; running jobs stop at their runner's next heartbeat."
        )}
      </ConfirmModal>
      {action.error ? <ErrorAlert error={action.error} title={confirm === "approve" ? "Could not approve the run" : "Could not cancel the run"} /> : null}
    </>
  );
}
