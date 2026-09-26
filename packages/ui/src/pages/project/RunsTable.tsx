// SPDX-License-Identifier: Apache-2.0
import type { Run } from "@kiln/api-client";
import { displayText, formatDateTime, formatDuration, formatRelative, shortSha } from "@kiln/core";

import { EmptyState, QueryState } from "../../components/QueryState";
import { StatusBadge } from "../../components/StatusBadge";
import { Button, Code, Table, Td, TextLink, Th } from "../../components/ui";
import { useRuns } from "../../queries";

export const EVENT_LABELS: Record<Run["event"], string> = {
  push: "Push",
  pull_request: "Pull request",
  manual: "Manual",
};

/** A project's runs, newest first. Titles and branches are untrusted text. */
export function RunsTable({ orgSlug, projectSlug }: { orgSlug: string; projectSlug: string }) {
  const runs = useRuns(orgSlug, projectSlug);
  return (
    <QueryState
      query={runs}
      label="runs"
      isEmpty={(d) => d.pages.every((p) => p.items.length === 0)}
      empty={
        <EmptyState
          title="No runs yet"
          description="Runs start when you push to the linked repository or open a pull request. Add a .kiln/pipeline.yaml to get started."
        />
      }
    >
      {(data) => (
        <div className="flex flex-col gap-4">
          <Table highlightOnHover>
            <thead>
              <tr>
                <Th>Run</Th>
                <Th>Status</Th>
                <Th>Branch</Th>
                <Th>Commit</Th>
                <Th>Trigger</Th>
                <Th>Started</Th>
                <Th>Duration</Th>
              </tr>
            </thead>
            <tbody>
              {data.pages.flatMap((p) =>
                p.items.map((r) => (
                  <tr key={r.id}>
                    <Td className="max-w-md">
                      <TextLink to={`/orgs/${orgSlug}/projects/${projectSlug}/runs/${r.id}`} className="font-medium">
                        #{r.number}
                      </TextLink>{" "}
                      <bdi className="break-words">{displayText(r.title)}</bdi>
                    </Td>
                    <Td>
                      <StatusBadge status={r.status} />
                    </Td>
                    <Td className="max-w-48 truncate font-mono text-xs" title={displayText(r.branch)}>
                      <bdi>{displayText(r.branch)}</bdi>
                    </Td>
                    <Td>
                      <Code>{shortSha(r.commitSha)}</Code>
                    </Td>
                    <Td className="whitespace-nowrap text-dimmed">
                      {EVENT_LABELS[r.event]}
                      {r.isFork ? " (fork)" : ""} by <bdi>{displayText(r.actorLogin)}</bdi>
                    </Td>
                    <Td className="whitespace-nowrap text-dimmed">
                      <time dateTime={r.createdAt} title={formatDateTime(r.createdAt)}>
                        {formatRelative(r.createdAt)}
                      </time>
                    </Td>
                    <Td className="whitespace-nowrap text-dimmed">{formatDuration(r.startedAt, r.finishedAt)}</Td>
                  </tr>
                )),
              )}
            </tbody>
          </Table>
          {runs.hasNextPage ? (
            <div className="flex justify-center">
              <Button
                variant="default"
                loading={runs.isFetchingNextPage}
                onClick={() => {
                  void runs.fetchNextPage();
                }}
              >
                Load more runs
              </Button>
            </div>
          ) : null}
        </div>
      )}
    </QueryState>
  );
}
