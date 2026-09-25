// SPDX-License-Identifier: Apache-2.0
import type { Org } from "@kiln/api-client";
import { formatDateTime, formatRelative } from "@kiln/core";

import { QueryState } from "../../components/QueryState";
import { Badge, Code, Table, Td, Th, Tooltip } from "../../components/ui";
import { useAuditEvents } from "../../queries";

export function AuditTab({ org }: { org: Org }) {
  const events = useAuditEvents(org.slug, true);
  return (
    <QueryState query={events} label="audit events" isEmpty={(d) => d.items.length === 0}>
      {(data) => (
        <Table dense>
          <thead>
            <tr>
              <Th>When</Th>
              <Th>Action</Th>
              <Th>Actor</Th>
              <Th>Target</Th>
              <Th>Result</Th>
              <Th>Source</Th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((e) => (
              <tr key={e.id}>
                <Td className="whitespace-nowrap">
                  <Tooltip label={formatDateTime(e.occurredAt)}>
                    <FocusableTime dateTime={e.occurredAt}>{formatRelative(e.occurredAt)}</FocusableTime>
                  </Tooltip>
                </Td>
                <Td className="whitespace-nowrap">
                  <Code>{e.action}</Code>
                </Td>
                <Td className="whitespace-nowrap">
                  {e.actorKind}:{e.actorId.slice(-6)}
                </Td>
                <Td className="whitespace-nowrap">
                  {e.targetType}
                  {e.targetId ? `:${e.targetId.slice(-6)}` : ""}
                </Td>
                <Td>
                  <Badge color={e.result === "success" ? "green" : "red"}>{e.result}</Badge>
                </Td>
                <Td className="whitespace-nowrap text-xs text-dimmed">{e.sourceIp}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </QueryState>
  );
}

/** A <time> keyboard users can focus to reveal its exact-time tooltip. */
function FocusableTime({ dateTime, children, ...rest }: { dateTime: string; children: string; "aria-describedby"?: string }) {
  return (
    // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- focus only reveals the tooltip (WCAG 2.1.1); there is no action.
    <time dateTime={dateTime} tabIndex={0} className="rounded-sm" {...rest}>
      {children}
    </time>
  );
}
