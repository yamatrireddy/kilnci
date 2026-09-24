// SPDX-License-Identifier: Apache-2.0
import type { Org } from "@kiln/api-client";
import { formatDateTime, formatRelative } from "@kiln/core";
import { Badge, Code, Table, Text, Tooltip } from "@mantine/core";

import { QueryState } from "../../components/QueryState";
import { useAuditEvents } from "../../queries";

export function AuditTab({ org }: { org: Org }) {
  const events = useAuditEvents(org.slug, true);
  return (
    <QueryState query={events} label="audit events" isEmpty={(d) => d.items.length === 0}>
      {(data) => (
        <Table verticalSpacing="xs" fz="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th scope="col">When</Table.Th>
              <Table.Th scope="col">Action</Table.Th>
              <Table.Th scope="col">Actor</Table.Th>
              <Table.Th scope="col">Target</Table.Th>
              <Table.Th scope="col">Result</Table.Th>
              <Table.Th scope="col">Source</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {data.items.map((e) => (
              <Table.Tr key={e.id}>
                <Table.Td>
                  <Tooltip label={formatDateTime(e.occurredAt)}>
                    <Text size="sm" tabIndex={0}>
                      {formatRelative(e.occurredAt)}
                    </Text>
                  </Tooltip>
                </Table.Td>
                <Table.Td>
                  <Code>{e.action}</Code>
                </Table.Td>
                <Table.Td>
                  {e.actorKind}:{e.actorId.slice(-6)}
                </Table.Td>
                <Table.Td>
                  {e.targetType}
                  {e.targetId ? `:${e.targetId.slice(-6)}` : ""}
                </Table.Td>
                <Table.Td>
                  <Badge color={e.result === "success" ? "green" : "red"} variant="light">
                    {e.result}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {e.sourceIp}
                  </Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </QueryState>
  );
}
