// SPDX-License-Identifier: Apache-2.0
import { roleDescription, roleLabel, type Role } from "@kiln/core";
import { Badge, Tooltip } from "@mantine/core";

const COLORS: Record<Role, string> = { owner: "kiln", admin: "grape", developer: "blue", viewer: "gray" };

export function RoleBadge({ role }: { role: Role }) {
  return (
    <Tooltip label={roleDescription(role)} withArrow>
      <Badge color={COLORS[role]} variant="light" tabIndex={0}>
        {roleLabel(role)}
      </Badge>
    </Tooltip>
  );
}
