// SPDX-License-Identifier: Apache-2.0
import { roleDescription, roleLabel, type Role } from "@kiln/core";

import { Badge, Tooltip, type BadgeColor } from "./ui";

const COLORS: Record<Role, BadgeColor> = { owner: "kiln", admin: "purple", developer: "blue", viewer: "gray" };

export function RoleBadge({ role }: { role: Role }) {
  return (
    <Tooltip label={roleDescription(role)}>
      {/* Focusable so keyboard users can read the role description. */}
      <Badge color={COLORS[role]} tabIndex={0}>
        {roleLabel(role)}
      </Badge>
    </Tooltip>
  );
}
