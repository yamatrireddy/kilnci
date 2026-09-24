// SPDX-License-Identifier: Apache-2.0

export type Role = "viewer" | "developer" | "admin" | "owner";

/** Roles from lowest to highest privilege, for display order. */
export const ROLES: readonly Role[] = ["viewer", "developer", "admin", "owner"];

const LABELS: Record<Role, string> = {
  viewer: "Viewer",
  developer: "Developer",
  admin: "Admin",
  owner: "Owner",
};

const DESCRIPTIONS: Record<Role, string> = {
  viewer: "Read projects, runs, and members",
  developer: "Viewer, plus trigger and cancel runs",
  admin: "Developer, plus manage projects and members",
  owner: "Admin, plus manage owners",
};

export function roleLabel(role: Role): string {
  return LABELS[role];
}

export function roleDescription(role: Role): string {
  return DESCRIPTIONS[role];
}

/**
 * Whether `role` is at least `min`. For hiding controls a user cannot use;
 * it is a usability hint only. The server enforces every permission.
 */
export function roleAtLeast(role: Role, min: Role): boolean {
  return ROLES.indexOf(role) >= ROLES.indexOf(min);
}
