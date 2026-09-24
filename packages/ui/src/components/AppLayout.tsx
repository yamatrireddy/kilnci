// SPDX-License-Identifier: Apache-2.0
import type { Session } from "@kiln/api-client";
import { Avatar, Burger, Group, Menu, NavLink, Text, Title, UnstyledButton } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { IconBuilding, IconFlame, IconKey, IconLogout } from "@tabler/icons-react";
import { Link, Outlet, useLocation } from "react-router";

import { usePlatform } from "../platform";
import { useOrgs, useSignOut } from "../queries";
import classes from "./AppLayout.module.css";

/** The signed-in application frame: header, navigation, and content. */
export function AppLayout({ session }: { session: Session }) {
  const [opened, { toggle, close }] = useDisclosure();
  const { name } = usePlatform();
  const location = useLocation();
  const orgs = useOrgs();
  const signOut = useSignOut();

  const initials = session.user.displayName
    .split(/\s+/)
    .map((p) => p[0] ?? "")
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <div className={classes.root}>
      <a href="#main" className={classes.skip}>
        Skip to content
      </a>
      <header className={classes.header}>
        <Group gap="xs">
          <Burger
            opened={opened}
            onClick={toggle}
            className={classes.burger}
            size="sm"
            aria-label="Toggle navigation"
            aria-controls="kiln-nav"
            aria-expanded={opened}
          />
          <IconFlame aria-hidden color="var(--mantine-color-kiln-6)" />
          <Title order={1} size="h4">
            {name}
          </Title>
        </Group>
        <Menu position="bottom-end" withArrow>
          <Menu.Target>
            <UnstyledButton aria-label={`Account menu for ${session.user.displayName}`}>
              <Group gap="xs">
                <Avatar radius="xl" size="sm" color="kiln" alt="">
                  {initials}
                </Avatar>
                <Text size="sm" fw={500}>
                  {session.user.displayName}
                </Text>
              </Group>
            </UnstyledButton>
          </Menu.Target>
          <Menu.Dropdown>
            <Menu.Label>{session.user.email}</Menu.Label>
            <Menu.Item component={Link} to="/settings/tokens" leftSection={<IconKey size={16} aria-hidden />}>
              API tokens
            </Menu.Item>
            <Menu.Item
              color="red"
              leftSection={<IconLogout size={16} aria-hidden />}
              onClick={() => {
                signOut.mutate();
              }}
            >
              Sign out
            </Menu.Item>
          </Menu.Dropdown>
        </Menu>
      </header>

      <nav id="kiln-nav" aria-label="Main navigation" className={opened ? classes.navOpen : classes.nav}>
        <NavLink
          component={Link}
          to="/orgs"
          label="Organizations"
          leftSection={<IconBuilding size={18} aria-hidden />}
          active={location.pathname === "/orgs"}
          onClick={close}
        />
        {orgs.data?.items.map((o) => (
          <NavLink
            key={o.id}
            component={Link}
            to={`/orgs/${o.slug}`}
            label={o.name}
            description={o.slug}
            active={location.pathname.startsWith(`/orgs/${o.slug}`)}
            onClick={close}
            pl="lg"
          />
        ))}
        <NavLink
          component={Link}
          to="/settings/tokens"
          label="API tokens"
          leftSection={<IconKey size={18} aria-hidden />}
          active={location.pathname.startsWith("/settings/tokens")}
          onClick={close}
          mt="md"
        />
      </nav>

      <main id="main" className={classes.main}>
        <Outlet />
      </main>
    </div>
  );
}
