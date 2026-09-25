// SPDX-License-Identifier: Apache-2.0
import type { Session } from "@kiln/api-client";
import { IconBuilding, IconFlame, IconKey, IconLogout, IconMenu2, IconX } from "@tabler/icons-react";
import { useEffect, useRef, type ReactNode } from "react";
import { Link, Outlet, useLocation } from "react-router";

import { usePlatform } from "../platform";
import { useOrgs, useSignOut } from "../queries";
import { Avatar, cn, IconButton, Menu, MenuItem, useDisclosure } from "./ui";

/** The signed-in application frame: header, navigation, and content. */
export function AppLayout({ session }: { session: Session }) {
  const [opened, { toggle, close }] = useDisclosure();
  const { name } = usePlatform();
  const location = useLocation();
  const orgs = useOrgs();
  const signOut = useSignOut();
  const burgerRef = useRef<HTMLButtonElement>(null);

  // The mobile navigation closes on Escape, returning focus to the burger.
  useEffect(() => {
    if (!opened) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        close();
        burgerRef.current?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
    };
  }, [opened, close]);

  const initials = session.user.displayName
    .split(/\s+/)
    .map((p) => p[0] ?? "")
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className="sr-only z-[1200] rounded-md border-2 border-kiln-600 bg-body px-3 py-2 text-sm font-medium focus:not-sr-only focus:fixed focus:left-4 focus:top-2"
      >
        Skip to content
      </a>
      <header className="sticky top-0 z-40 flex h-(--header-height) items-center justify-between gap-3 border-b border-line bg-body px-3 sm:px-4">
        <div className="flex min-w-0 items-center gap-2">
          <IconButton
            ref={burgerRef}
            onClick={toggle}
            className="md:hidden"
            aria-label="Toggle navigation"
            aria-controls="kiln-nav"
            aria-expanded={opened}
          >
            {opened ? <IconX size={20} aria-hidden /> : <IconMenu2 size={20} aria-hidden />}
          </IconButton>
          <IconFlame aria-hidden className="shrink-0 text-kiln-600 dark:text-kiln-400" />
          <h1 className="truncate text-lg">{name}</h1>
        </div>
        <Menu
          buttonLabel={`Account menu for ${session.user.displayName}`}
          buttonContent={
            <>
              <Avatar initials={initials} />
              <span className="hidden max-w-48 truncate text-sm font-medium text-fg sm:inline">
                {session.user.displayName}
              </span>
            </>
          }
          header={session.user.email}
        >
          <MenuItem to="/settings/tokens" icon={<IconKey size={16} aria-hidden />}>
            API tokens
          </MenuItem>
          <MenuItem
            danger
            icon={<IconLogout size={16} aria-hidden />}
            onSelect={() => {
              signOut.mutate();
            }}
          >
            Sign out
          </MenuItem>
        </Menu>
      </header>

      <div className="md:flex">
        <nav
          id="kiln-nav"
          aria-label="Main navigation"
          className={cn(
            "overflow-y-auto overscroll-contain bg-body p-2",
            opened ? "fixed inset-x-0 bottom-0 top-(--header-height) z-30 block" : "hidden",
            "md:sticky md:inset-auto md:top-(--header-height) md:z-auto md:block md:h-[calc(100vh-var(--header-height))] md:w-(--nav-width) md:shrink-0 md:border-r md:border-line",
          )}
        >
          <ul className="flex flex-col gap-0.5">
            <li>
              <NavItem
                to="/orgs"
                label="Organizations"
                icon={<IconBuilding size={18} aria-hidden />}
                active={location.pathname === "/orgs"}
                onNavigate={close}
              />
            </li>
            {orgs.data?.items.map((o) => (
              <li key={o.id}>
                <NavItem
                  to={`/orgs/${o.slug}`}
                  label={o.name}
                  description={o.slug}
                  active={location.pathname === `/orgs/${o.slug}` || location.pathname.startsWith(`/orgs/${o.slug}/`)}
                  onNavigate={close}
                  indent
                />
              </li>
            ))}
            <li className="mt-3 border-t border-line pt-3">
              <NavItem
                to="/settings/tokens"
                label="API tokens"
                icon={<IconKey size={18} aria-hidden />}
                active={location.pathname.startsWith("/settings/tokens")}
                onNavigate={close}
              />
            </li>
          </ul>
        </nav>

        <main id="main" tabIndex={-1} className="min-w-0 flex-1 px-4 py-5 focus:outline-none sm:px-6 sm:py-6">
          <div className="mx-auto w-full max-w-6xl">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

function NavItem({
  to,
  label,
  description,
  icon,
  active,
  indent = false,
  onNavigate,
}: {
  to: string;
  label: string;
  description?: string;
  icon?: ReactNode;
  active: boolean;
  indent?: boolean;
  onNavigate: () => void;
}) {
  return (
    <Link
      to={to}
      onClick={onNavigate}
      aria-current={active ? "page" : undefined}
      className={cn(
        "flex items-center gap-3 rounded-md py-2 pr-3 text-sm transition-colors",
        indent ? "pl-10" : "pl-3",
        active
          ? "bg-kiln-50 font-medium text-kiln-800 dark:bg-kiln-900/30 dark:text-kiln-200"
          : "text-fg hover:bg-hover",
      )}
    >
      {icon ? <span className="shrink-0">{icon}</span> : null}
      <span className="min-w-0">
        <span className="block truncate">{label}</span>
        {description ? <span className="block truncate font-mono text-xs font-normal text-dimmed">{description}</span> : null}
      </span>
    </Link>
  );
}
