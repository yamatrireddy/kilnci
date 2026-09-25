// SPDX-License-Identifier: Apache-2.0
//
// Page-level building blocks: headers, breadcrumbs, links, cards, tables.
import { Fragment, type HTMLAttributes, type ReactNode, type TdHTMLAttributes, type ThHTMLAttributes } from "react";
import { Link, type LinkProps } from "react-router";

import { cn } from "./cn";

/** Page title with optional subtitle and actions; wraps on narrow screens. */
export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-3">
      <div className="min-w-0">
        <h2 className="break-words text-2xl text-fg">{title}</h2>
        {subtitle ? <div className="mt-0.5 text-sm text-dimmed">{subtitle}</div> : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function TextLink({ className, ...rest }: LinkProps) {
  return (
    <Link
      className={cn("rounded-sm text-link underline-offset-2 hover:underline", className)}
      {...rest}
    />
  );
}

/** Breadcrumb trail; the last crumb is the current page. */
export function Breadcrumbs({ items }: { items: { label: string; to?: string }[] }) {
  return (
    <nav aria-label="Breadcrumb">
      <ol className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
        {items.map((item, i) => {
          const last = i === items.length - 1;
          return (
            <Fragment key={`${String(i)}-${item.label}`}>
              <li className="min-w-0 max-w-full truncate">
                {item.to && !last ? (
                  <TextLink to={item.to}>{item.label}</TextLink>
                ) : (
                  <span aria-current={last ? "page" : undefined} className="text-fg">
                    {item.label}
                  </span>
                )}
              </li>
              {last ? null : (
                <li aria-hidden="true" className="text-dimmed">
                  /
                </li>
              )}
            </Fragment>
          );
        })}
      </ol>
    </nav>
  );
}

export function Card({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-lg border border-line bg-surface", className)} {...rest} />;
}

/** A table that scrolls horizontally on narrow screens instead of overflowing the page. */
export function Table({
  highlightOnHover = false,
  dense = false,
  children,
}: {
  highlightOnHover?: boolean;
  dense?: boolean;
  children: ReactNode;
}) {
  return (
    // `relative` keeps absolutely positioned content (e.g. sr-only header
    // labels) inside the scroll box instead of widening the page.
    <div className="relative -mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
      <table
        className={cn(
          "w-full border-collapse text-left text-sm",
          "[&_th]:border-b [&_th]:border-line [&_th]:px-3 [&_th]:py-2 [&_th]:text-sm [&_th]:font-semibold [&_th]:text-fg",
          "[&_td]:border-b [&_td]:border-line [&_td]:px-3 [&_td]:align-middle",
          "[&_tbody_tr:last-child_td]:border-b-0",
          dense ? "[&_td]:py-2" : "[&_td]:py-3",
          highlightOnHover && "[&_tbody_tr]:transition-colors [&_tbody_tr:hover]:bg-hover",
        )}
      >
        {children}
      </table>
    </div>
  );
}

export function Th({ className, ...rest }: ThHTMLAttributes<HTMLTableCellElement>) {
  return <th scope="col" className={cn("whitespace-nowrap", className)} {...rest} />;
}

export function Td({ className, ...rest }: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={className} {...rest} />;
}
