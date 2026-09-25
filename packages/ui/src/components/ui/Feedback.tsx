// SPDX-License-Identifier: Apache-2.0
//
// Small presentational pieces: spinner, alert, badge, inline code, avatar,
// and the round icon used by empty states.
import { IconAlertTriangle, IconCircleCheck, IconInfoCircle } from "@tabler/icons-react";
import type { HTMLAttributes, ReactNode } from "react";

import { cn } from "./cn";

export function Spinner({ size = "md", label }: { size?: "sm" | "md" | "lg"; label?: string }) {
  const dims = size === "sm" ? "size-4" : size === "md" ? "size-7" : "size-9";
  const svg = (
    <svg className={cn("animate-spin", dims)} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9.5" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
      <path d="M21.5 12A9.5 9.5 0 0 0 12 2.5" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
  // With a label it is a live status; without one it decorates a button.
  if (!label) return svg;
  return (
    <span role="status" aria-label={label} className="inline-flex text-kiln-600 dark:text-kiln-400">
      {svg}
    </span>
  );
}

export type Tone = "red" | "yellow" | "green" | "blue";

const ALERT_TONES: Record<Tone, string> = {
  red: "border-red-200 bg-red-50 text-red-900 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-100",
  yellow: "border-amber-200 bg-amber-50 text-amber-950 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-100",
  green: "border-green-200 bg-green-50 text-green-900 dark:border-green-900/60 dark:bg-green-950/40 dark:text-green-100",
  blue: "border-blue-200 bg-blue-50 text-blue-900 dark:border-blue-900/60 dark:bg-blue-950/40 dark:text-blue-100",
};

const ALERT_ICON_TONES: Record<Tone, string> = {
  red: "text-red-700 dark:text-red-300",
  yellow: "text-amber-700 dark:text-amber-300",
  green: "text-green-700 dark:text-green-300",
  blue: "text-blue-700 dark:text-blue-300",
};

const DEFAULT_ICONS: Record<Tone, ReactNode> = {
  red: <IconAlertTriangle size={20} aria-hidden />,
  yellow: <IconAlertTriangle size={20} aria-hidden />,
  green: <IconCircleCheck size={20} aria-hidden />,
  blue: <IconInfoCircle size={20} aria-hidden />,
};

export function Alert({
  tone,
  title,
  icon,
  role,
  children,
}: {
  tone: Tone;
  title?: string;
  icon?: ReactNode;
  role?: "alert" | "status";
  children: ReactNode;
}) {
  return (
    <div role={role} className={cn("flex gap-3 rounded-lg border p-4 text-sm", ALERT_TONES[tone])}>
      <span className={cn("mt-px shrink-0", ALERT_ICON_TONES[tone])}>{icon ?? DEFAULT_ICONS[tone]}</span>
      <div className="min-w-0 flex-1">
        {title ? <p className="mb-1 font-semibold">{title}</p> : null}
        <div>{children}</div>
      </div>
    </div>
  );
}

export type BadgeColor = "kiln" | "purple" | "blue" | "gray" | "green" | "red";

const BADGE_COLORS: Record<BadgeColor, string> = {
  kiln: "bg-kiln-50 text-kiln-800 dark:bg-kiln-900/40 dark:text-kiln-200",
  purple: "bg-purple-50 text-purple-800 dark:bg-purple-900/40 dark:text-purple-200",
  blue: "bg-blue-50 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200",
  gray: "bg-gray-100 text-gray-700 dark:bg-gray-700/50 dark:text-gray-200",
  green: "bg-green-50 text-green-800 dark:bg-green-900/40 dark:text-green-200",
  red: "bg-red-50 text-red-800 dark:bg-red-900/40 dark:text-red-200",
};

export function Badge({ color, className, children, ...rest }: HTMLAttributes<HTMLSpanElement> & { color: BadgeColor }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center whitespace-nowrap rounded-full px-2 text-[0.6875rem] font-bold uppercase tracking-wide",
        BADGE_COLORS[color],
        className,
      )}
      {...rest}
    >
      {children}
    </span>
  );
}

export function Code({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <code className={cn("rounded bg-subtle px-1.5 py-0.5 font-mono text-[0.8125em] text-fg", className)}>{children}</code>
  );
}

/** Decorative initials; the surrounding control carries the accessible name. */
export function Avatar({ initials }: { initials: string }) {
  return (
    <span
      aria-hidden="true"
      className="inline-flex size-7 shrink-0 items-center justify-center rounded-full bg-kiln-100 text-xs font-bold text-kiln-800 dark:bg-kiln-900/50 dark:text-kiln-200"
    >
      {initials}
    </span>
  );
}

export function RoundIcon({ children }: { children: ReactNode }) {
  return (
    <span
      aria-hidden="true"
      className="inline-flex size-12 items-center justify-center rounded-full bg-kiln-50 text-kiln-600 dark:bg-kiln-900/30 dark:text-kiln-300"
    >
      {children}
    </span>
  );
}
