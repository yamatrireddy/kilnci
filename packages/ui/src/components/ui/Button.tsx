// SPDX-License-Identifier: Apache-2.0
import type { ComponentProps, ReactNode } from "react";

import { cn } from "./cn";
import { Spinner } from "./Feedback";

export type ButtonVariant = "filled" | "default" | "danger" | "light";

const VARIANTS: Record<ButtonVariant, string> = {
  filled: "bg-kiln-600 text-white hover:bg-kiln-700 active:bg-kiln-800",
  default: "border border-line-strong bg-surface text-fg hover:bg-hover",
  danger: "bg-red-700 text-white hover:bg-red-800 active:bg-red-900",
  light: "bg-kiln-50 text-kiln-800 hover:bg-kiln-100 dark:bg-kiln-900/30 dark:text-kiln-200 dark:hover:bg-kiln-900/50",
};

const SIZES = {
  sm: "h-8 gap-1.5 px-3 text-sm",
  md: "h-9 gap-2 px-4 text-sm",
  lg: "h-11 gap-2 px-5 text-base",
} as const;

export interface ButtonProps extends ComponentProps<"button"> {
  variant?: ButtonVariant;
  size?: keyof typeof SIZES;
  /** Shows a spinner and disables the button while an action runs. */
  loading?: boolean;
  /** Icon rendered before the label. */
  leftSection?: ReactNode;
  fullWidth?: boolean;
}

export function Button({
  variant = "filled",
  size = "md",
  loading = false,
  leftSection,
  fullWidth = false,
  disabled,
  className,
  children,
  type = "button",
  ...rest
}: ButtonProps) {
  return (
    <button
      type={type}
      disabled={disabled === true || loading}
      aria-busy={loading || undefined}
      className={cn(
        "inline-flex shrink-0 select-none items-center justify-center whitespace-nowrap rounded-md font-semibold transition-colors",
        "disabled:cursor-not-allowed disabled:opacity-60",
        VARIANTS[variant],
        SIZES[size],
        fullWidth && "w-full",
        className,
      )}
      {...rest}
    >
      {loading ? <Spinner size="sm" /> : leftSection}
      {children}
    </button>
  );
}

const ICON_VARIANTS = {
  subtle: "text-dimmed hover:bg-hover hover:text-fg",
  "subtle-danger": "text-red-700 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-950/40",
  light: "bg-kiln-50 text-kiln-800 hover:bg-kiln-100 dark:bg-kiln-900/30 dark:text-kiln-200 dark:hover:bg-kiln-900/50",
} as const;

export interface IconButtonProps extends ComponentProps<"button"> {
  /** Required: an icon-only button needs an accessible name. */
  "aria-label": string;
  variant?: keyof typeof ICON_VARIANTS;
}

/** A square, icon-only button. */
export function IconButton({ variant = "subtle", className, children, ...rest }: IconButtonProps) {
  return (
    <button
      type="button"
      className={cn(
        "inline-flex size-8 shrink-0 items-center justify-center rounded-md transition-colors disabled:cursor-not-allowed disabled:opacity-60",
        ICON_VARIANTS[variant],
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  );
}
