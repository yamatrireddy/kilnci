// SPDX-License-Identifier: Apache-2.0
//
// The sanitizing log viewer (T-09, ADR-0007 §5). Log bytes are attacker-
// controlled. They reach this component only as parsed lines from
// @kiln/core's AnsiParser, and are rendered as React text children: never
// as HTML, never as links, and styled only through the fixed class lists
// below (no inline styles, so the strict CSP holds).
import type { AnsiLine, AnsiStyle } from "@kiln/core";
import { IconArrowDown } from "@tabler/icons-react";
import { memo, useLayoutEffect, useRef, useState, type ReactNode } from "react";

import { Button, cn } from "../ui";

// Foreground colors for the 16 terminal colors on the viewer's dark
// background (light shades, so text stays readable on gray-950).
const FG = [
  "text-gray-400", "text-red-400", "text-green-400", "text-yellow-300",
  "text-blue-400", "text-fuchsia-400", "text-cyan-400", "text-gray-200",
  "text-gray-400", "text-red-300", "text-green-300", "text-yellow-200",
  "text-blue-300", "text-fuchsia-300", "text-cyan-300", "text-white",
] as const;

const BG = [
  "bg-black", "bg-red-900", "bg-green-900", "bg-yellow-800",
  "bg-blue-900", "bg-fuchsia-900", "bg-cyan-900", "bg-gray-300",
  "bg-gray-700", "bg-red-700", "bg-green-700", "bg-yellow-600",
  "bg-blue-700", "bg-fuchsia-700", "bg-cyan-700", "bg-white",
] as const;

/** The classes for one styled span. Exported for tests. */
export function spanClass(style: AnsiStyle): string {
  const fg = style.inverse ? style.bg : style.fg;
  const bg = style.inverse ? style.fg : style.bg;
  return cn(
    fg !== undefined ? FG[fg] : style.inverse && "text-gray-950",
    bg !== undefined ? BG[bg] : style.inverse && "bg-gray-100",
    style.bold && "font-bold",
    style.dim && "opacity-70",
    style.italic && "italic",
    style.underline && "underline",
    style.strike && "line-through",
  );
}

const LogLine = memo(function LogLine({ line, number }: { line: AnsiLine; number: number }) {
  return (
    <div className="flex hover:bg-white/5">
      <span aria-hidden="true" className="w-14 shrink-0 select-none pr-3 text-right text-gray-500">
        {number}
      </span>
      <span className="min-w-0 flex-1 whitespace-pre-wrap break-all">
        {line.spans.map((s, i) => {
          const cls = spanClass(s.style);
          return cls ? (
            <span key={i} className={cls}>
              {s.text}
            </span>
          ) : (
            s.text
          );
        })}
        {line.truncated ? <span className="text-gray-500"> … (line truncated)</span> : null}
      </span>
    </div>
  );
});

/** Lines rendered at first; earlier retained lines load on request. */
export const RENDER_LINES = 2_000;

export interface LogViewerProps {
  /** Accessible name, e.g. "Log for build". */
  label: string;
  lines: readonly AnsiLine[];
  /** The line still being written, shown last. */
  pending?: AnsiLine | null;
  /** Earlier lines that were dropped to bound memory. */
  dropped?: number;
  /** Re-render hint: bump when `lines` was mutated in place. */
  version?: number;
  /** Shown when there are no lines. */
  empty?: ReactNode;
  /** Status shown under the log (connection state, end status). */
  footer?: ReactNode;
}

/** Renders parsed log lines and keeps the newest in view while following. */
export function LogViewer({ label, lines, pending, dropped = 0, version, empty, footer }: LogViewerProps) {
  const scroller = useRef<HTMLDivElement>(null);
  const [follow, setFollow] = useState(true);
  // Rendering is bounded separately from what the buffer keeps, so a huge
  // log cannot freeze the page (security review).
  const [renderLimit, setRenderLimit] = useState(RENDER_LINES);
  const count = lines.length + (pending ? 1 : 0);
  const hidden = Math.max(0, lines.length - renderLimit);
  const shown = hidden > 0 ? lines.slice(hidden) : lines;

  useLayoutEffect(() => {
    const el = scroller.current;
    if (follow && el) el.scrollTop = el.scrollHeight;
  }, [follow, count, version]);

  return (
    <div className="flex flex-col gap-2">
      <div className="relative">
        <div
          ref={scroller}
          role="region"
          aria-label={label}
          // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a scrollable region must be focusable so keyboard users can scroll it (WCAG 2.1.1).
          tabIndex={0}
          onScroll={(e) => {
            const el = e.currentTarget;
            setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 24);
          }}
          className="max-h-[70vh] min-h-40 overflow-auto rounded-lg bg-gray-950 py-3 pr-3 font-mono text-[0.8125rem] leading-5 text-gray-100"
        >
          {dropped > 0 ? (
            <p className="px-3 pb-2 text-gray-400">
              {dropped.toLocaleString()} earlier {dropped === 1 ? "line is" : "lines are"} not shown.
            </p>
          ) : null}
          {hidden > 0 ? (
            <div className="px-3 pb-2">
              <Button
                size="sm"
                variant="default"
                onClick={() => {
                  setFollow(false);
                  setRenderLimit((n) => n + RENDER_LINES);
                }}
              >
                Show {Math.min(hidden, RENDER_LINES).toLocaleString()} earlier lines
              </Button>
            </div>
          ) : null}
          {count === 0 ? <div className="px-3 text-gray-400">{empty ?? "No output yet."}</div> : null}
          {shown.map((line, i) => (
            <LogLine key={dropped + hidden + i} line={line} number={dropped + hidden + i + 1} />
          ))}
          {pending ? <LogLine line={pending} number={dropped + lines.length + 1} /> : null}
        </div>
        {!follow && count > 0 ? (
          <Button
            size="sm"
            variant="default"
            className="absolute bottom-3 right-5 shadow"
            leftSection={<IconArrowDown size={14} aria-hidden />}
            onClick={() => {
              setFollow(true);
            }}
          >
            Jump to latest
          </Button>
        ) : null}
      </div>
      {footer ? <div className="text-sm text-dimmed">{footer}</div> : null}
    </div>
  );
}
