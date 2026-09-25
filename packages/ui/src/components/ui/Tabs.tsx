// SPDX-License-Identifier: Apache-2.0
import { useId, useRef, type KeyboardEvent, type ReactNode } from "react";

import { cn } from "./cn";

/**
 * Tabs (WAI-ARIA APG, automatic activation): arrows/Home/End move between
 * tabs and select them. Only the selected panel is rendered, as before.
 */
export function Tabs<T extends string>({
  value,
  onChange,
  tabs,
  label,
  children,
}: {
  value: T;
  onChange: (value: T) => void;
  tabs: { value: T; label: string }[];
  label: string;
  /** Content of the selected tab. */
  children: ReactNode;
}) {
  const base = useId();
  const listRef = useRef<HTMLDivElement>(null);
  const tabId = (v: T) => `${base}-tab-${v}`;
  const panelId = `${base}-panel`;

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    const i = tabs.findIndex((t) => t.value === value);
    let next: number | null = null;
    if (e.key === "ArrowRight") next = (i + 1) % tabs.length;
    else if (e.key === "ArrowLeft") next = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = tabs.length - 1;
    const target = next === null ? undefined : tabs[next];
    if (!target) return;
    e.preventDefault();
    onChange(target.value);
    const buttons = listRef.current?.querySelectorAll<HTMLElement>('[role="tab"]');
    buttons?.[next ?? 0]?.focus();
  };

  return (
    <div>
      {/* Scrolls sideways on narrow screens. The baseline is an inset shadow
          (not a border plus negative margins), so there is no vertical
          overflow and the selected tab's underline sits on top of it. */}
      <div className="overflow-x-auto">
        <div
          ref={listRef}
          role="tablist"
          aria-label={label}
          className="flex w-max min-w-full gap-1 shadow-[inset_0_-1px_0_var(--kiln-line)]"
        >
          {tabs.map((t) => {
            const selected = t.value === value;
            return (
              <button
                key={t.value}
                id={tabId(t.value)}
                type="button"
                role="tab"
                aria-selected={selected}
                aria-controls={selected ? panelId : undefined}
                tabIndex={selected ? 0 : -1}
                onKeyDown={onKeyDown}
                onClick={() => {
                  onChange(t.value);
                }}
                className={cn(
                  "whitespace-nowrap border-b-2 px-3 py-2.5 text-sm font-medium transition-colors focus-visible:-outline-offset-2",
                  selected
                    ? "border-kiln-600 text-fg dark:border-kiln-400"
                    : "border-transparent text-dimmed hover:border-line-strong hover:text-fg",
                )}
              >
                {t.label}
              </button>
            );
          })}
        </div>
      </div>
      <div id={panelId} role="tabpanel" aria-labelledby={tabId(value)} className="pt-4">
        {children}
      </div>
    </div>
  );
}
