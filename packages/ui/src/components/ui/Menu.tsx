// SPDX-License-Identifier: Apache-2.0
import {
  createContext,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { Link } from "react-router";

import { cn } from "./cn";

const CloseContext = createContext<() => void>(() => undefined);

/**
 * A menu button (WAI-ARIA APG pattern): Enter/Space/ArrowDown open it and
 * focus the first item, arrows/Home/End move, Escape closes and returns
 * focus to the button, and clicking elsewhere closes it.
 */
export function Menu({
  buttonLabel,
  buttonContent,
  header,
  children,
}: {
  /** Accessible name of the trigger button. */
  buttonLabel: string;
  buttonContent: ReactNode;
  /** Non-interactive text shown above the items. */
  header?: ReactNode;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuId = useId();

  const items = () => Array.from(menuRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? []);

  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) buttonRef.current?.focus();
  };

  useEffect(() => {
    if (!open) return;
    items()[0]?.focus();
    const onPointerDown = (e: MouseEvent) => {
      if (e.target instanceof Node && !rootRef.current?.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
    };
  }, [open]);

  const onMenuKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const list = items();
    const i = list.indexOf(document.activeElement as HTMLElement);
    const focusAt = (n: number) => {
      e.preventDefault();
      list[(n + list.length) % list.length]?.focus();
    };
    switch (e.key) {
      case "ArrowDown":
        focusAt(i + 1);
        break;
      case "ArrowUp":
        focusAt(i - 1);
        break;
      case "Home":
        focusAt(0);
        break;
      case "End":
        focusAt(list.length - 1);
        break;
      case "Escape":
        e.preventDefault();
        close(true);
        break;
      case "Tab":
        close(false);
        break;
    }
  };

  return (
    <div ref={rootRef} className="relative">
      <button
        ref={buttonRef}
        type="button"
        aria-label={buttonLabel}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => {
          setOpen((o) => !o);
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown" && !open) {
            e.preventDefault();
            setOpen(true);
          }
        }}
        className="flex items-center gap-2 rounded-md px-1.5 py-1 hover:bg-hover"
      >
        {buttonContent}
      </button>
      {open ? (
        <div className="absolute right-0 top-full z-50 mt-2 w-60 max-w-[calc(100vw-2rem)] rounded-lg border border-line bg-surface p-1 shadow-lg">
          {header ? <div className="truncate px-3 pb-1 pt-2 text-xs font-medium text-dimmed">{header}</div> : null}
          <div ref={menuRef} id={menuId} role="menu" aria-label={buttonLabel} tabIndex={-1} onKeyDown={onMenuKeyDown}>
            <CloseContext.Provider
              value={() => {
                close(false);
              }}
            >
              {children}
            </CloseContext.Provider>
          </div>
        </div>
      ) : null}
    </div>
  );
}

const ITEM =
  "flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-left text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus";

export function MenuItem({
  to,
  onSelect,
  icon,
  danger = false,
  children,
}: {
  /** In-app destination; otherwise the item is a button calling onSelect. */
  to?: string;
  onSelect?: () => void;
  icon?: ReactNode;
  danger?: boolean;
  children: ReactNode;
}) {
  const close = useContext(CloseContext);
  const cls = cn(
    ITEM,
    danger ? "text-red-700 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-950/40" : "text-fg hover:bg-hover",
  );
  if (to !== undefined) {
    return (
      <Link role="menuitem" tabIndex={-1} to={to} onClick={close} className={cls}>
        {icon}
        {children}
      </Link>
    );
  }
  return (
    <button
      role="menuitem"
      tabIndex={-1}
      type="button"
      onClick={() => {
        close();
        onSelect?.();
      }}
      className={cls}
    >
      {icon}
      {children}
    </button>
  );
}
