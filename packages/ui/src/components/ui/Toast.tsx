// SPDX-License-Identifier: Apache-2.0
import { IconAlertTriangle, IconCircleCheck, IconX } from "@tabler/icons-react";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { IconButton } from "./Button";
import { cn } from "./cn";

export interface ToastInput {
  color: "green" | "red";
  title?: string;
  message: string;
}

interface Toast extends ToastInput {
  id: number;
}

type Notify = (t: ToastInput) => void;

const ToastContext = createContext<Notify | null>(null);

/** Shows transient notifications, e.g. `notify({ color: "green", message })`. */
export function useNotify(): Notify {
  const notify = useContext(ToastContext);
  if (!notify) throw new Error("useNotify must be used inside <KilnProvider>");
  return notify;
}

const DURATION_MS = 5000;

/**
 * Holds the toast stack. The live region is always in the DOM so screen
 * readers announce toasts as they are added.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(0);

  const dismiss = useCallback((id: number) => {
    setToasts((ts) => ts.filter((t) => t.id !== id));
  }, []);
  const notify = useCallback<Notify>((t) => {
    nextId.current += 1;
    const id = nextId.current;
    setToasts((ts) => [...ts.slice(-4), { ...t, id }]);
  }, []);
  const value = useMemo(() => notify, [notify]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <section
        aria-label="Notifications"
        aria-live="polite"
        className="pointer-events-none fixed right-4 top-4 z-[1000] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2"
      >
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} onDismiss={dismiss} />
        ))}
      </section>
    </ToastContext.Provider>
  );
}

function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: (id: number) => void }) {
  const [paused, setPaused] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  // Hovering pauses auto-dismiss so the message can be read (a pointer-only
  // convenience; the toast is also announced and has a dismiss button).
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const pause = () => {
      setPaused(true);
    };
    const resume = () => {
      setPaused(false);
    };
    el.addEventListener("mouseenter", pause);
    el.addEventListener("mouseleave", resume);
    el.addEventListener("focusin", pause);
    el.addEventListener("focusout", resume);
    return () => {
      el.removeEventListener("mouseenter", pause);
      el.removeEventListener("mouseleave", resume);
      el.removeEventListener("focusin", pause);
      el.removeEventListener("focusout", resume);
    };
  }, []);

  useEffect(() => {
    if (paused) return;
    const timer = setTimeout(() => {
      onDismiss(toast.id);
    }, DURATION_MS);
    return () => {
      clearTimeout(timer);
    };
  }, [paused, toast.id, onDismiss]);

  const ok = toast.color === "green";
  return (
    <div
      ref={ref}
      className={cn(
        "pointer-events-auto flex items-start gap-3 rounded-lg border border-line bg-surface p-3 pl-4 text-sm shadow-lg",
        "border-l-4",
        ok ? "border-l-green-600" : "border-l-red-600",
      )}
    >
      <span className={cn("mt-0.5 shrink-0", ok ? "text-green-700 dark:text-green-400" : "text-red-700 dark:text-red-400")}>
        {ok ? <IconCircleCheck size={18} aria-hidden /> : <IconAlertTriangle size={18} aria-hidden />}
      </span>
      <div className="min-w-0 flex-1 pt-px">
        {toast.title ? <p className="font-semibold text-fg">{toast.title}</p> : null}
        <p className="break-words text-fg">{toast.message}</p>
      </div>
      <IconButton
        aria-label="Dismiss notification"
        className="-my-1 -mr-1 size-7"
        onClick={() => {
          onDismiss(toast.id);
        }}
      >
        <IconX size={16} aria-hidden />
      </IconButton>
    </div>
  );
}
