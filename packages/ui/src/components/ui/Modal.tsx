// SPDX-License-Identifier: Apache-2.0
import { IconX } from "@tabler/icons-react";
import { useEffect, useId, useRef, type ReactNode } from "react";

import { IconButton } from "./Button";
import { cn } from "./cn";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export interface ModalProps {
  opened: boolean;
  onClose: () => void;
  title: string;
  size?: "md" | "lg";
  children: ReactNode;
}

/**
 * A modal dialog on the native <dialog> element: showModal() gives the focus
 * trap, the inert background, the top layer, and Escape handling. Closed
 * modals are unmounted, so their state (e.g. a new token) leaves the DOM.
 */
export function Modal(props: ModalProps) {
  if (!props.opened) return null;
  return <OpenModal {...props} />;
}

function canShowModal(d: HTMLDialogElement): boolean {
  // jsdom (tests) does not implement showModal.
  return typeof (d as { showModal?: unknown }).showModal === "function";
}

function OpenModal({ onClose, title, size = "md", children }: ModalProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  });

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    const returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const modal = canShowModal(dialog);
    if (modal) {
      if (!dialog.open) dialog.showModal();
      document.documentElement.classList.add("overflow-hidden");
    } else {
      dialog.setAttribute("open", "");
    }
    // Focus the field marked data-autofocus, else the first control that is
    // not the close button.
    const target =
      dialog.querySelector<HTMLElement>("[data-autofocus]") ??
      dialog.querySelector<HTMLElement>(`[data-modal-body] :is(${FOCUSABLE})`) ??
      dialog;
    target.focus();

    // Clicking the backdrop (the dialog element itself, outside its panel)
    // closes it, as Escape does.
    const onPointerDown = (e: MouseEvent) => {
      if (e.target === dialog) onCloseRef.current();
    };
    // Any native close that bypasses `cancel` (e.g. a future
    // <form method="dialog">) must still unmount the modal, so its contents
    // (such as a one-time token) leave the DOM.
    const onNativeClose = () => {
      onCloseRef.current();
    };
    dialog.addEventListener("mousedown", onPointerDown);
    dialog.addEventListener("close", onNativeClose);
    return () => {
      dialog.removeEventListener("mousedown", onPointerDown);
      dialog.removeEventListener("close", onNativeClose);
      if (modal) {
        document.documentElement.classList.remove("overflow-hidden");
        if (dialog.open) dialog.close();
      }
      if (returnFocus?.isConnected) returnFocus.focus();
    };
  }, []);

  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      tabIndex={-1}
      onCancel={(e) => {
        // Escape: let React state decide, so the dialog unmounts cleanly.
        e.preventDefault();
        onClose();
      }}
      className={cn(
        "m-auto w-[calc(100%-2rem)] overflow-hidden rounded-xl border border-line bg-surface p-0 text-fg shadow-2xl",
        size === "lg" ? "max-w-2xl" : "max-w-md",
      )}
    >
      {/* The panel scrolls, not the <dialog>, so a scrollbar click is never a backdrop click. */}
      <div className="max-h-[calc(100dvh-2rem)] overflow-y-auto">
        <div className="flex items-center justify-between gap-4 px-5 pb-2 pt-4 sm:px-6">
          <h2 id={titleId} className="text-lg font-semibold">
            {title}
          </h2>
          <IconButton aria-label="Close" onClick={onClose} className="-mr-2">
            <IconX size={18} aria-hidden />
          </IconButton>
        </div>
        <div data-modal-body className="px-5 pb-5 pt-2 sm:px-6 sm:pb-6">
          {children}
        </div>
      </div>
    </dialog>
  );
}
