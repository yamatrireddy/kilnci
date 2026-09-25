// SPDX-License-Identifier: Apache-2.0
import { cloneElement, useEffect, useId, useRef, useState, type ReactElement } from "react";

import { cn } from "./cn";

interface Placement {
  x: number;
  y: number;
  below: boolean;
}

/**
 * A short label shown on hover and keyboard focus (WCAG 1.4.13: it stays
 * while hovered and Escape dismisses it). It is fixed-positioned from the
 * trigger's box, so scrolling table wrappers never clip it; the position is
 * set through the style property (CSSOM), which the CSP allows (ADR-0004).
 *
 * `describe` links the tooltip to the trigger via aria-describedby; turn it
 * off when the tooltip repeats the trigger's aria-label.
 */
export function Tooltip({
  label,
  describe = true,
  children,
}: {
  label: string;
  describe?: boolean;
  children: ReactElement<{ "aria-describedby"?: string }>;
}) {
  const id = useId();
  const anchor = useRef<HTMLSpanElement>(null);
  const [place, setPlace] = useState<Placement | null>(null);

  useEffect(() => {
    if (!place) return;
    const hide = () => {
      setPlace(null);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") hide();
    };
    document.addEventListener("keydown", onKey);
    window.addEventListener("scroll", hide, true);
    window.addEventListener("resize", hide);
    return () => {
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", hide, true);
      window.removeEventListener("resize", hide);
    };
  }, [place]);

  // Hover and focus only reveal text; they are not interactions, so they are
  // plain DOM listeners on the wrapper rather than JSX event handlers.
  useEffect(() => {
    const el = anchor.current;
    if (!el) return;
    const onShow = () => {
      const r = el.getBoundingClientRect();
      // Flip below the trigger when there is no room above it.
      const below = r.top < 48;
      // Keep the centre far enough from the viewport edges for a short label.
      const x = Math.min(Math.max(r.left + r.width / 2, 80), window.innerWidth - 80);
      setPlace({ x, y: below ? r.bottom + 8 : r.top - 8, below });
    };
    const onHide = () => {
      setPlace(null);
    };
    el.addEventListener("mouseenter", onShow);
    el.addEventListener("mouseleave", onHide);
    el.addEventListener("focusin", onShow);
    el.addEventListener("focusout", onHide);
    return () => {
      el.removeEventListener("mouseenter", onShow);
      el.removeEventListener("mouseleave", onHide);
      el.removeEventListener("focusin", onShow);
      el.removeEventListener("focusout", onHide);
    };
  }, []);

  return (
    <span ref={anchor} className="inline-flex">
      {describe ? cloneElement(children, { "aria-describedby": id }) : children}
      <span
        id={id}
        role="tooltip"
        aria-hidden={describe ? undefined : true}
        style={place ? { left: place.x, top: place.y } : undefined}
        className={cn(
          "pointer-events-none fixed z-[1100] w-max max-w-64 -translate-x-1/2 rounded-md bg-gray-900 px-2.5 py-1.5 text-xs font-medium normal-case tracking-normal text-white shadow-md dark:bg-gray-700",
          place?.below ? "translate-y-0" : "-translate-y-full",
          // Closed tooltips park at the viewport origin: a fixed box left at
          // its static position (e.g. deep in a scrolled table) would widen
          // the page.
          place ? "visible" : "invisible left-0 top-0",
        )}
      >
        {label}
      </span>
    </span>
  );
}
