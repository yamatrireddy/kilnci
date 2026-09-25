// SPDX-License-Identifier: Apache-2.0
//
// Labelled form controls built on native elements, so keyboard, mobile, and
// assistive-technology behaviour comes from the browser.
import { IconChevronDown } from "@tabler/icons-react";
import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";

import { cn } from "./cn";

const CONTROL =
  "block w-full rounded-md border border-line-strong bg-surface text-sm text-fg shadow-xs transition-colors " +
  "placeholder:text-dimmed focus-visible:border-kiln-600 focus-visible:outline-2 focus-visible:outline-offset-0 " +
  "disabled:cursor-not-allowed disabled:opacity-60 " +
  "aria-[invalid=true]:border-red-600 dark:aria-[invalid=true]:border-red-400";

interface FieldChrome {
  label: string;
  description?: ReactNode;
  error?: ReactNode;
  required?: boolean;
}

/** Label, description, and error wiring shared by every control. */
function useFieldIds(error: ReactNode, description: ReactNode) {
  const id = useId();
  const descId = description ? `${id}-desc` : undefined;
  const errId = error ? `${id}-err` : undefined;
  const describedBy = [descId, errId].filter(Boolean).join(" ") || undefined;
  return { id, descId, errId, describedBy };
}

function Chrome({
  id,
  label,
  required,
  description,
  descId,
  error,
  errId,
  children,
}: FieldChrome & { id: string; descId?: string; errId?: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-sm font-medium text-fg">
        {label}
        {required ? (
          <span aria-hidden="true" className="ml-0.5 text-red-700 dark:text-red-400">
            *
          </span>
        ) : null}
      </label>
      {description ? (
        <p id={descId} className="text-xs text-dimmed">
          {description}
        </p>
      ) : null}
      {children}
      {error ? (
        <p id={errId} className="text-xs font-medium text-red-700 dark:text-red-400">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export type TextFieldProps = Omit<InputHTMLAttributes<HTMLInputElement>, "id"> & FieldChrome;

export function TextField({ label, description, error, required, className, ...rest }: TextFieldProps) {
  const { id, descId, errId, describedBy } = useFieldIds(error, description);
  return (
    <Chrome {...{ id, label, required, description, descId, error, errId }}>
      <input
        id={id}
        required={required}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        className={cn(CONTROL, "h-9 px-3", className)}
        {...rest}
      />
    </Chrome>
  );
}

export type SelectFieldProps = Omit<SelectHTMLAttributes<HTMLSelectElement>, "id"> &
  Partial<FieldChrome> & {
    options: { value: string; label: string }[];
  };

/**
 * A native <select>. Without `label` it renders the bare control, which must
 * then get its name from `aria-label` (used inside table rows).
 */
export function SelectField({ label, description, error, required, options, className, ...rest }: SelectFieldProps) {
  const { id, descId, errId, describedBy } = useFieldIds(error, description);
  const control = (
    <div className={cn("relative", className)}>
      <select
        id={id}
        required={required}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        className={cn(CONTROL, "h-9 cursor-pointer appearance-none pl-3 pr-9")}
        {...rest}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <IconChevronDown
        size={16}
        aria-hidden
        className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-dimmed"
      />
    </div>
  );
  if (label === undefined) return control;
  return <Chrome {...{ id, label, required, description, descId, error, errId }}>{control}</Chrome>;
}

export function Checkbox({
  label,
  className,
  ...rest
}: Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & { label: ReactNode }) {
  return (
    <label className={cn("flex cursor-pointer items-start gap-2.5 text-sm text-fg", className)}>
      <input type="checkbox" className="mt-0.5 size-4 shrink-0 cursor-pointer accent-kiln-600" {...rest} />
      <span>{label}</span>
    </label>
  );
}

/** A group of checkboxes with a shared legend and error. */
export function CheckboxGroup({ legend, error, children }: { legend: string; error?: ReactNode; children: ReactNode }) {
  const errId = useId();
  return (
    <fieldset aria-describedby={error ? errId : undefined} className="flex flex-col gap-2">
      <legend className="mb-1 text-sm font-medium text-fg">{legend}</legend>
      {children}
      {error ? (
        <p id={errId} className="text-xs font-medium text-red-700 dark:text-red-400">
          {error}
        </p>
      ) : null}
    </fieldset>
  );
}
