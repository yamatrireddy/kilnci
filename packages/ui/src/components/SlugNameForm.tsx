// SPDX-License-Identifier: Apache-2.0
import { ApiError } from "@kiln/api-client";
import { useState, type SyntheticEvent } from "react";

import { ErrorAlert } from "./ErrorAlert";
import { Button, TextField } from "./ui";

/** Suggests a slug from a display name: lowercase, hyphenated, 40 chars max. */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/\p{M}+/gu, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
    .replace(/-+$/g, "");
}

const SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9]|-[a-z0-9]){0,39}$/;

/** Name + slug form used to create orgs and projects. */
export function SlugNameForm({
  submitLabel,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  submitLabel: string;
  pending: boolean;
  error: unknown;
  onSubmit: (v: { name: string; slug: string }) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const effectiveSlug = slugTouched ? slug : slugify(name);
  const fieldErrors = error instanceof ApiError ? error.fieldErrors() : {};
  const slugInvalid = effectiveSlug !== "" && !SLUG_PATTERN.test(effectiveSlug);

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    if (slugInvalid || !name.trim() || !effectiveSlug) return;
    onSubmit({ name: name.trim(), slug: effectiveSlug });
  };

  return (
    <form onSubmit={submit} noValidate>
      <div className="flex flex-col gap-4">
        {error && !(error instanceof ApiError && error.status === 422) ? <ErrorAlert error={error} /> : null}
        <TextField
          label="Name"
          required
          maxLength={100}
          autoComplete="off"
          value={name}
          onChange={(e) => {
            setName(e.currentTarget.value);
          }}
          error={fieldErrors.name}
          data-autofocus
        />
        <TextField
          label="Slug"
          description="Used in URLs. Lowercase letters, digits, and single hyphens."
          required
          maxLength={40}
          autoComplete="off"
          spellCheck={false}
          className="font-mono"
          value={effectiveSlug}
          onChange={(e) => {
            setSlugTouched(true);
            setSlug(e.currentTarget.value);
          }}
          error={slugInvalid ? "Use lowercase letters, digits, and single hyphens" : fieldErrors.slug}
        />
        <div className="mt-2 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <Button variant="default" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="submit" loading={pending} disabled={!name.trim() || !effectiveSlug || slugInvalid}>
            {submitLabel}
          </Button>
        </div>
      </div>
    </form>
  );
}
