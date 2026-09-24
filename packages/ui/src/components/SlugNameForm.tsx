// SPDX-License-Identifier: Apache-2.0
import { ApiError } from "@kiln/api-client";
import { Button, Group, Stack, TextInput } from "@mantine/core";
import { useState, type SyntheticEvent } from "react";

import { ErrorAlert } from "./ErrorAlert";

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
      <Stack>
        {error && !(error instanceof ApiError && error.status === 422) ? <ErrorAlert error={error} /> : null}
        <TextInput
          label="Name"
          required
          maxLength={100}
          value={name}
          onChange={(e) => {
            setName(e.currentTarget.value);
          }}
          error={fieldErrors.name}
          data-autofocus
        />
        <TextInput
          label="Slug"
          description="Used in URLs. Lowercase letters, digits, and single hyphens."
          required
          maxLength={40}
          value={effectiveSlug}
          onChange={(e) => {
            setSlugTouched(true);
            setSlug(e.currentTarget.value);
          }}
          error={slugInvalid ? "Use lowercase letters, digits, and single hyphens" : fieldErrors.slug}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="submit" loading={pending} disabled={!name.trim() || !effectiveSlug || slugInvalid}>
            {submitLabel}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
