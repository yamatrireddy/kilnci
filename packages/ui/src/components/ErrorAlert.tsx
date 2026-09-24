// SPDX-License-Identifier: Apache-2.0
import { ApiError } from "@kiln/api-client";
import { Alert, Code, Text } from "@mantine/core";
import { IconAlertTriangle } from "@tabler/icons-react";

/** User-facing text for an error; never includes internal details. */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 401:
        return "Your session has ended. Sign in again to continue.";
      case 403:
        return "You do not have permission to do this.";
      case 404:
        return "This page does not exist, or you do not have access to it.";
      case 409:
        return "That conflicts with existing data (for example, the name is already taken).";
      case 422:
        return "Some fields are invalid. Check them and try again.";
      case 429:
        return "Too many requests. Wait a moment and try again.";
      default:
        return "Something went wrong on the server. Try again shortly.";
    }
  }
  return "Could not reach Kiln. Check your connection and try again.";
}

export function ErrorAlert({ error, title = "Something went wrong" }: { error: unknown; title?: string }) {
  const requestId = error instanceof ApiError ? error.problem?.requestId : undefined;
  return (
    <Alert color="red" variant="light" title={title} icon={<IconAlertTriangle aria-hidden />} role="alert">
      <Text size="sm">{errorMessage(error)}</Text>
      {requestId ? (
        <Text size="xs" c="dimmed" mt="xs">
          Request ID: <Code>{requestId}</Code>
        </Text>
      ) : null}
    </Alert>
  );
}
