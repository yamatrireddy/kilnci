// SPDX-License-Identifier: Apache-2.0
import { Alert, Button, Center, Paper, Stack, Text, TextInput, Title } from "@mantine/core";
import { IconFlame } from "@tabler/icons-react";
import { useState, type SyntheticEvent } from "react";

/** First-run screen: which Kiln server should this app talk to? */
export function ServerSetup({ onSave }: { onSave: (url: string) => Promise<void> }) {
  const [url, setUrl] = useState("https://");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    onSave(url.trim()).catch((err: unknown) => {
      setError(typeof err === "string" ? err : "That server URL is not valid.");
      setBusy(false);
    });
  };

  return (
    <Center component="main" mih="100vh" p="md">
      <Paper withBorder shadow="sm" p="xl" radius="lg" maw={460} w="100%">
        <form onSubmit={submit} noValidate>
          <Stack>
            <Stack gap={4} align="center">
              <IconFlame size={40} aria-hidden color="var(--mantine-color-kiln-6)" />
              <Title order={1} size="h2">
                Connect to Kiln
              </Title>
              <Text c="dimmed" size="sm" ta="center">
                Enter the address of your organization&apos;s Kiln server.
              </Text>
            </Stack>
            {error ? (
              <Alert color="red" variant="light" role="alert">
                {error}
              </Alert>
            ) : null}
            <TextInput
              label="Server URL"
              description="Must use https (http is allowed only for localhost)."
              value={url}
              onChange={(e) => {
                setUrl(e.currentTarget.value);
              }}
              required
              data-autofocus
            />
            <Button type="submit" loading={busy}>
              Continue
            </Button>
          </Stack>
        </form>
      </Paper>
    </Center>
  );
}
