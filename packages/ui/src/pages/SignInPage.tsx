// SPDX-License-Identifier: Apache-2.0
import { safeReturnPath, signInErrorMessage } from "@kiln/core";
import { Alert, Button, Center, Paper, Stack, Text, Title } from "@mantine/core";
import { IconFlame, IconLogin } from "@tabler/icons-react";
import { useState } from "react";
import { useSearchParams } from "react-router";

import { usePlatform } from "../platform";

export function SignInPage() {
  const { name, signIn } = usePlatform();
  const [params] = useSearchParams();
  const [busy, setBusy] = useState(false);
  const error = signInErrorMessage(params.get("error"));
  const returnTo = safeReturnPath(params.get("returnTo"));

  return (
    <Center component="main" mih="100vh" p="md">
      <Paper withBorder shadow="sm" p="xl" radius="lg" maw={420} w="100%">
        <Stack gap="md">
          <Stack gap={4} align="center">
            <IconFlame size={40} aria-hidden color="var(--mantine-color-kiln-6)" />
            <Title order={1} size="h2">
              Sign in to {name}
            </Title>
            <Text c="dimmed" size="sm" ta="center">
              Kiln uses your organization&apos;s identity provider. You will be redirected to sign in.
            </Text>
          </Stack>
          {error ? (
            <Alert color="red" variant="light" role="alert">
              {error}
            </Alert>
          ) : null}
          <Button
            size="md"
            leftSection={<IconLogin size={18} aria-hidden />}
            loading={busy}
            onClick={() => {
              setBusy(true);
              void Promise.resolve(signIn(returnTo)).catch(() => {
                setBusy(false);
              });
            }}
          >
            Continue with single sign-on
          </Button>
        </Stack>
      </Paper>
    </Center>
  );
}
