// SPDX-License-Identifier: Apache-2.0
import { safeReturnPath, signInErrorMessage } from "@kiln/core";
import { IconFlame, IconLogin } from "@tabler/icons-react";
import { useState } from "react";
import { useSearchParams } from "react-router";

import { Alert, Button } from "../components/ui";
import { usePlatform } from "../platform";

export function SignInPage() {
  const { name, signIn } = usePlatform();
  const [params] = useSearchParams();
  const [busy, setBusy] = useState(false);
  const error = signInErrorMessage(params.get("error"));
  const returnTo = safeReturnPath(params.get("returnTo"));

  return (
    <main className="grid min-h-screen place-items-center bg-subtle p-4">
      <div className="w-full max-w-[420px] rounded-xl border border-line bg-surface p-6 shadow-sm sm:p-8">
        <div className="flex flex-col gap-5">
          <div className="flex flex-col items-center gap-1 text-center">
            <IconFlame size={40} aria-hidden className="text-kiln-600 dark:text-kiln-400" />
            <h1 className="mt-1 text-2xl">Sign in to {name}</h1>
            <p className="text-sm text-dimmed">
              Kiln uses your organization&apos;s identity provider. You will be redirected to sign in.
            </p>
          </div>
          {error ? (
            <Alert tone="red" role="alert">
              {error}
            </Alert>
          ) : null}
          <Button
            size="lg"
            fullWidth
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
        </div>
      </div>
    </main>
  );
}
