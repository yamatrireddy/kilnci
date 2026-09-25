// SPDX-License-Identifier: Apache-2.0
import { Alert, Button, TextField } from "@kiln/ui";
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
    <main className="grid min-h-screen place-items-center bg-subtle p-4">
      <div className="w-full max-w-[460px] rounded-xl border border-line bg-surface p-6 shadow-sm sm:p-8">
        <form onSubmit={submit} noValidate>
          <div className="flex flex-col gap-5">
            <div className="flex flex-col items-center gap-1 text-center">
              <IconFlame size={40} aria-hidden className="text-kiln-600 dark:text-kiln-400" />
              <h1 className="mt-1 text-2xl">Connect to Kiln</h1>
              <p className="text-sm text-dimmed">Enter the address of your organization&apos;s Kiln server.</p>
            </div>
            {error ? (
              <Alert tone="red" role="alert">
                {error}
              </Alert>
            ) : null}
            <TextField
              label="Server URL"
              description="Must use https (http is allowed only for localhost)."
              type="url"
              inputMode="url"
              autoComplete="url"
              spellCheck={false}
              value={url}
              onChange={(e) => {
                setUrl(e.currentTarget.value);
              }}
              required
            />
            <Button type="submit" size="lg" fullWidth loading={busy}>
              Continue
            </Button>
          </div>
        </form>
      </div>
    </main>
  );
}
