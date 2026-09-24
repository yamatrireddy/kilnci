// SPDX-License-Identifier: Apache-2.0

/** RFC 4648 base64url without padding. */
export function base64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** 256 random bits from the platform CSPRNG, base64url (43 chars). */
export function randomToken(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return base64Url(b);
}

/** A PKCE pair (RFC 7636, S256) for the desktop sign-in flow. */
export interface PkcePair {
  verifier: string;
  challenge: string;
}

export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64Url(new Uint8Array(digest));
}

export async function createPkcePair(): Promise<PkcePair> {
  const verifier = randomToken();
  return { verifier, challenge: await pkceChallenge(verifier) };
}
