// SPDX-License-Identifier: Apache-2.0

/** Messages for the coarse reasons the server puts in /signin?error=. */
export function signInErrorMessage(code: string | null): string | null {
  switch (code) {
    case null:
    case "":
      return null;
    case "not_invited":
      return "Your identity provider signed you in, but you do not have a Kiln account yet. Ask an org admin to invite your email address.";
    default:
      return "Sign-in failed or expired. Please try again.";
  }
}

/**
 * Returns `path` if it is a same-origin path that is safe to return to after
 * sign-in, otherwise "/". The server validates this again.
 */
export function safeReturnPath(path: string | null | undefined): string {
  if (!path?.startsWith("/") || path.startsWith("//") || path.includes("\\") || path.length > 512) {
    return "/";
  }
  for (let i = 0; i < path.length; i++) {
    const c = path.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return "/";
  }
  if (path.startsWith("/signin")) return "/";
  return path;
}
