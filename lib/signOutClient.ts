import { signOut } from "next-auth/react";

/** Clears this app's session and, for a Keycloak sign-in, the Keycloak SSO session as well. */
export async function fullSignOut(): Promise<void> {
  let destination = "/login";
  try {
    const r = await fetch("/api/logout-url", { cache: "no-store", headers: { Accept: "application/json" } });
    if (r.ok) destination = ((await r.json()) as { url?: string }).url || destination;
  } catch {
    /* fall back to /login */
  }
  await signOut({ redirect: false });
  window.location.href = destination;
}
