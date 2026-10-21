import type { NextApiRequest, NextApiResponse } from "next";
import { getToken } from "next-auth/jwt";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../lib/auth";

/**
 * Where the browser should go after the local session is cleared. For a Keycloak sign-in this is Keycloak's
 * end-session endpoint (so "Sign out" really signs out, instead of silently signing back in through the
 * live SSO session); for the demo login there is no Keycloak session, so it is just /login.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");

  const issuer = (process.env.KEYCLOAK_ISSUER || "").replace(/\/+$/, "");
  const appUrl = (process.env.NEXTAUTH_URL || "").replace(/\/+$/, "");
  const token = await getToken({ req, secret: process.env.NEXTAUTH_SECRET });
  if (!issuer || !appUrl || !token?.idToken) return res.status(200).json({ url: "/login" });

  const url =
    `${issuer}/protocol/openid-connect/logout` +
    `?id_token_hint=${encodeURIComponent(token.idToken)}` +
    `&post_logout_redirect_uri=${encodeURIComponent(`${appUrl}/login`)}`;
  return res.status(200).json({ url });
}
