import type { NextApiRequest, NextApiResponse } from "next";
import type { NextAuthOptions } from "next-auth";
import { getServerSession } from "next-auth/next";
import KeycloakProvider from "next-auth/providers/keycloak";
import CredentialsProvider from "next-auth/providers/credentials";

function decodeJwtPayload(token: string): { realm_access?: { roles?: string[] }; iss?: string } {
  try {
    const payload = token.split(".")[1];
    if (!payload) return {};
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(Buffer.from(normalized, "base64").toString("utf8"));
  } catch {
    return {};
  }
}

// Resolved per request (not at import) so `next build` works without a populated .env.
function requireAuthSecret(): string {
  const secret = process.env.NEXTAUTH_SECRET;
  if (!secret || secret.includes("replace-with")) {
    throw new Error(
      "NEXTAUTH_SECRET is missing or still the .env.example placeholder. Run scripts/setup.sh or scripts/setup.ps1 to generate one."
    );
  }
  return secret;
}

/**
 * Passwordless demo sign-in. Bypasses Keycloak, so it is opt-in (DEMO_LOGIN=true)
 * and can never be enabled in a production build.
 */
export function demoLoginEnabled(): boolean {
  return process.env.DEMO_LOGIN === "true" && process.env.NODE_ENV !== "production";
}

export const authOptions: NextAuthOptions = {
  providers: [
    KeycloakProvider({
      clientId: process.env.KEYCLOAK_CLIENT_ID ?? "",
      clientSecret: process.env.KEYCLOAK_CLIENT_SECRET ?? "",
      issuer: process.env.KEYCLOAK_ISSUER,
      authorization: { params: { scope: "openid email profile" } }
    }),
    ...(demoLoginEnabled()
      ? [
          CredentialsProvider({
            id: "demo",
            name: "Demo",
            credentials: {},
            async authorize() {
              if (!demoLoginEnabled()) return null;
              return { id: "demo-user", name: "Demo Analyst", email: "demo@primesec.local" };
            }
          })
        ]
      : [])
  ],
  get secret() {
    return requireAuthSecret();
  },
  session: { strategy: "jwt", maxAge: 8 * 60 * 60 },
  pages: { signIn: "/login" },
  callbacks: {
    async jwt({ token, account }) {
      if (account?.provider === "demo" && demoLoginEnabled()) {
        // Least-privilege by default; DEMO_LOGIN_ROLE=SOC_Analyst lets a local demo create investigations.
        const requested = process.env.DEMO_LOGIN_ROLE;
        token.roles = [requested && PRIMESEC_ROLES.includes(requested) ? requested : "SOC_ReadOnly"];
        token.issuer = "demo";
        return token;
      }
      if (account?.access_token) {
        // Roles are read server-side only; the access token itself is never stored in the JWT.
        const claims = decodeJwtPayload(account.access_token);
        token.roles = claims.realm_access?.roles ?? [];
        token.issuer = claims.iss;
      }
      return token;
    },
    async session({ session, token }) {
      const roles = Array.isArray(token.roles) ? token.roles : [];
      session.user = {
        ...session.user,
        roles,
        isPrimeSecAdmin: roles.includes("SOC_Admin")
      };
      return session;
    }
  }
};

/** Roles allowed to see PrimeSEC data. */
export const PRIMESEC_ROLES = ["SOC_Admin", "SOC_Analyst", "SOC_ReadOnly"];

/**
 * Guard for API routes: replies 401 without a session and 403 without a PrimeSEC role.
 * Returns true when the request may proceed.
 */
export async function requireSocSession(req: NextApiRequest, res: NextApiResponse): Promise<boolean> {
  const session = await getServerSession(req, res, authOptions);
  if (!session) {
    res.status(401).json({ error: "Authentication required" });
    return false;
  }
  if (!session.user?.roles?.some((r) => PRIMESEC_ROLES.includes(r))) {
    res.status(403).json({ error: "Forbidden" });
    return false;
  }
  return true;
}

/** Browser POST/DELETE must come from this app's own origin (a no-Origin request, e.g. curl, is allowed; it still needs a session). */
export function originIsAllowed(req: NextApiRequest): boolean {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const host = (req.headers["x-forwarded-host"] as string | undefined) || req.headers.host;
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}
