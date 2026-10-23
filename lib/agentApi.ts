import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed, PRIMESEC_ROLES } from "./auth";
import type { AuditActor } from "./audit";
import { AgentSecError } from "./agentsec";
import { logError } from "./log";

export type Need = "view" | "analyst" | "admin";
export type Ctx = { actor: AuditActor; roles: string[]; isAdmin: boolean };

/**
 * Shared checks for the agent-security API: session, role, and (for anything that changes state) origin.
 * "view" = any PrimeSEC role; "analyst" = SOC_Analyst or SOC_Admin; "admin" = SOC_Admin only.
 * Changing what an agent may do (registry, policies) is admin-only because it is the trust boundary.
 */
export async function agentGuard(req: NextApiRequest, res: NextApiResponse, need: Need): Promise<Ctx | null> {
  const session = await getServerSession(req, res, authOptions);
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (!session) { res.status(401).json({ error: "Authentication required" }); return null; }
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => PRIMESEC_ROLES.includes(r))) { res.status(403).json({ error: "A PrimeSEC role is required." }); return null; }
  const isAdmin = roles.includes("SOC_Admin");
  if (need === "admin" && !isAdmin) { res.status(403).json({ error: "SOC_Admin role required." }); return null; }
  if (need === "analyst" && !(isAdmin || roles.includes("SOC_Analyst"))) { res.status(403).json({ error: "SOC_Analyst or SOC_Admin role required." }); return null; }
  if (need !== "view" && !originIsAllowed(req)) { res.status(403).json({ error: "Cross-origin request rejected." }); return null; }
  return { actor: { name: session.user?.name ?? null, email: session.user?.email ?? null, roles }, roles, isAdmin };
}

const STATUS = { INVALID: 400, NOT_FOUND: 404, CONFLICT: 409, LOCKED: 409 } as const;
/** Maps our own errors to a status; anything else is logged and returned as a generic 500. */
export function fail(res: NextApiResponse, error: unknown, context: string) {
  if (error instanceof AgentSecError) return res.status(STATUS[error.code]).json({ error: error.message });
  logError(context, error);
  return res.status(500).json({ error: "The agent-security store is unavailable." });
}
