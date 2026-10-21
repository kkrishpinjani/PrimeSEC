import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed } from "../../../lib/auth";
import { startAuthorizedScan } from "../../../lib/vaptLaunch";

/** Starts a Greenbone scan. All guards (rate limit, scope, audit-before-launch) live in lib/vaptLaunch.ts. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r))) {
    return res.status(403).json({ error: "SOC_Analyst or SOC_Admin role required to launch a scan." });
  }
  if (!originIsAllowed(req)) return res.status(403).json({ error: "Cross-origin request rejected." });

  const actor = { name: session.user?.name ?? null, email: session.user?.email ?? null, roles };
  const outcome = await startAuthorizedScan({ actor, target: req.body?.target, name: req.body?.name });
  if (!outcome.ok) {
    if (outcome.retryAfter) res.setHeader("Retry-After", String(outcome.retryAfter));
    return res.status(outcome.status).json({ error: outcome.error });
  }
  return res.status(201).json({ assessment: outcome.assessment, auditEventId: outcome.auditEventId, scope: outcome.scope });
}
