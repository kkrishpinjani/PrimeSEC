import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, PRIMESEC_ROLES } from "../../../lib/auth";
import { getVaptOverview, readScopes } from "../../../lib/vapt";
import { readAuditEvents } from "../../../lib/audit";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => PRIMESEC_ROLES.includes(r))) return res.status(403).json({ error: "A PrimeSEC role is required." });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");

  const [scanner, scopes, audit] = await Promise.all([
    getVaptOverview(),
    readScopes().catch(() => []),
    readAuditEvents(15, ["vapt_scope_approved", "vapt_scope_revoked", "vapt_assessment_started", "vapt_assessment_denied"]).catch(() => [])
  ]);
  return res.status(200).json({
    scanner,
    scopes,
    audit,
    canApprove: roles.includes("SOC_Admin"),
    canScan: roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r))
  });
}
