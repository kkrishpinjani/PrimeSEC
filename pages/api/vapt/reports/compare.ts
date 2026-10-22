import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, PRIMESEC_ROLES } from "../../../../lib/auth";
import { compareReports, CompareError } from "../../../../lib/reports";
import { writeAuditEvent } from "../../../../lib/audit";
import { logError } from "../../../../lib/log";

/**
 * Compares two imported reports (read-only, any PrimeSEC role). It never closes or changes a finding. Each view is
 * audited (best effort: a failing audit write is logged but does not block reading).
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => PRIMESEC_ROLES.includes(r))) return res.status(403).json({ error: "A PrimeSEC role is required." });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");

  const pick = (v: unknown) => (typeof v === "string" && v.length <= 200 ? v : "");
  try {
    const result = await compareReports(pick(req.query.baseline), pick(req.query.retest));
    try {
      await writeAuditEvent({
        action: "vapt_report_comparison_viewed",
        actor: { name: session.user?.name ?? null, email: session.user?.email ?? null, roles },
        baselineReportId: result.baselineReportId, retestReportId: result.retestReportId, summary: result.summary
      });
    } catch (error) {
      logError("report comparison: audit write failed", error);
    }
    return res.status(200).json(result);
  } catch (error) {
    if (error instanceof CompareError) return res.status(error.code === "NOT_FOUND" ? 404 : 400).json({ error: error.message });
    logError("report comparison", error);
    return res.status(500).json({ error: "Could not compare reports." });
  }
}
