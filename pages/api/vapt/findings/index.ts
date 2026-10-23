import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, demoLoginEnabled, PRIMESEC_ROLES } from "../../../../lib/auth";
import { EXPLOIT_EVIDENCE, readFindings, STATUSES } from "../../../../lib/findings";
import { logError } from "../../../../lib/log";

/** Read-only list of the locally stored, normalized findings (any PrimeSEC role). Syncing is a separate POST. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => PRIMESEC_ROLES.includes(r))) return res.status(403).json({ error: "A PrimeSEC role is required." });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  try {
    const findings = await readFindings();
    const count = <K extends string>(key: (f: (typeof findings)[number]) => K) => {
      const out: Record<string, number> = {};
      for (const f of findings) out[key(f)] = (out[key(f)] ?? 0) + 1;
      return out;
    };
    return res.status(200).json({
      findings,
      summary: { total: findings.length, bySeverity: count((f) => f.severity), byStatus: count((f) => f.remediationStatus), notInLatestSync: findings.filter((f) => f.notInLatestSync).length },
      statuses: STATUSES,
      exploitEvidenceOptions: EXPLOIT_EVIDENCE,
      canEdit: roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r)),
      isAdmin: roles.includes("SOC_Admin"),
      demoDataAvailable: demoLoginEnabled()
    });
  } catch (error) {
    logError("findings: reading the findings store", error);
    return res.status(500).json({ error: "The findings store is unavailable." });
  }
}
