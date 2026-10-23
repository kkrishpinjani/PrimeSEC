import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, demoLoginEnabled, originIsAllowed } from "../../../lib/auth";
import { clearAllFindingData, seedDemoData } from "../../../lib/demoData";
import { writeAuditEvent } from "../../../lib/audit";
import { logError } from "../../../lib/log";

/**
 * POST   load labelled sample findings (only while DEMO_LOGIN is on; never in a production build).
 * DELETE delete all findings, host context and report snapshots (any environment). Scopes and the audit log are kept.
 * SOC_Admin only, origin-checked, audited. Deleting needs {"confirm":"DELETE"} in the body so a stray request cannot do it.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  if (req.method !== "POST" && req.method !== "DELETE") return res.status(405).json({ error: "Method not allowed" });
  const roles = session.user?.roles ?? [];
  if (!roles.includes("SOC_Admin")) return res.status(403).json({ error: "SOC_Admin role required." });
  if (!originIsAllowed(req)) return res.status(403).json({ error: "Cross-origin request rejected." });
  const actor = { name: session.user?.name ?? null, email: session.user?.email ?? null, roles };

  try {
    if (req.method === "POST") {
      if (!demoLoginEnabled()) return res.status(403).json({ error: "Sample data is only available while demo mode (DEMO_LOGIN) is on." });
      const result = await seedDemoData();
      let auditRecorded = true;
      try { await writeAuditEvent({ action: "vapt_demo_data_seeded", actor, ...result }); } catch (error) { auditRecorded = false; logError("demo seed: audit write failed", error); }
      return res.status(200).json({ ...result, auditRecorded });
    }
    if ((req.body ?? {}).confirm !== "DELETE") return res.status(400).json({ error: 'Send {"confirm":"DELETE"} to confirm.' });
    const removed = await clearAllFindingData();
    let auditRecorded = true;
    try { await writeAuditEvent({ action: "vapt_data_cleared", actor, ...removed }); } catch (error) { auditRecorded = false; logError("data clear: audit write failed", error); }
    return res.status(200).json({ ...removed, auditRecorded });
  } catch (error) {
    if ((error as Error).message?.startsWith("Findings already exist")) return res.status(409).json({ error: (error as Error).message });
    logError("demo data", error);
    return res.status(500).json({ error: "The findings store is unavailable." });
  }
}
