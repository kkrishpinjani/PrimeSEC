import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed } from "../../../../lib/auth";
import { getBridgeFindings } from "../../../../lib/vapt";
import { syncFindings } from "../../../../lib/findings";
import { writeAuditEvent } from "../../../../lib/audit";
import { allowRequest } from "../../../../lib/rateLimit";
import { logError } from "../../../../lib/log";

/**
 * Imports recent Greenbone report results into the findings store. A POST (not a GET with a query flag):
 * it calls an upstream service and writes a file, so it must not be triggerable by a cross-site link.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r))) return res.status(403).json({ error: "SOC_Analyst or SOC_Admin role required to sync findings." });
  if (!originIsAllowed(req)) return res.status(403).json({ error: "Cross-origin request rejected." });

  const actor = { name: session.user?.name ?? null, email: session.user?.email ?? null, roles };
  if (!allowRequest(`findings-sync:${actor.email || actor.name || "unknown"}`, 6, 10 * 60_000)) {
    res.setHeader("Retry-After", "600");
    return res.status(429).json({ error: "Too many syncs. Wait a few minutes and try again." });
  }

  let remote;
  try {
    remote = await getBridgeFindings();
  } catch (error) {
    logError("findings sync: bridge", error);
    const code = (error as { code?: string }).code;
    return res.status(code === "NOT_CONFIGURED" ? 503 : 502).json({ error: (error as Error).message || "Could not retrieve Greenbone findings." });
  }

  try {
    const result = await syncFindings(remote.findings, { truncated: remote.truncated });
    let auditRecorded = true;
    try {
      await writeAuditEvent({
        action: "vapt_findings_synchronized", actor,
        imported: result.imported, updated: result.updated, missing: result.missing, total: result.findings.length, truncated: result.truncated
      });
    } catch (error) {
      auditRecorded = false;
      logError("findings sync: the import succeeded but the audit write failed", error);
    }
    return res.status(200).json({
      imported: result.imported, updated: result.updated, missing: result.missing, total: result.findings.length,
      truncated: result.truncated, retrievedAt: remote.retrievedAt, auditRecorded
    });
  } catch (error) {
    logError("findings sync: storing findings", error);
    return res.status(500).json({ error: "The findings store is unavailable." });
  }
}
