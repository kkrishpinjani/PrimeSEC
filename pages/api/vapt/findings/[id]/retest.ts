import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed } from "../../../../../lib/auth";
import { getFinding, markRetestRequested } from "../../../../../lib/findings";
import { startAuthorizedScan } from "../../../../../lib/vaptLaunch";
import { writeAuditEvent } from "../../../../../lib/audit";
import { logError } from "../../../../../lib/log";

const FINDING_ID = /^vuln_[0-9a-f]{16}$/;

/**
 * Requests a new scan of a finding's host. This is NOT a separate, lighter path: it goes through the same
 * startAuthorizedScan() as any scan, so the host must be inside a current approved scope, the audit event is
 * written before Greenbone is called, and the scan rate limit applies. Nothing is fixed or changed on the host.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r))) return res.status(403).json({ error: "SOC_Analyst or SOC_Admin role required." });
  if (!originIsAllowed(req)) return res.status(403).json({ error: "Cross-origin request rejected." });

  const id = String(req.query.id ?? "");
  if (!FINDING_ID.test(id)) return res.status(400).json({ error: "A valid finding id is required." });

  let finding;
  try {
    finding = await getFinding(id);
  } catch (error) {
    logError("retest: reading findings", error);
    return res.status(500).json({ error: "The findings store is unavailable." });
  }
  if (!finding) return res.status(404).json({ error: "Finding not found. Sync Greenbone findings and try again." });

  const actor = { name: session.user?.name ?? null, email: session.user?.email ?? null, roles };
  const outcome = await startAuthorizedScan({ actor, target: finding.host, name: `Retest ${finding.id}`, findingId: finding.id });
  if (!outcome.ok) {
    if (outcome.retryAfter) res.setHeader("Retry-After", String(outcome.retryAfter));
    return res.status(outcome.status).json({ error: outcome.error });
  }

  let updated = finding;
  let warning: string | undefined;
  try {
    updated = await markRetestRequested(finding.id, outcome.assessment.taskId ?? null, actor);
  } catch (error) {
    warning = "The scan started but the finding could not be updated. Record the task id manually.";
    logError("retest: scan started but marking the finding failed", error);
  }
  try {
    await writeAuditEvent({
      action: "vapt_finding_retest_requested", actor,
      finding: { id: finding.id, host: finding.host, port: finding.port, name: finding.name },
      target: outcome.assessment.target, taskId: outcome.assessment.taskId ?? null
    });
  } catch (error) {
    logError("retest: linking audit event failed", error);
  }
  return res.status(201).json({ finding: updated, assessment: outcome.assessment, auditEventId: outcome.auditEventId, warning });
}
