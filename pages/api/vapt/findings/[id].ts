import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed } from "../../../../lib/auth";
import { FindingError, getFinding, updateFinding, type Patch } from "../../../../lib/findings";
import { writeAuditEvent } from "../../../../lib/audit";
import { logError } from "../../../../lib/log";

const FINDING_ID = /^vuln_[0-9a-f]{16}$/;
const STATUS_FOR = { NOT_FOUND: 404, INVALID: 400, CONFLICT: 409, FORBIDDEN: 403 } as const;

/** Updates remediation status, owner and notes. Only the fields present in the body change. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  if (req.method !== "PATCH") return res.status(405).json({ error: "Method not allowed" });
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r))) return res.status(403).json({ error: "SOC_Analyst or SOC_Admin role required." });
  if (!originIsAllowed(req)) return res.status(403).json({ error: "Cross-origin request rejected." });

  const id = String(req.query.id ?? "");
  if (!FINDING_ID.test(id)) return res.status(400).json({ error: "A valid finding id is required." });

  // Whitelist: nothing but these four keys ever reaches the store, whatever the client sends.
  const body = (req.body ?? {}) as Record<string, unknown>;
  const patch: Patch = {};
  for (const key of ["remediationStatus", "owner", "remediationNotes", "exploitEvidence", "expectedUpdatedAt"] as const) if (key in body) patch[key] = body[key];

  const actor = { name: session.user?.name ?? null, email: session.user?.email ?? null, roles };
  try {
    const before = await getFinding(id);
    const finding = await updateFinding(id, patch, actor);
    let auditRecorded = true;
    try {
      const changes = (["remediationStatus", "owner", "remediationNotes", "exploitEvidence"] as const).filter((k) => before && before[k] !== finding[k]);
      await writeAuditEvent({
        action: "vapt_finding_updated", actor,
        finding: { id: finding.id, host: finding.host, port: finding.port, name: finding.name, cves: finding.cves },
        changes: changes as string[],
        status: { from: before?.remediationStatus ?? "", to: finding.remediationStatus }
      });
    } catch (error) {
      auditRecorded = false;
      logError("finding update: applied but the audit write failed", error);
    }
    return res.status(200).json({ finding, auditRecorded });
  } catch (error) {
    if (error instanceof FindingError) return res.status(STATUS_FOR[error.code]).json({ error: error.message });
    logError("finding update", error);
    return res.status(500).json({ error: "The findings store is unavailable." });
  }
}
