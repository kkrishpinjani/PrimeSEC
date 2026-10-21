import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed } from "../../../lib/auth";
import { launchVaptAssessment, normalizeTarget, readScopes, targetAllowed } from "../../../lib/vapt";
import { writeAuditEvent } from "../../../lib/audit";
import { allowRequest } from "../../../lib/rateLimit";

/**
 * Starts a Greenbone scan. The target must lie inside a current, approved, unrevoked scope; that
 * check happens here, before the bridge is called. Refused attempts are audited too.
 */
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
  const actorKey = actor.email || actor.name || "unknown";
  if (!allowRequest(`scan:${actorKey}`, 5, 10 * 60_000)) {
    res.setHeader("Retry-After", "600");
    return res.status(429).json({ error: "Too many scans started. Wait a few minutes and try again." });
  }

  let target: string;
  try {
    target = normalizeTarget(req.body?.target);
  } catch (error) {
    return res.status(400).json({ error: (error as Error).message });
  }

  const scope = targetAllowed(target, await readScopes());
  if (!scope) {
    await writeAuditEvent({ action: "vapt_assessment_denied", actor, target, reason: "target not covered by a current approved scope" });
    return res.status(403).json({ error: "Target is not covered by a current approved PrimeSEC scope. Ask a SOC_Admin to register written authorization first." });
  }

  try {
    const result = await launchVaptAssessment({ target, name: req.body?.name });
    const audit = await writeAuditEvent({
      action: "vapt_assessment_started", actor, target, scopeId: scope.id,
      assessment: { taskId: result.taskId, targetId: result.targetId, targetName: result.targetName, status: result.status }
    });
    return res.status(201).json({ assessment: result, auditEventId: audit.eventId, scope: { id: scope.id, name: scope.name } });
  } catch (error) {
    const code = (error as { code?: string }).code;
    return res.status(code === "NOT_CONFIGURED" ? 503 : 502).json({ error: (error as Error).message || "Assessment could not be started." });
  }
}
