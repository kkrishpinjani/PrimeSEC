import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed } from "../../../lib/auth";
import { launchVaptAssessment, normalizeTarget, readScopes, targetAllowed } from "../../../lib/vapt";
import { writeAuditEvent } from "../../../lib/audit";
import { allowRequest } from "../../../lib/rateLimit";
import { logError } from "../../../lib/log";

/**
 * Starts a Greenbone scan. The target must lie inside a current, approved, unrevoked scope; that check
 * happens here, before the bridge is called. Order matters: the audit event is written BEFORE the
 * irreversible call, so a scan can never exist without an audit record (if the audit log is
 * unavailable, the scan is not started). Refused attempts are audited too.
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

  let scopes;
  try {
    scopes = await readScopes();
  } catch (error) {
    logError("vapt assessments: reading scope store", error);
    return res.status(500).json({ error: "The scope store is unavailable, so no scan can be authorized right now." });
  }

  const scope = targetAllowed(target, scopes);
  if (!scope) {
    try {
      await writeAuditEvent({ action: "vapt_assessment_denied", actor, target, reason: "target not covered by a current approved scope" });
    } catch (error) {
      logError("vapt assessments: auditing a refused scan", error);
    }
    return res.status(403).json({ error: "Target is not covered by a current approved PrimeSEC scope. Ask a SOC_Admin to register written authorization first." });
  }

  // Audit first (fail closed): no audit record, no scan.
  let requested;
  try {
    requested = await writeAuditEvent({ action: "vapt_assessment_requested", actor, target, scopeId: scope.id });
  } catch (error) {
    logError("vapt assessments: audit unavailable, scan NOT started", error);
    return res.status(503).json({ error: "The audit log is unavailable, so the scan was not started." });
  }

  try {
    const result = await launchVaptAssessment({ target, name: req.body?.name });
    let auditEventId = requested.eventId;
    try {
      const started = await writeAuditEvent({
        action: "vapt_assessment_started", actor, target, scopeId: scope.id,
        assessment: { taskId: result.taskId, targetId: result.targetId, targetName: result.targetName, status: result.status }
      });
      auditEventId = started.eventId;
    } catch (error) {
      logError("vapt assessments: scan started but the completion audit failed", error);
    }
    return res.status(201).json({ assessment: result, auditEventId, scope: { id: scope.id, name: scope.name } });
  } catch (error) {
    const code = (error as { code?: string }).code;
    logError("vapt assessments: launch failed", error);
    try {
      await writeAuditEvent({ action: "vapt_assessment_failed", actor, target, scopeId: scope.id, reason: String((error as Error).message).slice(0, 200) });
    } catch (auditError) {
      logError("vapt assessments: auditing a failed launch", auditError);
    }
    return res.status(code === "NOT_CONFIGURED" ? 503 : 502).json({ error: (error as Error).message || "Assessment could not be started." });
  }
}
