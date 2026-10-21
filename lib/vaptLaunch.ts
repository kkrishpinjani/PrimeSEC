/**
 * The ONE way a scan starts (new assessment or a finding retest). Everything that must hold for a scan
 * lives here so no entry point can skip a guard:
 *   rate limit -> target rules -> approved, unexpired, unrevoked scope -> AUDIT -> launch -> audit result.
 * The audit event is written BEFORE Greenbone is called: no audit record, no scan.
 */
import { writeAuditEvent, type AuditActor } from "./audit";
import { allowRequest } from "./rateLimit";
import { logError } from "./log";
import { launchVaptAssessment, normalizeTarget, readScopes, targetAllowed, type VaptAssessment } from "./vapt";

export type LaunchOutcome =
  | { ok: true; status: 201; assessment: VaptAssessment; scope: { id: string; name: string }; auditEventId: string }
  | { ok: false; status: number; error: string; retryAfter?: number };

export const SCAN_LIMIT = { max: 5, windowMs: 10 * 60_000 };

export async function startAuthorizedScan(input: { actor: AuditActor; target: unknown; name?: unknown; findingId?: string }): Promise<LaunchOutcome> {
  const { actor, findingId } = input;
  const actorKey = actor.email || actor.name || "unknown";
  if (!allowRequest(`scan:${actorKey}`, SCAN_LIMIT.max, SCAN_LIMIT.windowMs)) {
    return { ok: false, status: 429, error: "Too many scans started. Wait a few minutes and try again.", retryAfter: SCAN_LIMIT.windowMs / 1000 };
  }

  let target: string;
  try {
    target = normalizeTarget(input.target);
  } catch (error) {
    return { ok: false, status: 400, error: (error as Error).message };
  }

  let scopes;
  try {
    scopes = await readScopes();
  } catch (error) {
    logError("scan launch: reading scope store", error);
    return { ok: false, status: 500, error: "The scope store is unavailable, so no scan can be authorized right now." };
  }

  const scope = targetAllowed(target, scopes);
  if (!scope) {
    try {
      await writeAuditEvent({ action: "vapt_assessment_denied", actor, target, findingId, reason: "target not covered by a current approved scope" });
    } catch (error) {
      logError("scan launch: auditing a refused scan", error);
    }
    return { ok: false, status: 403, error: "Target is not covered by a current approved PrimeSEC scope. Ask a SOC_Admin to register written authorization first." };
  }

  let requested;
  try {
    requested = await writeAuditEvent({ action: "vapt_assessment_requested", actor, target, scopeId: scope.id, findingId });
  } catch (error) {
    logError("scan launch: audit unavailable, scan NOT started", error);
    return { ok: false, status: 503, error: "The audit log is unavailable, so the scan was not started." };
  }

  try {
    const assessment = await launchVaptAssessment({ target, name: input.name });
    let auditEventId = requested.eventId;
    try {
      const started = await writeAuditEvent({
        action: "vapt_assessment_started", actor, target, scopeId: scope.id, findingId,
        assessment: { taskId: assessment.taskId, targetId: assessment.targetId, targetName: assessment.targetName, status: assessment.status }
      });
      auditEventId = started.eventId;
    } catch (error) {
      logError("scan launch: scan started but the completion audit failed", error);
    }
    return { ok: true, status: 201, assessment, scope: { id: scope.id, name: scope.name }, auditEventId };
  } catch (error) {
    logError("scan launch: launch failed", error);
    try {
      await writeAuditEvent({ action: "vapt_assessment_failed", actor, target, scopeId: scope.id, findingId, reason: String((error as Error).message).slice(0, 200) });
    } catch (auditError) {
      logError("scan launch: auditing a failed launch", auditError);
    }
    const code = (error as { code?: string }).code;
    return { ok: false, status: code === "NOT_CONFIGURED" ? 503 : 502, error: (error as Error).message || "Assessment could not be started." };
  }
}
