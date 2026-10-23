import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard, fail } from "../../../lib/agentApi";
import { evaluateAction, readState, recordEvaluation, TOOL_NAME } from "../../../lib/agentsec";
import { writeAuditEvent } from "../../../lib/audit";
import { allowRequest } from "../../../lib/rateLimit";
import { logError } from "../../../lib/log";

/**
 * Asks whether a proposed agent action should be allowed. It runs nothing and calls nothing: it returns a decision, writes
 * an audit event and, for a non-ALLOW result, a (deduplicated) finding. SOC_Analyst or SOC_Admin; rate-limited.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "analyst");
  if (!ctx) return;
  if (!allowRequest(`agent-evaluate:${ctx.actor.email || ctx.actor.name || "unknown"}`, 120, 60_000)) {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({ error: "Too many evaluations. Wait a minute and try again." });
  }
  const b = (req.body ?? {}) as Record<string, unknown>;
  const agentId = typeof b.agentId === "string" ? b.agentId.trim() : "";
  const tool = typeof b.tool === "string" ? b.tool.trim() : "";
  if (!agentId || agentId.length > 120 || /[\u0000-\u001f\u007f]/.test(agentId)) return res.status(400).json({ error: "A valid agentId is required." });
  if (!TOOL_NAME.test(tool)) return res.status(400).json({ error: "tool is required and may use letters, digits and . _ : / - only." });
  const dataClass = typeof b.dataClass === "string" ? b.dataClass.slice(0, 80) : "unknown";
  const input = { agentId, tool, dataClass, target: typeof b.target === "string" ? b.target.slice(0, 160) : "", external: b.external === true, sensitive: b.sensitive === true };
  try {
    const e = evaluateAction(await readState(), input);
    let eventId: string | null = null;
    let auditRecorded = true;
    try {
      const event = await writeAuditEvent({ action: "agent_policy_evaluated", actor: ctx.actor, agentId: agentId.slice(0, 120), tool, decision: e.decision, dataClass: dataClass.slice(0, 80), external: input.external, policyRevision: e.policyRevision, reasonPolicies: e.reasons.map((r) => r.policyId) });
      eventId = event.eventId;
    } catch (error) {
      auditRecorded = false;
      logError("agents: evaluated but the audit write failed", error);
    }
    await recordEvaluation(e, eventId);
    return res.status(200).json({ ...e, eventId, auditRecorded });
  } catch (error) {
    return fail(res, error, "agent evaluate");
  }
}
