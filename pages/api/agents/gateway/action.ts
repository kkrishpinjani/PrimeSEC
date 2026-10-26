import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard, fail } from "../../../../lib/agentApi";
import { authorize, voidGrant } from "../../../../lib/agentgate";
import { TOOL_NAME } from "../../../../lib/agentsec";
import { writeAuditEvent } from "../../../../lib/audit";
import { allowRequest } from "../../../../lib/rateLimit";
import { logError } from "../../../../lib/log";

/**
 * The action gateway. A caller proposes an agent action BEFORE doing it:
 *   ALLOW -> a one-time permit; REQUIRE_APPROVAL -> a pending approval (or, once a person approved this exact action, a permit);
 *   DENY / REVIEW -> nothing. PrimeSEC executes nothing. SOC_Analyst or SOC_Admin; origin-checked; rate-limited; audited.
 * If the decision cannot be audited, a permit is withdrawn and nothing is issued (fail closed).
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "analyst");
  if (!ctx) return;
  if (!allowRequest(`agent-gateway:${ctx.actor.email || ctx.actor.name || "unknown"}`, 120, 60_000)) {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({ error: "Too many gateway requests. Wait a minute and try again." });
  }
  const b = (req.body ?? {}) as Record<string, unknown>;
  const agentId = typeof b.agentId === "string" ? b.agentId.trim() : "";
  const tool = typeof b.tool === "string" ? b.tool.trim() : "";
  if (!agentId || agentId.length > 120 || /[\u0000-\u001f\u007f]/.test(agentId)) return res.status(400).json({ error: "A valid agentId is required." });
  if (!TOOL_NAME.test(tool)) return res.status(400).json({ error: "tool is required and may use letters, digits and . _ : / - only." });
  try {
    const out = await authorize(
      { agentId, tool, dataClass: typeof b.dataClass === "string" ? b.dataClass : "unknown", target: typeof b.target === "string" ? b.target : "", external: b.external === true, sensitive: b.sensitive === true },
      ctx.actor
    );
    try {
      await writeAuditEvent({ action: "agent_gateway_decision", actor: ctx.actor, requestId: out.requestId, agentId: agentId.slice(0, 120), tool, decision: out.decision, status: out.status, approvalId: out.approvalId ?? null, authorizedByApproval: out.authorizedByApproval, policyRevision: out.policyRevision });
    } catch (error) {
      logError("agents gateway: audit write failed; permit withdrawn", error);
      if (out.permit && out.grantId) await voidGrant(out.grantId);
      return res.status(503).json({ error: "The decision could not be recorded in the audit log, so no permit was issued. Try again." });
    }
    return res.status(out.status === "pending_approval" ? 202 : 200).json(out);
  } catch (error) {
    return fail(res, error, "agents gateway");
  }
}
