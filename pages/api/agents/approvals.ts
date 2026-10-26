import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard, fail } from "../../../lib/agentApi";
import { decideApproval } from "../../../lib/agentgate";
import { readState } from "../../../lib/agentsec";
import { writeAuditEvent } from "../../../lib/audit";
import { allowRequest } from "../../../lib/rateLimit";
import { logError } from "../../../lib/log";

/**
 * GET: the approval queue (any role). POST: approve or reject a request (SOC_Analyst or SOC_Admin).
 * The approver cannot be the person who made the request. Approving does not run anything and does not override a denial:
 * it only lets the same requester submit the same action once more and receive a permit.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST") { res.setHeader("Allow", "GET, POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, req.method === "GET" ? "view" : "analyst");
  if (!ctx) return;
  try {
    if (req.method === "GET") {
      const state = await readState();
      const now = Date.now();
      const status = typeof req.query.status === "string" ? req.query.status : "";
      const approvals = state.approvals
        .map((a) => (a.status === "pending" && Date.parse(a.expiresAt) <= now ? { ...a, status: "expired" as const } : a))
        .filter((a) => !status || a.status === status).slice(0, 200)
        .map((a) => ({ ...a, mine: !!ctx.actor.email && a.requestedBy.email === ctx.actor.email }));
      return res.status(200).json({ approvals });
    }
    if (!allowRequest(`agent-approvals:${ctx.actor.email || ctx.actor.name || "unknown"}`, 60, 60_000)) {
      res.setHeader("Retry-After", "60");
      return res.status(429).json({ error: "Too many decisions. Wait a minute and try again." });
    }
    const b = (req.body ?? {}) as Record<string, unknown>;
    const id = typeof b.id === "string" ? b.id.trim().slice(0, 40) : "";
    const out = await decideApproval(id, b.decision, b.note, ctx.actor);
    if (!out.ok) return res.status(out.status).json({ error: out.error });
    let auditRecorded = true;
    try {
      await writeAuditEvent({ action: "agent_approval_decided", actor: ctx.actor, approvalId: out.approval.id, agentId: out.approval.agentId, tool: out.approval.tool, decision: out.approval.status, requestedBy: out.approval.requestedBy.email });
    } catch (error) {
      auditRecorded = false;
      logError("agents approvals: decided but the audit write failed", error);
    }
    return res.status(200).json({
      approval: out.approval, auditRecorded,
      message: out.approval.status === "approved"
        ? "Approval recorded. Nothing was executed. The requester can now submit the same action once more to receive a permit, within 10 minutes."
        : "Request rejected. Nothing was executed."
    });
  } catch (error) {
    return fail(res, error, "agents approvals");
  }
}
