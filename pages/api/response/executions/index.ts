import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../../lib/agentApi";
import { executeProposal, type Phase } from "../../../../lib/response";
import { ensureAdapters } from "../../../../lib/responseAdapters";
import { respFail } from "../../../../lib/responseApi";
import { writeAuditEvent } from "../../../../lib/audit";
import { allowRequest } from "../../../../lib/rateLimit";

/**
 * POST { proposalId } with an Idempotency-Key header: execute an APPROVED proposal. SOC_Admin only.
 * Disabled by default; with no adapter registered it answers 503. The audit "requested" record is written BEFORE the adapter
 * is called, and if it cannot be written nothing is executed.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  ensureAdapters();
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "admin");
  if (!ctx) return;
  const by = ctx.actor.email || ctx.actor.name || "unknown";
  if (!allowRequest(`response-execute:${by}`, 10, 10 * 60_000)) { res.setHeader("Retry-After", "600"); return res.status(429).json({ error: "Too many execution requests. Wait a few minutes and try again." }); }
  try {
    const proposalId = (req.body as { proposalId?: unknown } | undefined)?.proposalId;
    if (typeof proposalId !== "string" || !proposalId) return res.status(400).json({ error: "proposalId is required." });
    const { execution, replay } = await executeProposal(proposalId, req.headers["idempotency-key"], ctx.actor, undefined, undefined, {
      onPhase: async (phase: Phase, e) => {
        await writeAuditEvent({ action: "response_execution", actor: ctx.actor, phase, executionId: e.id, proposalId: e.proposalId, actionType: e.actionType, target: e.target, adapter: e.adapter, status: e.status });
      }
    });
    return res.status(execution.status === "failed" ? 502 : 200).json({ execution, idempotentReplay: replay });
  } catch (error) { return respFail(res, error, "response execute"); }
}
