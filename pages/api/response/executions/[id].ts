import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../../lib/agentApi";
import { rollbackExecution, verifyExecution, type Execution, type Phase } from "../../../../lib/response";
import { respFail } from "../../../../lib/responseApi";
import { writeAuditEvent } from "../../../../lib/audit";

/** POST { action: "verify" | "rollback" } on an execution. SOC_Admin only; audited. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "admin");
  if (!ctx) return;
  try {
    const action = (req.body as { action?: unknown } | undefined)?.action;
    if (action !== "verify" && action !== "rollback") return res.status(400).json({ error: 'action must be "verify" or "rollback".' });
    const hooks = {
      onPhase: async (phase: Phase, e: Execution) => {
        await writeAuditEvent({ action: "response_execution", actor: ctx.actor, phase, executionId: e.id, proposalId: e.proposalId, actionType: e.actionType, target: e.target, adapter: e.adapter, status: e.status });
      }
    };
    const execution = action === "verify" ? await verifyExecution(String(req.query.id), undefined, hooks) : await rollbackExecution(String(req.query.id), undefined, hooks);
    return res.status(200).json({ execution });
  } catch (error) { return respFail(res, error, "response verify/rollback"); }
}
