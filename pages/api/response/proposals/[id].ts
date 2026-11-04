import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../../lib/agentApi";
import { cancelProposal, readResponse, reviewProposal, ResponseError } from "../../../../lib/response";
import { respFail } from "../../../../lib/responseApi";
import { writeAuditEvent } from "../../../../lib/audit";
import { logError } from "../../../../lib/log";

/**
 * POST { decision: "approve" | "reject", note }: review a proposal. SOC_Admin only, and (dual control) never the proposer.
 * DELETE: the proposer withdraws it.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const id = String(req.query.id);
  if (req.method === "POST") {
    const ctx = await agentGuard(req, res, "admin");
    if (!ctx) return;
    try {
      const body = (req.body ?? {}) as { decision?: unknown; note?: unknown };
      const proposal = await reviewProposal(id, body.decision, body.note, ctx.actor);
      let auditRecorded = true;
      try { await writeAuditEvent({ action: "response_reviewed", actor: ctx.actor, proposalId: proposal.id, decision: body.decision as "approve" | "reject", actionType: proposal.actionType, target: proposal.target, proposedBy: proposal.proposedBy }); }
      catch (error) { auditRecorded = false; logError("response: review saved but the audit write failed", error); }
      return res.status(200).json({ proposal, auditRecorded });
    } catch (error) { return respFail(res, error, "response review"); }
  }
  if (req.method === "DELETE") {
    const ctx = await agentGuard(req, res, "analyst");
    if (!ctx) return;
    try {
      const proposal = await cancelProposal(id, ctx.actor);
      try { await writeAuditEvent({ action: "response_proposal_cancelled", actor: ctx.actor, proposalId: proposal.id }); } catch (error) { logError("response: cancel audit failed", error); }
      return res.status(200).json({ proposal });
    } catch (error) { return respFail(res, error, "response cancel"); }
  }
  if (req.method === "GET") {
    const ctx = await agentGuard(req, res, "view");
    if (!ctx) return;
    try {
      const p = (await readResponse()).proposals.find((x) => x.id === id);
      if (!p) throw new ResponseError("Proposal not found.", "NOT_FOUND");
      return res.status(200).json({ proposal: p });
    } catch (error) { return respFail(res, error, "response get"); }
  }
  res.setHeader("Allow", "GET, POST, DELETE");
  return res.status(405).json({ error: "Method not allowed" });
}
