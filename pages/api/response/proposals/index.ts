import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../../lib/agentApi";
import { createProposal, type ProposalInput } from "../../../../lib/response";
import { respFail } from "../../../../lib/responseApi";
import { writeAuditEvent } from "../../../../lib/audit";
import { allowRequest } from "../../../../lib/rateLimit";
import { logError } from "../../../../lib/log";

/** POST: propose a response action (SOC_Analyst or SOC_Admin). A proposal is a request for review; creating one acts on nothing. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "analyst");
  if (!ctx) return;
  const by = ctx.actor.email || ctx.actor.name || "unknown";
  if (!allowRequest(`response-propose:${by}`, 20, 10 * 60_000)) { res.setHeader("Retry-After", "600"); return res.status(429).json({ error: "Too many proposals. Wait a few minutes and try again." }); }
  try {
    const proposal = await createProposal((req.body ?? {}) as ProposalInput, ctx.actor);
    let auditRecorded = true;
    try { await writeAuditEvent({ action: "response_proposed", actor: ctx.actor, proposalId: proposal.id, actionType: proposal.actionType, target: proposal.target, links: proposal.links as Record<string, string> }); }
    catch (error) { auditRecorded = false; logError("response: proposal saved but the audit write failed", error); }
    return res.status(201).json({ proposal, auditRecorded });
  } catch (error) { return respFail(res, error, "response propose"); }
}
