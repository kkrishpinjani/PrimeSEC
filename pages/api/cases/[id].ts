import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { addEvidence, assignCase, buildPlan, CASE_ACTIONS, CaseError, getCase, markPlanned, noteEvent, transitionCase } from "../../../lib/cases";
import { createProposal, readResponse } from "../../../lib/response";
import { caseFail } from "../../../lib/caseApi";
import { writeAuditEvent } from "../../../lib/audit";
import { logError } from "../../../lib/log";

/**
 * GET: one case with its evidence, timeline and any response proposals made from it (any PrimeSEC role).
 * POST { action }, SOC_Analyst or SOC_Admin:
 *   assign { owner }                 transition { status, note }       evidence { type, title, content }
 *   plan                             a rule-based investigation plan (moves a new case to triaged)
 *   propose { actionType, target, rationale }   hands a response proposal to the governed-response review. Nothing executes here.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const id = String(req.query.id);
  if (req.method === "GET") {
    const ctx = await agentGuard(req, res, "view");
    if (!ctx) return;
    try {
      const c = await getCase(id);
      const proposals = (await readResponse()).proposals.filter((p) => p.links.caseId === id);
      return res.status(200).json({ case: c, proposals });
    } catch (error) { return caseFail(res, error, "case get"); }
  }
  if (req.method !== "POST") { res.setHeader("Allow", "GET, POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "analyst");
  if (!ctx) return;
  const body = (req.body ?? {}) as Record<string, unknown>;
  const audit = async (caseKey: string, event: string, details: Record<string, unknown>) => {
    try { await writeAuditEvent({ action: "case_event", actor: ctx.actor, caseId: id, caseKey, event, details }); }
    catch (error) { logError("cases: change saved but the audit write failed", error); }
  };
  try {
    switch (body.action) {
      case "assign": {
        const c = await assignCase(id, body.owner, ctx.actor);
        await audit(c.caseKey, "case_assigned", { owner: c.owner });
        return res.status(200).json({ case: c });
      }
      case "transition": {
        const c = await transitionCase(id, body.status, body.note, ctx.actor);
        await audit(c.caseKey, "status_changed", { status: c.status });
        return res.status(200).json({ case: c });
      }
      case "evidence": {
        const c = await addEvidence(id, body as { type?: unknown; source?: unknown; title?: unknown; content?: unknown }, ctx.actor);
        await audit(c.caseKey, "evidence_added", { title: c.evidence[c.evidence.length - 1].title });
        return res.status(201).json({ case: c });
      }
      case "plan": {
        const plan = buildPlan(await getCase(id));
        const c = await markPlanned(id, plan.steps.length, ctx.actor);
        await audit(c.caseKey, "investigation_plan_generated", { steps: plan.steps.length });
        return res.status(200).json({ plan, case: c });
      }
      case "propose": {
        const c0 = await getCase(id);
        if (c0.status === "closed") throw new CaseError("A closed case cannot take a response proposal.", "CONFLICT");
        if (typeof body.actionType !== "string" || !(CASE_ACTIONS as readonly string[]).includes(body.actionType)) throw new CaseError(`actionType must be one of ${CASE_ACTIONS.join(", ")}.`, "INVALID");
        const proposal = await createProposal({ actionType: body.actionType, target: body.target, rationale: body.rationale, links: { caseId: id, alertId: c0.sourceAlertIds[0] } }, ctx.actor);
        const c = await noteEvent(id, "response_proposal_created", ctx.actor, { proposalId: proposal.id, actionType: proposal.actionType, target: proposal.target });
        try { await writeAuditEvent({ action: "response_proposed", actor: ctx.actor, proposalId: proposal.id, actionType: proposal.actionType, target: proposal.target, links: proposal.links as Record<string, string> }); } catch (error) { logError("cases: proposal audit failed", error); }
        await audit(c.caseKey, "response_proposal_created", { proposalId: proposal.id });
        return res.status(201).json({ proposal, case: c, execution: "Not executed: another administrator must review it in Governed response." });
      }
      default:
        return res.status(400).json({ error: "action must be one of assign, transition, evidence, plan, propose." });
    }
  } catch (error) { return caseFail(res, error, "case action"); }
}
