import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { assess, SapError, validateInput } from "../../../lib/sap";
import { writeAuditEvent } from "../../../lib/audit";
import { allowRequest } from "../../../lib/rateLimit";
import { logError } from "../../../lib/log";

/**
 * Offline assessment of SAP configuration text the analyst pastes. Nothing is contacted, scanned or executed.
 * SOC_Analyst or SOC_Admin; origin-checked; rate-limited; audited (the pasted configuration itself is NOT written to the audit log).
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "analyst");
  if (!ctx) return;
  if (!allowRequest(`sap-assess:${ctx.actor.email || ctx.actor.name || "unknown"}`, 20, 10 * 60_000)) {
    res.setHeader("Retry-After", "600");
    return res.status(429).json({ error: "Too many assessments. Wait a few minutes and try again." });
  }
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const input = validateInput(body);
    const item = await assess(input, { explain: body.includeExplanation === true, createdBy: ctx.actor.email || ctx.actor.name || "unknown" });
    let auditRecorded = true;
    try {
      await writeAuditEvent({ action: "sap_assessment_created", actor: ctx.actor, assessmentId: item.id, assetId: item.assetId, findingCount: item.findings.length, findingIds: item.findings.map((f) => f.id), explained: item.llmExplanation !== null });
    } catch (error) {
      auditRecorded = false;
      logError("sap: assessment saved but the audit write failed", error);
    }
    return res.status(200).json({ ...item, auditRecorded });
  } catch (error) {
    if (error instanceof SapError) return res.status(error.code === "INVALID" ? 400 : 503).json({ error: error.message });
    logError("sap assess", error);
    return res.status(500).json({ error: "The assessment could not be completed." });
  }
}
