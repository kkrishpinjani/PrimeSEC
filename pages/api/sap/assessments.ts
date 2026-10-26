import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { readAssessments, retrieve, DEMO_INPUT, SAP_LIMITATIONS, LIMITS } from "../../../lib/sap";
import { logError } from "../../../lib/log";

/**
 * GET /api/sap/assessments            -> recent assessments (summaries)
 * GET /api/sap/assessments?id=...     -> one assessment in full
 * GET /api/sap/assessments?q=...      -> search the bundled SAP notes
 * GET /api/sap/assessments?demo=1     -> the synthetic demo input and the limits
 * Any PrimeSEC role.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "view");
  if (!ctx) return;
  try {
    if (req.query.demo) return res.status(200).json({ demo: DEMO_INPUT, limits: LIMITS, limitations: SAP_LIMITATIONS, canAssess: ctx.isAdmin || ctx.roles.includes("SOC_Analyst") });
    if (typeof req.query.q === "string") {
      const q = req.query.q.trim();
      if (!q) return res.status(400).json({ error: "q must not be empty." });
      return res.status(200).json({ query: q.slice(0, 500), results: await retrieve(q, Number(req.query.top_k) || 5) });
    }
    const all = await readAssessments();
    if (typeof req.query.id === "string") {
      const one = all.find((a) => a.id === req.query.id);
      return one ? res.status(200).json(one) : res.status(404).json({ error: "Assessment not found." });
    }
    return res.status(200).json({
      items: all.slice(0, 50).map((a) => ({ id: a.id, createdAt: a.createdAt, createdBy: a.createdBy, assetId: a.assetId, summary: a.summary, findingCount: a.findings.length, findingIds: a.findings.map((f) => f.id) })),
      canAssess: ctx.isAdmin || ctx.roles.includes("SOC_Analyst")
    });
  } catch (error) {
    logError("sap read", error);
    return res.status(500).json({ error: "The SAP assessment store is unavailable." });
  }
}
