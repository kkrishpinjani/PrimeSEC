import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../lib/agentApi";
import { insights, TOPICS } from "../../lib/insights";

/** GET /api/insights?topic=alerts|vulns|findings|cases|... Chart data for the Insights panels. Any PrimeSEC role; read-only. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "view");
  if (!ctx) return;
  const topic = Array.isArray(req.query.topic) ? req.query.topic[0] : req.query.topic;
  if (!topic || !(TOPICS as readonly string[]).includes(topic)) return res.status(400).json({ error: `topic must be one of ${TOPICS.join(", ")}.` });
  return res.status(200).json(await insights(topic));
}
