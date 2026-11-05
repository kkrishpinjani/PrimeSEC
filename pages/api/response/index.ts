import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { listExecutions, listProposals, responseStatus } from "../../../lib/response";
import { ensureAdapters } from "../../../lib/responseAdapters";
import { logError } from "../../../lib/log";

/** Governed-response overview: whether execution is on, the allow-list, registered adapters, proposals and executions. Any PrimeSEC role. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  ensureAdapters();
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "view");
  if (!ctx) return;
  try {
    return res.status(200).json({ status: responseStatus(), proposals: await listProposals(100), executions: await listExecutions(100) });
  } catch (error) {
    logError("response overview", error);
    return res.status(500).json({ error: "The response store is unavailable." });
  }
}
