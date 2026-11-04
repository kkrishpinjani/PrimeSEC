import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { assetDetail, InventoryError } from "../../../lib/inventory";
import { logError } from "../../../lib/log";

/** One asset with its vulnerabilities and the recent source observations behind it. Any PrimeSEC role. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "view");
  if (!ctx) return;
  try {
    return res.status(200).json(await assetDetail(String(req.query.id)));
  } catch (error) {
    if (error instanceof InventoryError) return res.status(error.code === "NOT_FOUND" ? 404 : 400).json({ error: error.message });
    logError("inventory detail", error);
    return res.status(500).json({ error: "The inventory is unavailable." });
  }
}
