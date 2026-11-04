import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { ingestAssets, inventorySummary, InventoryError, listAssets, validateBatch } from "../../../lib/inventory";
import { writeAuditEvent } from "../../../lib/audit";
import { allowRequest } from "../../../lib/rateLimit";
import { logError } from "../../../lib/log";

/**
 * GET: the canonical asset inventory (any PrimeSEC role), risk-ranked, with a summary.
 * POST: ingest normalised asset observations (SOC_Analyst or SOC_Admin). Records data only: it never scans or changes a host.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    const ctx = await agentGuard(req, res, "view");
    if (!ctx) return;
    try {
      const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);
      const list = await listAssets({ q: one(req.query.q), riskLevel: one(req.query.riskLevel), environment: one(req.query.environment), limit: Number(one(req.query.limit)) || undefined, offset: Number(one(req.query.offset)) || undefined });
      return res.status(200).json({ ...list, summary: await inventorySummary() });
    } catch (error) {
      logError("inventory list", error);
      return res.status(500).json({ error: "The inventory is unavailable." });
    }
  }
  if (req.method !== "POST") { res.setHeader("Allow", "GET, POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "analyst");
  if (!ctx) return;
  if (!allowRequest(`inventory-ingest:${ctx.actor.email || ctx.actor.name || "unknown"}`, 30, 10 * 60_000)) {
    res.setHeader("Retry-After", "600");
    return res.status(429).json({ error: "Too many imports. Wait a few minutes and try again." });
  }
  try {
    const inputs = validateBatch((req.body as { items?: unknown } | undefined)?.items);
    const result = await ingestAssets(inputs);
    let auditRecorded = true;
    try {
      await writeAuditEvent({ action: "inventory_ingested", actor: ctx.actor, origin: "manual", sources: [...new Set(inputs.map((i) => i.source))], accepted: result.accepted, created: result.created, updated: result.updated });
    } catch (error) {
      auditRecorded = false;
      logError("inventory: ingest saved but the audit write failed", error);
    }
    return res.status(202).json({ accepted: result.accepted, created: result.created, updated: result.updated, items: result.assets, auditRecorded });
  } catch (error) {
    if (error instanceof InventoryError) return res.status(400).json({ error: error.message });
    logError("inventory ingest", error);
    return res.status(500).json({ error: "The import could not be completed." });
  }
}
