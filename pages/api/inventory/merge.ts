import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { dismissPair, InventoryError, mergeAssets, mergeCandidates, readInventory } from "../../../lib/inventory";
import { writeAuditEvent } from "../../../lib/audit";
import { allowRequest } from "../../../lib/rateLimit";
import { logError } from "../../../lib/log";

const STATUS = { INVALID: 400, NOT_FOUND: 404, CONFLICT: 409 } as const;

/**
 * GET: suggested duplicate pairs (any PrimeSEC role). A suggestion is only a lead.
 * POST { action: "merge", survivorId, absorbedId, note }  or  { action: "dismiss", survivorId, absorbedId, note }
 * SOC_Analyst or SOC_Admin; a written reason is required and recorded. Merging changes PrimeSEC's inventory only; it touches no host.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    const ctx = await agentGuard(req, res, "view");
    if (!ctx) return;
    try { return res.status(200).json({ candidates: await mergeCandidates() }); }
    catch (error) { logError("inventory merge candidates", error); return res.status(500).json({ error: "The inventory is unavailable." }); }
  }
  if (req.method !== "POST") { res.setHeader("Allow", "GET, POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "analyst");
  if (!ctx) return;
  const by = ctx.actor.email || ctx.actor.name || "unknown";
  if (!allowRequest(`inventory-merge:${by}`, 30, 10 * 60_000)) { res.setHeader("Retry-After", "600"); return res.status(429).json({ error: "Too many merge decisions. Wait a few minutes and try again." }); }
  try {
    const { action, survivorId, absorbedId, note } = (req.body ?? {}) as Record<string, unknown>;
    if (action !== "merge" && action !== "dismiss") return res.status(400).json({ error: 'action must be "merge" or "dismiss".' });
    const inv = await readInventory();
    const name = (id: unknown) => inv.assets.find((a) => a.id === id)?.name ?? String(id).slice(0, 40);
    const names = { survivor: { id: String(survivorId), name: name(survivorId) }, absorbed: { id: String(absorbedId), name: name(absorbedId) } };
    let asset = null;
    if (action === "merge") asset = await mergeAssets(survivorId, absorbedId, note, by);
    else {
      if (typeof note !== "string" || note.trim().length < 10) throw new InventoryError("Say why they are different machines (at least 10 characters).", "INVALID");
      await dismissPair(survivorId, absorbedId);
    }
    let auditRecorded = true;
    try { await writeAuditEvent({ action: "inventory_merge", actor: ctx.actor, decision: action === "merge" ? "merged" : "dismissed", ...names, note: String(note).trim() }); }
    catch (error) { auditRecorded = false; logError("inventory: merge saved but the audit write failed", error); }
    return res.status(200).json({ asset, auditRecorded });
  } catch (error) {
    if (error instanceof InventoryError) return res.status(STATUS[error.code]).json({ error: error.message });
    logError("inventory merge", error);
    return res.status(500).json({ error: "The merge could not be completed." });
  }
}
