import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard, fail } from "../../../../lib/agentApi";
import { consumePermit } from "../../../../lib/agentgate";
import { writeAuditEvent } from "../../../../lib/audit";
import { allowRequest } from "../../../../lib/rateLimit";
import { logError } from "../../../../lib/log";

/**
 * Called by the adapter immediately before it acts. The permit is spent only if the action details sent here match the
 * ones it was issued for. This records an authorization; it does not execute anything.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "analyst");
  if (!ctx) return;
  if (!allowRequest(`agent-consume:${ctx.actor.email || ctx.actor.name || "unknown"}`, 120, 60_000)) {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({ error: "Too many attempts. Wait a minute and try again." });
  }
  const b = (req.body ?? {}) as Record<string, unknown>;
  const agentId = typeof b.agentId === "string" ? b.agentId.trim().slice(0, 120) : "";
  const tool = typeof b.tool === "string" ? b.tool.trim().slice(0, 160) : "";
  try {
    const out = await consumePermit(b.permit, { agentId, tool, dataClass: typeof b.dataClass === "string" ? b.dataClass : "unknown", target: typeof b.target === "string" ? b.target : "", external: b.external === true, sensitive: b.sensitive === true });
    try {
      if (out.ok) await writeAuditEvent({ action: "agent_permit_consumed", actor: ctx.actor, grantId: out.grantId, agentId, tool, via: out.via });
      else await writeAuditEvent({ action: "agent_permit_rejected", actor: ctx.actor, reason: out.reason, agentId, tool });
    } catch (error) {
      // The permit is already spent, so a failed audit means "no": the adapter must not act without a recorded consumption.
      logError("agents gateway: consume audit write failed", error);
      return res.status(503).json({ error: "The authorization could not be recorded. Do not act; request a new permit." });
    }
    if (!out.ok) return res.status(out.status).json({ error: out.error, reason: out.reason });
    return res.status(200).json({ ok: true, grantId: out.grantId, consumedAt: out.consumedAt, message: "Permit accepted. You may perform exactly this action once. PrimeSEC has not executed anything." });
  } catch (error) {
    return fail(res, error, "agents consume");
  }
}
