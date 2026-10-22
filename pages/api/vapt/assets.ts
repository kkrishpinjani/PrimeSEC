import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed } from "../../../lib/auth";
import { AssetError, updateAsset, type AssetPatch } from "../../../lib/assets";
import { readFindings } from "../../../lib/findings";
import { writeAuditEvent } from "../../../lib/audit";
import { logError } from "../../../lib/log";

/**
 * Sets a host's criticality and exposure (inputs to the risk score). SOC_Analyst or SOC_Admin; origin-checked; audited
 * with the old and new values, because lowering a host's criticality lowers the priority of every finding on it.
 * Only hosts that actually have findings can be classified.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  if (req.method !== "PATCH") return res.status(405).json({ error: "Method not allowed" });
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r))) return res.status(403).json({ error: "SOC_Analyst or SOC_Admin role required." });
  if (!originIsAllowed(req)) return res.status(403).json({ error: "Cross-origin request rejected." });

  const body = (req.body ?? {}) as Record<string, unknown>;
  const host = typeof body.host === "string" ? body.host.trim() : "";
  if (!host || host.length > 255) return res.status(400).json({ error: "A host is required." });

  const patch: AssetPatch = {};
  for (const key of ["criticality", "exposure", "expectedUpdatedAt"] as const) if (key in body) patch[key] = body[key];
  const actor = { name: session.user?.name ?? null, email: session.user?.email ?? null, roles };

  try {
    const known = (await readFindings()).some((f) => f.host.trim().toLowerCase() === host.toLowerCase());
    if (!known) return res.status(404).json({ error: "No findings are recorded for that host. Sync Greenbone findings first." });
    const { asset, before } = await updateAsset(host, patch, actor);
    let auditRecorded = true;
    try {
      const changes = (["criticality", "exposure"] as const)
        .filter((k) => (before?.[k] ?? "Unknown") !== asset[k])
        .map((k) => ({ field: k, from: before?.[k] ?? "Unknown", to: asset[k] }));
      await writeAuditEvent({ action: "vapt_asset_updated", actor, host: asset.host, changes });
    } catch (error) {
      auditRecorded = false;
      logError("asset update applied but the audit write failed", error);
    }
    return res.status(200).json({ asset, auditRecorded });
  } catch (error) {
    if (error instanceof AssetError) return res.status(error.code === "CONFLICT" ? 409 : 400).json({ error: error.message });
    logError("asset update", error);
    return res.status(500).json({ error: "The asset store is unavailable." });
  }
}
