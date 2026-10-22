import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, PRIMESEC_ROLES } from "../../../lib/auth";
import { readFindings, EXPLOIT_EVIDENCE } from "../../../lib/findings";
import { assetMap, readAssets, CRITICALITIES, EXPOSURES } from "../../../lib/assets";
import { METHODOLOGY, rankFindings } from "../../../lib/risk";
import { logError } from "../../../lib/log";

/** Risk-ranked remediation queue (any PrimeSEC role). Resolved and Closed findings are left out unless ?all=1. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => PRIMESEC_ROLES.includes(r))) return res.status(403).json({ error: "A PrimeSEC role is required." });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  try {
    const [findings, assets, assetRecords] = await Promise.all([readFindings(), assetMap(), readAssets()]);
    const ranked = rankFindings(findings, assets, { includeClosed: req.query.all === "1" });
    const bands: Record<string, number> = {};
    for (const f of ranked) bands[f.risk.band] = (bands[f.risk.band] ?? 0) + 1;
    // Hosts that have findings, with their (possibly unset) context, so the UI can show every host that needs it.
    const hosts = [...new Set(findings.map((f) => f.host))].sort().map((host) => {
      const a = assets.get(host.trim().toLowerCase());
      return { host, criticality: a?.criticality ?? "Unknown", exposure: a?.exposure ?? "Unknown", updatedAt: a?.updatedAt ?? null, updatedBy: a?.updatedBy ?? null, findings: findings.filter((f) => f.host === host).length };
    });
    return res.status(200).json({
      findings: ranked,
      summary: { total: ranked.length, byBand: bands, unclassifiedHosts: hosts.filter((h) => h.criticality === "Unknown" || h.exposure === "Unknown").length },
      hosts,
      methodology: METHODOLOGY,
      options: { criticalities: CRITICALITIES, exposures: EXPOSURES, exploitEvidence: EXPLOIT_EVIDENCE },
      canEdit: roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r)),
      knownAssets: assetRecords.length
    });
  } catch (error) {
    logError("risk queue", error);
    return res.status(500).json({ error: "The risk queue is unavailable." });
  }
}
