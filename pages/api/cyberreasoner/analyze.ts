import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed } from "../../../lib/auth";
import { getFinding } from "../../../lib/findings";
import { assetMap, hostKey } from "../../../lib/assets";
import { analyzeFinding, ReasonerError } from "../../../lib/cyberreasoner";
import { writeAuditEvent } from "../../../lib/audit";
import { allowRequest } from "../../../lib/rateLimit";
import { logError } from "../../../lib/log";

const FINDING_ID = /^vuln_[0-9a-f]{16}$/;
const STATUS = { MODEL_UNAVAILABLE: 502, BAD_OUTPUT: 502, NOT_CONFIGURED: 503, TIMEOUT: 504, BUSY: 429 } as const;

/**
 * Advisory analysis of ONE imported finding by a local model. The only input is a finding id: no target, URL or command
 * is accepted. SOC_Analyst or SOC_Admin; origin-checked; rate-limited; one model run at a time; audited.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r))) return res.status(403).json({ error: "SOC_Analyst or SOC_Admin role required." });
  if (!originIsAllowed(req)) return res.status(403).json({ error: "Cross-origin request rejected." });

  const findingId = String((req.body ?? {}).findingId ?? "");
  if (!FINDING_ID.test(findingId)) return res.status(400).json({ error: "A valid finding id is required." });
  const actor = { name: session.user?.name ?? null, email: session.user?.email ?? null, roles };
  if (!allowRequest(`cyberreasoner:${actor.email || actor.name || "unknown"}`, 10, 10 * 60_000)) {
    res.setHeader("Retry-After", "600");
    return res.status(429).json({ error: "Too many analyses. Wait a few minutes and try again." });
  }

  try {
    const finding = await getFinding(findingId);
    if (!finding) return res.status(404).json({ error: "Finding not found. Sync Greenbone findings first." });
    const asset = (await assetMap()).get(hostKey(finding.host)) ?? null;
    const analysis = await analyzeFinding(finding, asset);
    let auditRecorded = true;
    try {
      await writeAuditEvent({ action: "cyberreasoner_analysis", actor, finding: { id: finding.id, host: finding.host, port: finding.port, name: finding.name }, model: analysis.model, removedItems: analysis.removedItems });
    } catch (error) {
      auditRecorded = false;
      logError("cyberreasoner: analysis returned but the audit write failed", error);
    }
    return res.status(200).json({ analysis, auditRecorded });
  } catch (error) {
    if (error instanceof ReasonerError) {
      if (error.code !== "BUSY") logError("cyberreasoner analysis", error);
      return res.status(STATUS[error.code]).json({ error: error.message, ...(error.code === "MODEL_UNAVAILABLE" || error.code === "TIMEOUT" ? { hint: "Start Ollama, pull the configured model, and check OLLAMA_BASE_URL." } : {}) });
    }
    logError("cyberreasoner analysis", error);
    return res.status(500).json({ error: "Analysis failed." });
  }
}
