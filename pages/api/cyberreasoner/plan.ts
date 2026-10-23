import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed } from "../../../lib/auth";
import { getFinding } from "../../../lib/findings";
import { createDefensivePlan } from "../../../lib/cyberreasoner";
import { writeAuditEvent } from "../../../lib/audit";
import { logError } from "../../../lib/log";

const FINDING_ID = /^vuln_[0-9a-f]{16}$/;

/** A fixed, declarative workflow proposal for one imported finding. Nothing is executed, stored or sent anywhere. */
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
  try {
    const finding = await getFinding(findingId);
    if (!finding) return res.status(404).json({ error: "Finding not found. Sync Greenbone findings first." });
    const plan = createDefensivePlan(finding, actor);
    let auditRecorded = true;
    try {
      await writeAuditEvent({ action: "cyberreasoner_plan_created", actor, finding: { id: finding.id, host: finding.host, port: finding.port, name: finding.name }, planId: plan.planId, taskTypes: plan.tasks.map((t) => t.type) });
    } catch (error) {
      auditRecorded = false;
      logError("cyberreasoner: plan created but the audit write failed", error);
    }
    return res.status(200).json({ plan, auditRecorded, note: "A proposal only. It is not stored, sent to JEV or executed." });
  } catch (error) {
    logError("cyberreasoner plan", error);
    return res.status(500).json({ error: "Could not create the plan." });
  }
}
