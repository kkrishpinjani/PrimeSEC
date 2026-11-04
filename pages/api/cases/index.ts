import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { createCase, listCases, openCaseFromAlert, type CaseInput } from "../../../lib/cases";
import { investigateAlert } from "../../../lib/investigate";
import { caseFail } from "../../../lib/caseApi";
import { writeAuditEvent } from "../../../lib/audit";
import { allowRequest } from "../../../lib/rateLimit";
import { logError } from "../../../lib/log";

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

/**
 * GET: the case list with open counts (any PrimeSEC role).
 * POST { alertId } opens (or refreshes) a case from a Wazuh alert: the alert is re-read from Wazuh, never taken from the browser.
 * POST { title, description, severity, ... } opens a manual case. SOC_Analyst or SOC_Admin. Records work; changes no system.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    const ctx = await agentGuard(req, res, "view");
    if (!ctx) return;
    try {
      return res.status(200).json(await listCases({ status: one(req.query.status), owner: one(req.query.owner), severity: one(req.query.severity), search: one(req.query.q), limit: Number(one(req.query.limit)) || undefined, offset: Number(one(req.query.offset)) || undefined }));
    } catch (error) { return caseFail(res, error, "cases list"); }
  }
  if (req.method !== "POST") { res.setHeader("Allow", "GET, POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "analyst");
  if (!ctx) return;
  const by = ctx.actor.email || ctx.actor.name || "unknown";
  if (!allowRequest(`case-create:${by}`, 20, 10 * 60_000)) { res.setHeader("Retry-After", "600"); return res.status(429).json({ error: "Too many cases opened. Wait a few minutes and try again." }); }
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    let c, created = true;
    if (body.alertId !== undefined) {
      const inv = await investigateAlert(body.alertId);
      const r = await openCaseFromAlert({
        alert: inv.alert, searched: inv.searched, openCtiConnected: inv.openCti.connected && inv.openCti.configured,
        matches: inv.correlation.matches.map((m) => ({ indicatorName: m.indicatorName, matchedValue: m.matchedValue, observableType: m.observableType, score: m.score })),
        vulnerabilities: inv.vulnerabilities.map((v) => ({ cve: v.cve, known: v.known, cvss: v.cvss, knownExploited: v.knownExploited })), techniques: inv.techniques
      }, ctx.actor);
      c = r.case; created = r.created;
    } else {
      c = await createCase(body as CaseInput, ctx.actor);
    }
    try { await writeAuditEvent({ action: "case_event", actor: ctx.actor, caseId: c.id, caseKey: c.caseKey, event: created ? "case_created" : "correlation_refreshed", details: { severity: c.severity, priorityScore: c.priorityScore, sourceAlertIds: c.sourceAlertIds } }); }
    catch (error) { logError("cases: case saved but the audit write failed", error); }
    return res.status(created ? 201 : 200).json({ case: c, created });
  } catch (error) { return caseFail(res, error, "cases create"); }
}
