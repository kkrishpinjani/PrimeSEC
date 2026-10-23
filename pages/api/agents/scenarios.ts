import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard, fail } from "../../../lib/agentApi";
import { readState, runScenarios, SCENARIOS } from "../../../lib/agentsec";
import { writeAuditEvent } from "../../../lib/audit";
import { allowRequest } from "../../../lib/rateLimit";
import { logError } from "../../../lib/log";

const NOTE = "Deterministic checks of the policy rules against the current configuration. They are not an adversarial red-team or an alignment test, and they do not prove any agent runtime enforces the decisions.";

/** GET: the scenario list (any role). POST: run them against the live policy set, record nothing but one audit line (SOC_Analyst or SOC_Admin). */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST") { res.setHeader("Allow", "GET, POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, req.method === "GET" ? "view" : "analyst");
  if (!ctx) return;
  try {
    if (req.method === "GET") return res.status(200).json({ scenarios: SCENARIOS.map(({ id, name, description, expected }) => ({ id, name, description, expected })), note: NOTE, canRun: ctx.isAdmin || ctx.roles.includes("SOC_Analyst") });
    if (!allowRequest(`agent-scenarios:${ctx.actor.email || ctx.actor.name || "unknown"}`, 20, 60_000)) {
      res.setHeader("Retry-After", "60");
      return res.status(429).json({ error: "Too many test runs. Wait a minute and try again." });
    }
    const state = await readState();
    const run = runScenarios(state);
    let auditRecorded = true;
    try { await writeAuditEvent({ action: "agent_scenarios_run", actor: ctx.actor, passed: run.passed, total: run.total, policyRevision: state.policyRevision }); }
    catch (error) { auditRecorded = false; logError("agents: scenarios ran but the audit write failed", error); }
    return res.status(200).json({ ranAt: new Date().toISOString(), policyRevision: state.policyRevision, ...run, note: NOTE, auditRecorded });
  } catch (error) {
    return fail(res, error, "agent scenarios");
  }
}
