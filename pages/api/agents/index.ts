import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard, fail } from "../../../lib/agentApi";
import { ENVIRONMENTS, FRAMEWORKS, readState, registerAgent, setAgentStatus } from "../../../lib/agentsec";
import { writeAuditEvent } from "../../../lib/audit";
import { logError } from "../../../lib/log";

/** GET: the registry (any role). POST: register an agent (SOC_Admin). PATCH: suspend or reactivate one (SOC_Admin). */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST" && req.method !== "PATCH") { res.setHeader("Allow", "GET, POST, PATCH"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, req.method === "GET" ? "view" : "admin");
  if (!ctx) return;
  const body = (req.body ?? {}) as Record<string, unknown>;
  try {
    if (req.method === "GET") {
      const state = await readState();
      return res.status(200).json({ agents: state.agents, frameworks: FRAMEWORKS, environments: ENVIRONMENTS, canEdit: ctx.isAdmin, inventory: "manual registry (seeded examples are marked); no live discovery" });
    }
    let auditRecorded = true;
    if (req.method === "POST") {
      const agent = await registerAgent(body, ctx.actor.email || ctx.actor.name || "unknown");
      try { await writeAuditEvent({ action: "agent_registered", actor: ctx.actor, agent: { id: agent.id, name: agent.name, framework: agent.framework, environment: agent.environment, toolCount: agent.tools.length } }); }
      catch (error) { auditRecorded = false; logError("agents: registered but the audit write failed", error); }
      return res.status(201).json({ agent, auditRecorded });
    }
    const { agent, before } = await setAgentStatus(String(body.id ?? ""), body.status);
    if (before !== agent.status) {
      try { await writeAuditEvent({ action: "agent_status_changed", actor: ctx.actor, agent: { id: agent.id, name: agent.name }, from: before, to: agent.status }); }
      catch (error) { auditRecorded = false; logError("agents: status changed but the audit write failed", error); }
    }
    return res.status(200).json({ agent, auditRecorded });
  } catch (error) {
    return fail(res, error, "agents");
  }
}
