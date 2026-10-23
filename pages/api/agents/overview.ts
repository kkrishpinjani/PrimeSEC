import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard, fail } from "../../../lib/agentApi";
import { readState } from "../../../lib/agentsec";
import { readAuditEvents, type AuditAction, type AuditEvent } from "../../../lib/audit";

const AGENT_ACTIONS: AuditAction[] = ["agent_registered", "agent_status_changed", "agent_policy_changed", "agent_policy_evaluated", "agent_scenarios_run"];
type Evaluated = Extract<AuditEvent, { action: "agent_policy_evaluated" }>;

/** Summary numbers, findings and recent events for the Agent Security page (any role). */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "view");
  if (!ctx) return;
  try {
    const [state, events] = await Promise.all([readState(), readAuditEvents(100, AGENT_ACTIONS)]);
    const evaluations = events.filter((e): e is Evaluated => e.action === "agent_policy_evaluated");
    const open = state.findings.filter((f) => f.status === "open" || f.status === "pending_approval");
    return res.status(200).json({
      metrics: {
        agents: state.agents.length,
        suspended: state.agents.filter((a) => a.status === "suspended").length,
        highPrivilege: state.agents.filter((a) => a.privileges === "high" || a.criticality === "critical").length,
        enabledPolicies: state.policies.filter((p) => p.enabled).length,
        openFindings: open.length,
        pendingApprovals: open.filter((f) => f.status === "pending_approval").length,
        recentEvaluations: evaluations.length,
        recentDenied: evaluations.filter((e) => e.decision === "DENY").length
      },
      policyRevision: state.policyRevision,
      findings: state.findings.slice(0, 20),
      events: events.slice(0, 25),
      canEdit: ctx.isAdmin,
      canEvaluate: ctx.isAdmin || ctx.roles.includes("SOC_Analyst"),
      liveDiscovery: false
    });
  } catch (error) {
    return fail(res, error, "agent overview");
  }
}
