import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard, fail } from "../../../lib/agentApi";
import { createPolicy, POLICY_ACTIONS, POLICY_CONDITIONS, readState, SEVERITIES, setPolicyEnabled } from "../../../lib/agentsec";
import { writeAuditEvent } from "../../../lib/audit";
import { logError } from "../../../lib/log";

/** GET: policies (any role). POST: add a restrictive policy (SOC_Admin). PATCH: enable or disable one (SOC_Admin); baseline policies cannot be disabled. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST" && req.method !== "PATCH") { res.setHeader("Allow", "GET, POST, PATCH"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, req.method === "GET" ? "view" : "admin");
  if (!ctx) return;
  const body = (req.body ?? {}) as Record<string, unknown>;
  try {
    if (req.method === "GET") {
      const state = await readState();
      return res.status(200).json({ policies: state.policies, policyRevision: state.policyRevision, conditions: POLICY_CONDITIONS, actions: POLICY_ACTIONS, severities: SEVERITIES, canEdit: ctx.isAdmin });
    }
    let auditRecorded = true;
    const audit = async (policy: { id: string; name: string; condition: string; action: string }, change: "created" | "enabled" | "disabled") => {
      try { await writeAuditEvent({ action: "agent_policy_changed", actor: ctx.actor, policy: { id: policy.id, name: policy.name, condition: policy.condition, action: policy.action }, change, policyRevision: (await readState()).policyRevision }); }
      catch (error) { auditRecorded = false; logError("agents: policy changed but the audit write failed", error); }
    };
    if (req.method === "POST") {
      const policy = await createPolicy(body);
      await audit(policy, "created");
      return res.status(201).json({ policy, auditRecorded });
    }
    const { policy, before } = await setPolicyEnabled(String(body.id ?? ""), body.enabled);
    if (before !== policy.enabled) await audit(policy, policy.enabled ? "enabled" : "disabled");
    return res.status(200).json({ policy, auditRecorded });
  } catch (error) {
    return fail(res, error, "agent policies");
  }
}
