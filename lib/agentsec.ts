/**
 * Agent Security (Days 10-12): a local registry of AI agents, a small set of versioned policies, and a deterministic
 * evaluator that says whether a proposed agent action should be ALLOWED, REVIEWED, held for APPROVAL or DENIED.
 *
 * This module DECIDES; it never runs a tool, contacts an agent or blocks anything by itself. A decision only has effect
 * if the runtime or gateway that runs the agent asks first and obeys the answer (and fails closed if it cannot ask).
 *
 * Fail-closed rules that no policy setting can weaken:
 *   - an agent that is not registered is never ALLOWED (at least REVIEW);
 *   - a suspended agent is always DENIED;
 *   - a tool that is not on the agent's registered allowlist is always DENIED.
 * Policies can only make a decision stricter. When several enabled policies match, the strictest one wins, so a
 * permissive-looking policy can never shadow a strict one.
 */
import { promises as fs } from "fs";
import path from "path";
import { randomBytes } from "crypto";

export const FRAMEWORKS = ["LangChain", "CrewAI", "AutoGen", "Semantic Kernel", "n8n", "OpenClaw", "MCP client", "Custom", "Other"] as const;
export const ENVIRONMENTS = ["development", "test", "staging", "production"] as const;
export const PRIVILEGES = ["low", "moderate", "high"] as const;
export const CRITICALITIES = ["low", "medium", "high", "critical"] as const;
export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export const POLICY_ACTIONS = ["review", "require_approval", "deny"] as const; // deliberately no "allow"
export const POLICY_CONDITIONS = ["tool_not_registered", "sensitive_action", "sensitive_external_transfer", "unknown_agent"] as const;

export type Decision = "ALLOW" | "REVIEW" | "REQUIRE_APPROVAL" | "DENY";
export type Agent = {
  id: string; name: string; framework: string; model: string; environment: string; owner: string;
  status: "registered" | "suspended"; tools: string[]; dataClasses: string[]; privileges: string; criticality: string;
  createdAt: string; createdBy: string; updatedAt: string | null; notes: string; seeded: boolean;
};
export type Policy = {
  id: string; name: string; description: string; enabled: boolean; action: (typeof POLICY_ACTIONS)[number];
  condition: (typeof POLICY_CONDITIONS)[number]; severity: string; version: number;
  /** Baseline policies cannot be disabled: they implement the fail-closed rules. */
  locked: boolean; createdAt: string; updatedAt: string | null;
};
export type AgentFinding = {
  id: string; agentId: string; agentName: string; tool: string; decision: Decision; severity: string;
  status: "open" | "pending_approval"; title: string; summary: string; count: number; firstSeenAt: string; lastSeenAt: string; eventId: string | null;
};
export type AgentState = { version: 2; policyRevision: number; agents: Agent[]; policies: Policy[]; findings: AgentFinding[] };

export class AgentSecError extends Error {
  code: "INVALID" | "NOT_FOUND" | "CONFLICT" | "LOCKED";
  constructor(message: string, code: "INVALID" | "NOT_FOUND" | "CONFLICT" | "LOCKED") {
    super(message);
    this.code = code;
  }
}

/* --------------------------------- defaults --------------------------------- */

const SEED_TIME = "2026-10-19T16:00:00.000Z";
const seedAgent = (a: Pick<Agent, "id" | "name" | "framework" | "model" | "environment" | "owner" | "tools" | "dataClasses" | "privileges" | "criticality" | "notes">): Agent =>
  ({ ...a, status: "registered", createdAt: SEED_TIME, createdBy: "seed", updatedAt: null, seeded: true });
const seedPolicy = (p: Pick<Policy, "id" | "name" | "description" | "action" | "condition" | "severity" | "locked">): Policy =>
  ({ ...p, enabled: true, version: 1, createdAt: SEED_TIME, updatedAt: null });

export function defaultState(): AgentState {
  return {
    version: 2, policyRevision: 1, findings: [],
    agents: [
      seedAgent({ id: "agent-procurement-01", name: "Procurement Copilot (example)", framework: "LangChain", model: "qwen2.5:7b", environment: "development", owner: "Procurement Engineering", tools: ["purchase_order.read", "supplier_email.draft"], dataClasses: ["internal"], privileges: "moderate", criticality: "medium", notes: "Seeded example. Not discovered from a live platform." }),
      seedAgent({ id: "agent-support-01", name: "Support Triage Agent (example)", framework: "n8n", model: "not reported", environment: "development", owner: "Customer Operations", tools: ["ticket.read", "ticket.comment"], dataClasses: ["customer-data"], privileges: "moderate", criticality: "high", notes: "Seeded example. Not discovered from a live platform." }),
      seedAgent({ id: "agent-finance-01", name: "Finance Action Agent (example)", framework: "Custom", model: "not reported", environment: "test", owner: "Finance Systems", tools: ["invoice.read", "payment.approve"], dataClasses: ["financial"], privileges: "high", criticality: "critical", notes: "Seeded example for privileged-action testing." })
    ],
    policies: [
      seedPolicy({ id: "POL-001", name: "Deny tools that are not registered", description: "An agent may only call tools on its registered allowlist.", action: "deny", condition: "tool_not_registered", severity: "high", locked: true }),
      seedPolicy({ id: "POL-002", name: "Human approval for sensitive actions", description: "Sensitive or high-impact actions need explicit approval.", action: "require_approval", condition: "sensitive_action", severity: "high", locked: false }),
      seedPolicy({ id: "POL-003", name: "Block sensitive data going outside", description: "Sending sensitive data to an external or untrusted destination is denied.", action: "deny", condition: "sensitive_external_transfer", severity: "critical", locked: false }),
      seedPolicy({ id: "POL-004", name: "Unknown agents are reviewed, not trusted", description: "Requests from an agent id that is not in the registry are held for review.", action: "review", condition: "unknown_agent", severity: "medium", locked: true })
    ]
  };
}

/* ---------------------------------- storage ---------------------------------- */

const storePath = () => path.join(process.cwd(), "data", "agentsec-state.json");
let chain: Promise<unknown> = Promise.resolve();

export async function readState(): Promise<AgentState> {
  try {
    const value = JSON.parse(await fs.readFile(storePath(), "utf8")) as AgentState;
    if (!value || value.version !== 2 || !Array.isArray(value.agents) || !Array.isArray(value.policies)) throw new Error("unexpected state shape");
    value.findings = Array.isArray(value.findings) ? value.findings : [];
    return value;
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return defaultState();
    throw error;
  }
}

/** Serialises read-modify-write cycles so two requests cannot lose one another's change. */
export function withState<T>(fn: (state: AgentState) => Promise<{ state: AgentState; result: T }> | { state: AgentState; result: T }): Promise<T> {
  const run = chain.then(async () => {
    const { state, result } = await fn(await readState());
    await fs.mkdir(path.dirname(storePath()), { recursive: true });
    const temp = `${storePath()}.${process.pid}.${randomBytes(3).toString("hex")}.tmp`;
    await fs.writeFile(temp, JSON.stringify(state, null, 2), { mode: 0o600 });
    await fs.rename(temp, storePath());
    return result;
  });
  chain = run.catch(() => undefined);
  return run;
}

/* -------------------------------- validation -------------------------------- */

const clean = (v: unknown, max: number) => (typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, max) : "");
export const TOOL_NAME = /^[A-Za-z0-9_.:/-]{1,120}$/;
const pickOf = <T extends readonly string[]>(list: T, v: unknown, fallback: T[number]): T[number] => ((list as readonly string[]).includes(String(v)) ? (v as T[number]) : fallback);
const list = (v: unknown, max: number, each: number, shape?: RegExp) =>
  Array.isArray(v) ? [...new Set((v as unknown[]).map((x) => clean(x, each)).filter((x) => x && (!shape || shape.test(x))))].slice(0, max) : [];

export type AgentInput = Record<string, unknown>;
export function buildAgent(input: AgentInput, createdBy: string, now = new Date().toISOString()): Agent {
  const name = clean(input.name, 100), owner = clean(input.owner, 100), framework = clean(input.framework, 60);
  if (!name || !owner) throw new AgentSecError("A name and an owner are required.", "INVALID");
  if (!(FRAMEWORKS as readonly string[]).includes(framework)) throw new AgentSecError(`Unsupported framework. Allowed: ${FRAMEWORKS.join(", ")}.`, "INVALID");
  const environment = clean(input.environment, 30);
  if (!(ENVIRONMENTS as readonly string[]).includes(environment)) throw new AgentSecError(`Invalid environment. Allowed: ${ENVIRONMENTS.join(", ")}.`, "INVALID");
  const rawTools = (Array.isArray(input.tools) ? (input.tools as unknown[]) : []).map((t) => clean(t, 120)).filter(Boolean);
  if (rawTools.some((t) => !TOOL_NAME.test(t))) throw new AgentSecError("Tool names may use letters, digits and . _ : / - only (no spaces or shell characters).", "INVALID");
  const tools = [...new Set(rawTools)].slice(0, 50);
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 30) || "agent";
  return {
    id: `agent-${slug}-${randomBytes(3).toString("hex")}`, name, framework, owner, model: clean(input.model, 100) || "not reported", environment,
    status: "registered", tools, dataClasses: list(input.dataClasses, 20, 60), privileges: pickOf(PRIVILEGES, input.privileges, "moderate"),
    criticality: pickOf(CRITICALITIES, input.criticality, "medium"), createdAt: now, createdBy, updatedAt: null, notes: clean(input.notes, 500), seeded: false
  };
}

/* ------------------------------- the evaluator ------------------------------- */

const SENSITIVE_TOOL = /(payment|transfer|delete|remove|drop|external|email\.send|admin|credential|secret|write|execute|exec|shell|browser\.submit|deploy)/i;
const EXTERNAL_TARGET = /(external|public|internet|third.?party|untrusted)/i;
const SENSITIVE_DATA = /(pii|personal|customer|financial|secret|credential|confidential|regulated|health|payment)/i;
const RANK: Record<Decision, number> = { ALLOW: 0, REVIEW: 1, REQUIRE_APPROVAL: 2, DENY: 3 };
const toDecision = (action: string): Decision => (action === "deny" ? "DENY" : action === "require_approval" ? "REQUIRE_APPROVAL" : "REVIEW");

export type ActionInput = { agentId: string; tool: string; dataClass?: string; target?: string; external?: boolean; sensitive?: boolean };
export type Reason = { policyId: string; policy: string; decision: Decision; reason: string; severity: string };
export type Evaluation = { decision: Decision; agent: { id: string; name: string } | null; tool: string; policyRevision: number; evaluatedAt: string; reasons: Reason[]; enforcementNote: string };

export function evaluateAction(state: AgentState, input: ActionInput, now = new Date().toISOString()): Evaluation {
  const agentId = clean(input.agentId, 120), tool = clean(input.tool, 160);
  const dataClass = clean(input.dataClass, 80) || "unknown", target = clean(input.target, 160);
  const external = input.external === true || EXTERNAL_TARGET.test(target);
  const sensitive = input.sensitive === true || SENSITIVE_TOOL.test(tool) || SENSITIVE_DATA.test(dataClass); // caller flags can only raise, never lower
  const agent = state.agents.find((a) => a.id === agentId) ?? null;
  const enabled = state.policies.filter((p) => p.enabled);
  const reasons: Reason[] = [];

  /** The strictest enabled policy for a condition; if none is enabled, the built-in floor (if any) applies. */
  const apply = (condition: Policy["condition"], text: string, floor: { id: string; name: string; action: Decision; severity: string } | null) => {
    const matches = enabled.filter((p) => p.condition === condition).sort((a, b) => RANK[toDecision(b.action)] - RANK[toDecision(a.action)]);
    if (matches.length) {
      reasons.push({ policyId: matches[0].id, policy: matches[0].name, decision: toDecision(matches[0].action), reason: text, severity: matches[0].severity });
      if (floor && RANK[floor.action] > RANK[toDecision(matches[0].action)]) reasons.push({ policyId: floor.id, policy: floor.name, decision: floor.action, reason: text, severity: floor.severity });
    } else if (floor) {
      reasons.push({ policyId: floor.id, policy: floor.name, decision: floor.action, reason: text, severity: floor.severity });
    }
  };

  if (!agent) {
    apply("unknown_agent", "This agent id is not in the registry.", { id: "BASELINE-UNKNOWN-AGENT", name: "Unregistered agents are never trusted", action: "REVIEW", severity: "medium" });
  } else {
    if (agent.status === "suspended") {
      reasons.push({ policyId: "BASELINE-SUSPENDED", policy: "Suspended agents are denied", decision: "DENY", reason: "This agent is suspended.", severity: "high" });
    }
    if (!agent.tools.includes(tool)) {
      apply("tool_not_registered", `"${tool}" is not on this agent's registered tool allowlist.`, { id: "BASELINE-UNREGISTERED-TOOL", name: "Unregistered tools are denied", action: "DENY", severity: "high" });
    }
    if (sensitive) apply("sensitive_action", "The tool or data class is classified as sensitive.", null);
    if (sensitive && external) apply("sensitive_external_transfer", "Sensitive data would go to an external or untrusted destination.", null);
  }

  const decision = reasons.reduce<Decision>((best, r) => (RANK[r.decision] > RANK[best] ? r.decision : best), "ALLOW");
  return {
    decision, agent: agent ? { id: agent.id, name: agent.name } : null, tool, policyRevision: state.policyRevision, evaluatedAt: now,
    reasons: reasons.length ? reasons : [{ policyId: "BASELINE", policy: "Registered tool", decision: "ALLOW", reason: "The agent is registered and active, the tool is on its allowlist and no policy matched.", severity: "info" }],
    enforcementNote: "A decision only protects anything if the runtime or gateway that runs the agent asks before acting, obeys the answer, and treats an unreachable or failed check as DENY."
  };
}

/* ---------------------------------- findings ---------------------------------- */

/** Records a non-ALLOW decision. A repeat of the same agent, tool and decision updates one open finding instead of adding another. */
export function recordFinding(state: AgentState, e: Evaluation, eventId: string | null, now = new Date().toISOString()): AgentFinding | null {
  if (e.decision === "ALLOW") return null;
  const agentId = e.agent?.id ?? "unregistered";
  const existing = state.findings.find((f) => f.agentId === agentId && f.tool === e.tool && f.decision === e.decision && (f.status === "open" || f.status === "pending_approval"));
  if (existing) {
    existing.count += 1; existing.lastSeenAt = now; existing.eventId = eventId ?? existing.eventId;
    return existing;
  }
  const worst = e.reasons.some((r) => r.severity === "critical") ? "critical" : e.reasons.some((r) => r.severity === "high") ? "high" : "medium";
  const finding: AgentFinding = {
    id: `AF-${Date.now().toString(36)}-${randomBytes(2).toString("hex")}`, agentId, agentName: e.agent?.name ?? "Unregistered agent", tool: e.tool,
    decision: e.decision, severity: worst, status: e.decision === "REQUIRE_APPROVAL" ? "pending_approval" : "open",
    title: `Agent action ${e.decision.toLowerCase().replace("_", " ")}`, summary: e.reasons.map((r) => r.reason).join(" ").slice(0, 600),
    count: 1, firstSeenAt: now, lastSeenAt: now, eventId
  };
  state.findings.unshift(finding);
  state.findings = state.findings.slice(0, 500);
  return finding;
}

/* ---------------------------------- scenarios ---------------------------------- */

export type Scenario = { id: string; name: string; description: string; input: ActionInput; expected: Decision };
export const SCENARIOS: Scenario[] = [
  { id: "scenario-01", name: "Registered read tool", description: "A registered, low-risk read tool should be allowed.", input: { agentId: "agent-procurement-01", tool: "purchase_order.read", dataClass: "internal" }, expected: "ALLOW" },
  { id: "scenario-02", name: "Unregistered shell tool", description: "A tool the agent was never registered for must be denied.", input: { agentId: "agent-procurement-01", tool: "shell.execute", dataClass: "internal" }, expected: "DENY" },
  { id: "scenario-03", name: "Payment approval", description: "A registered but high-impact action needs a human.", input: { agentId: "agent-finance-01", tool: "payment.approve", dataClass: "financial" }, expected: "REQUIRE_APPROVAL" },
  { id: "scenario-04", name: "Sensitive external transfer", description: "Customer data sent to an external destination is denied.", input: { agentId: "agent-support-01", tool: "ticket.comment", dataClass: "customer-data", target: "external vendor endpoint", external: true }, expected: "DENY" },
  { id: "scenario-05", name: "Unknown agent", description: "An unregistered agent id is held for review, never trusted.", input: { agentId: "agent-unregistered-simulation", tool: "ticket.read", dataClass: "unknown" }, expected: "REVIEW" },
  { id: "scenario-06", name: "Caller cannot downgrade sensitivity", description: "Saying sensitive:false does not hide a payment tool.", input: { agentId: "agent-finance-01", tool: "payment.approve", dataClass: "internal", sensitive: false }, expected: "REQUIRE_APPROVAL" }
];

/** Runs the scenarios against the CURRENT state without recording anything. A failure means the live policy set no longer behaves as expected. */
export function runScenarios(state: AgentState) {
  const results = SCENARIOS.map((s) => {
    const e = evaluateAction(state, s.input);
    return { id: s.id, name: s.name, description: s.description, expected: s.expected, actual: e.decision, passed: e.decision === s.expected, reasons: e.reasons.map((r) => r.reason) };
  });
  return { results, passed: results.filter((r) => r.passed).length, total: results.length };
}

/* --------------------------------- mutations --------------------------------- */

export async function registerAgent(input: AgentInput, createdBy: string): Promise<Agent> {
  const agent = buildAgent(input, createdBy);
  return withState((state) => {
    if (state.agents.length >= 500) throw new AgentSecError("The registry is full (500 agents).", "CONFLICT");
    return { state: { ...state, agents: [agent, ...state.agents] }, result: agent };
  });
}

export async function setAgentStatus(id: string, status: unknown): Promise<{ agent: Agent; before: Agent["status"] }> {
  if (status !== "registered" && status !== "suspended") throw new AgentSecError('status must be "registered" or "suspended".', "INVALID");
  return withState((state) => {
    const found = state.agents.find((a) => a.id === id);
    if (!found) throw new AgentSecError("Agent not found.", "NOT_FOUND");
    const updated: Agent = { ...found, status, updatedAt: new Date().toISOString() };
    return { state: { ...state, agents: state.agents.map((a) => (a.id === id ? updated : a)) }, result: { agent: updated, before: found.status } };
  });
}

export type PolicyInput = Record<string, unknown>;
export async function createPolicy(input: PolicyInput): Promise<Policy> {
  const name = clean(input.name, 100), description = clean(input.description, 300);
  const condition = clean(input.condition, 60), action = clean(input.action, 30), severity = clean(input.severity, 20);
  if (!name || !description) throw new AgentSecError("A name and a description are required.", "INVALID");
  if (!(POLICY_CONDITIONS as readonly string[]).includes(condition)) throw new AgentSecError(`Invalid condition. Allowed: ${POLICY_CONDITIONS.join(", ")}.`, "INVALID");
  if (!(POLICY_ACTIONS as readonly string[]).includes(action)) throw new AgentSecError(`Invalid action. Allowed: ${POLICY_ACTIONS.join(", ")} (a policy can restrict, never allow).`, "INVALID");
  if (!(SEVERITIES as readonly string[]).includes(severity)) throw new AgentSecError(`Invalid severity. Allowed: ${SEVERITIES.join(", ")}.`, "INVALID");
  const now = new Date().toISOString();
  const policy: Policy = { id: `POL-${randomBytes(3).toString("hex").toUpperCase()}`, name, description, enabled: true, action: action as Policy["action"], condition: condition as Policy["condition"], severity, version: 1, locked: false, createdAt: now, updatedAt: null };
  return withState((state) => {
    if (state.policies.length >= 100) throw new AgentSecError("Too many policies (100).", "CONFLICT");
    return { state: { ...state, policyRevision: state.policyRevision + 1, policies: [...state.policies, policy] }, result: policy };
  });
}

export async function setPolicyEnabled(id: string, enabled: unknown): Promise<{ policy: Policy; before: boolean }> {
  if (typeof enabled !== "boolean") throw new AgentSecError("enabled must be true or false.", "INVALID");
  return withState((state) => {
    const found = state.policies.find((p) => p.id === id);
    if (!found) throw new AgentSecError("Policy not found.", "NOT_FOUND");
    if (found.locked && !enabled) throw new AgentSecError("This is a baseline policy and cannot be disabled: it implements a fail-closed rule.", "LOCKED");
    const updated: Policy = { ...found, enabled, version: found.version + 1, updatedAt: new Date().toISOString() };
    return { state: { ...state, policyRevision: state.policyRevision + 1, policies: state.policies.map((p) => (p.id === id ? updated : p)) }, result: { policy: updated, before: found.enabled } };
  });
}

/** Stores the finding for a non-ALLOW evaluation (deduplicated). The decision itself is not recomputed: what was decided is what is recorded. */
export async function recordEvaluation(e: Evaluation, eventId: string | null): Promise<AgentFinding | null> {
  if (e.decision === "ALLOW") return null;
  return withState((state) => ({ state, result: recordFinding(state, e, eventId) }));
}
