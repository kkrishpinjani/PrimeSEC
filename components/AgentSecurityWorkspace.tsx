import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { LogoMark } from "./Logo";
import { fullSignOut } from "../lib/signOutClient";
import type { Agent, AgentFinding, Evaluation, Policy } from "../lib/agentsec";
import type { AuditEvent } from "../lib/audit";

type Overview = {
  metrics: Record<string, number>; policyRevision: number; findings: AgentFinding[]; events: AuditEvent[];
  canEdit: boolean; canEvaluate: boolean;
};
type ScenarioRun = { ranAt: string; policyRevision: number; passed: number; total: number; note: string; results: { id: string; name: string; description: string; expected: string; actual: string; passed: boolean; reasons: string[] }[] };
type Tab = "overview" | "inventory" | "policies" | "lab";

const TABS: { id: Tab; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "inventory", label: "Agent inventory" }, { id: "policies", label: "Policies" }, { id: "lab", label: "Test lab" }];
const DECISION_CLASS: Record<string, string> = { ALLOW: "sev-low", REVIEW: "sev-medium", REQUIRE_APPROVAL: "sev-medium", DENY: "sev-high" };
const when = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : "—");

function describe(e: AuditEvent): string {
  switch (e.action) {
    case "agent_registered": return `Registered ${e.agent.name} (${e.agent.framework}, ${e.agent.environment}, ${e.agent.toolCount} tools)`;
    case "agent_status_changed": return `${e.agent.name}: ${e.from} → ${e.to}`;
    case "agent_policy_changed": return `Policy ${e.policy.id} ${e.change} (revision ${e.policyRevision})`;
    case "agent_policy_evaluated": return `${e.agentId} → ${e.tool}: ${e.decision}`;
    case "agent_scenarios_run": return `Scenario suite: ${e.passed}/${e.total} passed`;
    default: return e.action;
  }
}

export default function AgentSecurityWorkspace({ user, roles }: { user: { name?: string | null; email?: string | null }; roles: string[] }) {
  const [tab, setTab] = useState<Tab>("overview");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [frameworks, setFrameworks] = useState<string[]>([]);
  const [environments, setEnvironments] = useState<string[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [policyOptions, setPolicyOptions] = useState<{ conditions: string[]; actions: string[]; severities: string[] }>({ conditions: [], actions: [], severities: [] });
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState("");
  const [run, setRun] = useState<ScenarioRun | null>(null);
  const [tried, setTried] = useState<Evaluation | null>(null);
  const [form, setForm] = useState({ name: "", framework: "Custom", owner: "", environment: "development", model: "", tools: "", privileges: "moderate", criticality: "medium" });
  const [policyForm, setPolicyForm] = useState({ name: "", description: "", condition: "sensitive_action", action: "require_approval", severity: "high" });
  const [action, setAction] = useState({ agentId: "agent-procurement-01", tool: "", dataClass: "internal", target: "", external: false });
  const isAdmin = roles.includes("SOC_Admin");
  const canEvaluate = isAdmin || roles.includes("SOC_Analyst");
  const displayName = user.name || user.email || "Analyst";

  const load = useCallback(async () => {
    try {
      const [o, a, p] = await Promise.all([fetch("/api/agents/overview", { cache: "no-store" }), fetch("/api/agents", { cache: "no-store" }), fetch("/api/agents/policies", { cache: "no-store" })]);
      const [ob, ab, pb] = await Promise.all([o.json(), a.json(), p.json()]);
      if (!o.ok) throw new Error(ob.error || "Could not load the overview.");
      if (!a.ok) throw new Error(ab.error || "Could not load the agent inventory.");
      if (!p.ok) throw new Error(pb.error || "Could not load the policies.");
      setOverview(ob); setAgents(ab.agents); setFrameworks(ab.frameworks); setEnvironments(ab.environments);
      setPolicies(pb.policies); setPolicyOptions({ conditions: pb.conditions, actions: pb.actions, severities: pb.severities });
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function send(id: string, url: string, init: RequestInit, done: (b: any) => string) {
    setBusy(id); setError(""); setNotice("");
    try {
      const r = await fetch(url, { ...init, headers: { "Content-Type": "application/json" } });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "Request failed.");
      setNotice(done(b));
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }

  const register = () => send("register", "/api/agents", { method: "POST", body: JSON.stringify({ ...form, tools: form.tools.split(/[\n,]+/).map((t) => t.trim()).filter(Boolean) }) },
    (b) => { setForm({ ...form, name: "", tools: "", owner: "" }); return `Registered ${b.agent.name} (${b.agent.id}).`; });
  const setStatus = (a: Agent) => send(a.id, "/api/agents", { method: "PATCH", body: JSON.stringify({ id: a.id, status: a.status === "suspended" ? "registered" : "suspended" }) }, (b) => `${b.agent.name} is now ${b.agent.status}.`);
  const toggle = (p: Policy) => send(p.id, "/api/agents/policies", { method: "PATCH", body: JSON.stringify({ id: p.id, enabled: !p.enabled }) }, (b) => `${b.policy.name} ${b.policy.enabled ? "enabled" : "disabled"}.`);
  const addPolicy = () => send("policy", "/api/agents/policies", { method: "POST", body: JSON.stringify(policyForm) }, (b) => { setPolicyForm({ ...policyForm, name: "", description: "" }); return `Added ${b.policy.id}.`; });
  const runScenarios = () => send("scenarios", "/api/agents/scenarios", { method: "POST" }, (b) => { setRun(b); return `Scenario suite: ${b.passed} of ${b.total} passed.`; });
  const tryAction = () => send("evaluate", "/api/agents/evaluate", { method: "POST", body: JSON.stringify(action) }, (b) => { setTried(b); return `Decision: ${b.decision}.`; });

  const m = overview?.metrics;
  return (
    <section className="preview soc-dash vapt-page" aria-label="Agent security">
      <div className="pv-top">
        <span className="pv-logo"><LogoMark size={18} /></span>
        <Link href="/dashboard" className="pv-chip">← Dashboard</Link>
        <span className="pv-chip">Agent security</span>
        <div className="pv-actions">
          <span className="pv-user" title={roles.join(", ")}>
            <span className="pv-avatar">{displayName.slice(0, 1).toUpperCase()}</span>
            <span className="pv-user-text"><b>{displayName}</b><small>{roles[0] ?? "No role"}</small></span>
          </span>
          <button className="pv-btn" onClick={() => void fullSignOut()}>Sign out</button>
        </div>
      </div>

      <div className="pv-tabs" role="tablist">
        {TABS.map((t) => <button key={t.id} role="tab" aria-selected={tab === t.id} className={tab === t.id ? "on" : ""} onClick={() => setTab(t.id)}>{t.label}</button>)}
      </div>

      <div className="vapt-body">
        <p className="vapt-warning">This records which AI agents you know about and <b>decides</b> whether a proposed action should be allowed. It does not run, monitor or block any agent by itself: a decision only matters if the system that runs the agent asks first and obeys the answer. The inventory is entered by hand (seeded examples are marked); nothing is discovered automatically.</p>
        {error && <div className="pv-list pv-error" role="alert">{error}</div>}
        {notice && <div className="pv-list vapt-ok" role="status">{notice}</div>}

        {tab === "overview" && (
          <>
            <div className="pv-invest-summary fd-tiles">
              <div><span>Agents</span><strong>{m?.agents ?? "…"}</strong><em>{m ? `${m.highPrivilege} high-privilege, ${m.suspended} suspended` : ""}</em></div>
              <div><span>Policies on</span><strong>{m?.enabledPolicies ?? "…"}</strong><em>revision {overview?.policyRevision ?? "…"}</em></div>
              <div><span>Open findings</span><strong>{m?.openFindings ?? "…"}</strong><em>{m ? `${m.pendingApprovals} waiting for approval` : ""}</em></div>
              <div><span>Recent decisions</span><strong>{m?.recentEvaluations ?? "…"}</strong><em>{m ? `${m.recentDenied} denied (last 100 events)` : ""}</em></div>
            </div>
            <div className="pv-list">
              <small>Findings (non-allow decisions, repeats are counted not duplicated)</small>
              {overview && overview.findings.length === 0 ? <p className="pv-empty">None yet. Use the Test lab to evaluate an action.</p> : overview?.findings.map((f) => (
                <div className="pv-row" key={f.id}>
                  <span className={`pv-sev ${DECISION_CLASS[f.decision]}`}>{f.decision.replace("_", " ")}</span>
                  <strong>{f.agentName}</strong><code>{f.tool}</code><span>×{f.count} · last {when(f.lastSeenAt)}</span>
                </div>
              ))}
            </div>
            <div className="pv-list">
              <small>Recent activity (from the audit log)</small>
              {overview && overview.events.length === 0 ? <p className="pv-empty">No activity yet.</p> : overview?.events.map((e) => (
                <div className="pv-row" key={e.eventId}><span>{when(e.timestamp)}</span><strong>{describe(e)}</strong><code>{e.actor.email || e.actor.name || "—"}</code></div>
              ))}
            </div>
          </>
        )}

        {tab === "inventory" && (
          <>
            <div className="pv-list">
              <small>{agents.length} registered agent{agents.length === 1 ? "" : "s"}</small>
              {agents.map((a) => (
                <div className="fd-card" key={a.id}>
                  <div className="fd-head">
                    <span className={`pv-sev ${a.status === "suspended" ? "sev-high" : "sev-low"}`}>{a.status}</span>
                    <strong className="fd-name">{a.name}</strong><code>{a.id}</code>
                    {a.seeded && <span className="fd-flag">Example</span>}
                  </div>
                  <p className="fd-meta">{a.framework} · {a.environment} · owner {a.owner} · privileges {a.privileges} · criticality {a.criticality}</p>
                  <div className="fd-cves">{a.tools.length ? a.tools.map((t) => <code key={t}>{t}</code>) : <em>no tools registered</em>}</div>
                  {isAdmin && <div className="fd-actions"><button className="pv-btn" disabled={busy !== ""} onClick={() => void setStatus(a)}>{a.status === "suspended" ? "Reactivate" : "Suspend (deny everything)"}</button></div>}
                </div>
              ))}
            </div>
            <div className="pv-list">
              <small>Register an agent {isAdmin ? "" : "(SOC_Admin only)"}</small>
              <div className="fd-edit">
                <label>Name<input className="fd-input" value={form.name} maxLength={100} disabled={!isAdmin} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
                <label>Owner<input className="fd-input" value={form.owner} maxLength={100} disabled={!isAdmin} onChange={(e) => setForm({ ...form, owner: e.target.value })} /></label>
                <label>Framework<select className="fd-input" value={form.framework} disabled={!isAdmin} onChange={(e) => setForm({ ...form, framework: e.target.value })}>{frameworks.map((f) => <option key={f}>{f}</option>)}</select></label>
                <label>Environment<select className="fd-input" value={form.environment} disabled={!isAdmin} onChange={(e) => setForm({ ...form, environment: e.target.value })}>{environments.map((f) => <option key={f}>{f}</option>)}</select></label>
                <label>Model (optional)<input className="fd-input" value={form.model} maxLength={100} disabled={!isAdmin} onChange={(e) => setForm({ ...form, model: e.target.value })} /></label>
                <label>Allowed tools (comma or line separated)<textarea className="fd-input" rows={2} value={form.tools} disabled={!isAdmin} placeholder="ticket.read, ticket.comment" onChange={(e) => setForm({ ...form, tools: e.target.value })} /></label>
                <div className="fd-actions"><button className="pv-btn pv-btn-primary" disabled={!isAdmin || busy !== "" || !form.name || !form.owner} onClick={() => void register()}>{busy === "register" ? "Saving…" : "Register agent"}</button></div>
              </div>
              <p className="fd-meta">The tool list is the agent&apos;s allowlist: anything else is denied. Registering is SOC_Admin only because it decides what an agent is trusted to do.</p>
            </div>
          </>
        )}

        {tab === "policies" && (
          <>
            <div className="pv-list">
              <small>Policy revision {overview?.policyRevision ?? "…"} · when several policies match, the strictest one wins</small>
              {policies.map((p) => (
                <div className="fd-card" key={p.id}>
                  <div className="fd-head">
                    <span className={`pv-sev ${p.enabled ? "sev-low" : "sev-medium"}`}>{p.enabled ? "on" : "off"}</span>
                    <strong className="fd-name">{p.name}</strong><code>{p.id}</code>
                    {p.locked && <span className="fd-flag" title="Implements a fail-closed rule and cannot be turned off">Baseline</span>}
                  </div>
                  <p className="fd-meta">{p.description} · when <code>{p.condition}</code> → <b>{p.action.replace("_", " ")}</b> · severity {p.severity} · v{p.version}</p>
                  {isAdmin && !p.locked && <div className="fd-actions"><button className="pv-btn" disabled={busy !== ""} onClick={() => void toggle(p)}>{p.enabled ? "Turn off" : "Turn on"}</button></div>}
                </div>
              ))}
            </div>
            <div className="pv-list">
              <small>Add a restrictive policy {isAdmin ? "" : "(SOC_Admin only)"}</small>
              <div className="fd-edit">
                <label>Name<input className="fd-input" value={policyForm.name} maxLength={100} disabled={!isAdmin} onChange={(e) => setPolicyForm({ ...policyForm, name: e.target.value })} /></label>
                <label>Description<input className="fd-input" value={policyForm.description} maxLength={300} disabled={!isAdmin} onChange={(e) => setPolicyForm({ ...policyForm, description: e.target.value })} /></label>
                <label>When<select className="fd-input" value={policyForm.condition} disabled={!isAdmin} onChange={(e) => setPolicyForm({ ...policyForm, condition: e.target.value })}>{policyOptions.conditions.map((c) => <option key={c}>{c}</option>)}</select></label>
                <label>Then<select className="fd-input" value={policyForm.action} disabled={!isAdmin} onChange={(e) => setPolicyForm({ ...policyForm, action: e.target.value })}>{policyOptions.actions.map((c) => <option key={c}>{c}</option>)}</select></label>
                <label>Severity<select className="fd-input" value={policyForm.severity} disabled={!isAdmin} onChange={(e) => setPolicyForm({ ...policyForm, severity: e.target.value })}>{policyOptions.severities.map((c) => <option key={c}>{c}</option>)}</select></label>
                <div className="fd-actions"><button className="pv-btn pv-btn-primary" disabled={!isAdmin || busy !== "" || !policyForm.name || !policyForm.description} onClick={() => void addPolicy()}>{busy === "policy" ? "Saving…" : "Add policy"}</button></div>
              </div>
              <p className="fd-meta">A policy can only make decisions stricter: there is no &quot;allow&quot; action, and the baseline rules (unregistered tools denied, unknown or suspended agents never trusted) cannot be turned off.</p>
            </div>
          </>
        )}

        {tab === "lab" && (
          <>
            <div className="pv-list">
              <small>Scenario suite (does not record findings)</small>
              <p className="fd-meta">Six fixed checks of the rules against the <b>current</b> policies. If you change a policy and a check starts failing, that is the point.</p>
              <div className="fd-actions"><button className="pv-btn pv-btn-primary" disabled={!canEvaluate || busy !== ""} onClick={() => void runScenarios()}>{busy === "scenarios" ? "Running…" : "Run scenarios"}</button></div>
              {run && (
                <>
                  <p className="fd-meta">{run.passed} of {run.total} passed · policy revision {run.policyRevision} · {when(run.ranAt)}</p>
                  {run.results.map((r) => (
                    <div className="pv-row" key={r.id}>
                      <span className={`pv-sev ${r.passed ? "sev-low" : "sev-high"}`}>{r.passed ? "pass" : "fail"}</span>
                      <strong>{r.name}</strong><span>expected {r.expected.replace("_", " ")}, got {r.actual.replace("_", " ")}</span>
                    </div>
                  ))}
                  <p className="fd-meta">{run.note}</p>
                </>
              )}
            </div>
            <div className="pv-list">
              <small>Try an action (records an audit event and, if not allowed, a finding)</small>
              <div className="fd-edit">
                <label>Agent<select className="fd-input" value={action.agentId} disabled={!canEvaluate} onChange={(e) => setAction({ ...action, agentId: e.target.value })}>
                  {agents.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}<option value="agent-not-in-registry">(an unregistered agent id)</option>
                </select></label>
                <label>Tool<input className="fd-input" value={action.tool} maxLength={120} disabled={!canEvaluate} placeholder="e.g. shell.execute" onChange={(e) => setAction({ ...action, tool: e.target.value })} /></label>
                <label>Data class<input className="fd-input" value={action.dataClass} maxLength={80} disabled={!canEvaluate} onChange={(e) => setAction({ ...action, dataClass: e.target.value })} /></label>
                <label>Destination (optional)<input className="fd-input" value={action.target} maxLength={160} disabled={!canEvaluate} placeholder="e.g. external vendor endpoint" onChange={(e) => setAction({ ...action, target: e.target.value })} /></label>
                <label className="fd-check"><input type="checkbox" checked={action.external} disabled={!canEvaluate} onChange={(e) => setAction({ ...action, external: e.target.checked })} /> Goes to an external destination</label>
                <div className="fd-actions"><button className="pv-btn pv-btn-primary" disabled={!canEvaluate || busy !== "" || !action.tool} onClick={() => void tryAction()}>{busy === "evaluate" ? "Evaluating…" : "Evaluate"}</button></div>
              </div>
              {tried && (
                <div className="fd-card">
                  <div className="fd-head"><span className={`pv-sev ${DECISION_CLASS[tried.decision]}`}>{tried.decision.replace("_", " ")}</span><strong className="fd-name">{tried.tool}</strong><code>revision {tried.policyRevision}</code></div>
                  <ul>{tried.reasons.map((r, i) => <li key={i}><b>{r.policy}</b>: {r.reason}</li>)}</ul>
                  <p className="fd-meta">{tried.enforcementNote}</p>
                </div>
              )}
              {!canEvaluate && <p className="fd-meta">Evaluating needs the SOC_Analyst or SOC_Admin role.</p>}
            </div>
          </>
        )}
      </div>
    </section>
  );
}
