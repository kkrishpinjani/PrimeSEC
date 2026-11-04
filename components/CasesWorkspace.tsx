import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { LogoMark } from "./Logo";
import { fullSignOut } from "../lib/signOutClient";
import type { Case, CaseSummary, CaseStatus, Plan } from "../lib/cases";
import type { Proposal } from "../lib/response";

const STATUSES: CaseStatus[] = ["new", "triaged", "investigating", "contained", "resolved", "closed"];
const NEXT: Record<CaseStatus, CaseStatus[]> = { new: ["triaged", "investigating", "closed"], triaged: ["investigating", "contained", "resolved", "closed"], investigating: ["contained", "resolved", "closed"], contained: ["investigating", "resolved", "closed"], resolved: ["investigating", "closed"], closed: [] };
const ACTIONS = ["isolate_endpoint", "block_ip", "disable_user", "quarantine_file", "run_scan"];
type List = { items: CaseSummary[]; total: number; openCount: number; openBySeverity: Record<string, number> };

const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");
const sev = (s: string) => (s === "critical" || s === "high" ? "sev-high" : s === "medium" ? "sev-medium" : "sev-low");

export default function CasesWorkspace({ user, roles }: { user: { name?: string | null; email?: string | null }; roles: string[] }) {
  const [list, setList] = useState<List | null>(null);
  const [filter, setFilter] = useState("");
  const [search, setSearch] = useState("");
  const [detail, setDetail] = useState<{ case: Case; proposals: Proposal[] } | null>(null);
  const [plan, setPlan] = useState<Plan | null>(null);
  const [owner, setOwner] = useState("");
  const [ev, setEv] = useState({ type: "note", title: "", text: "" });
  const [prop, setProp] = useState({ actionType: "isolate_endpoint", target: "", rationale: "" });
  const [nc, setNc] = useState({ title: "", description: "", severity: "medium" });
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const canWork = roles.includes("SOC_Admin") || roles.includes("SOC_Analyst");
  const displayName = user.name || user.email || "Analyst";

  const load = useCallback(async () => {
    const params = new URLSearchParams({ limit: "200" });
    if (filter) params.set("status", filter);
    if (search.trim()) params.set("q", search.trim());
    const r = await fetch(`/api/cases?${params}`, { cache: "no-store" });
    const b = await r.json();
    if (!r.ok) return setError(b.error || "Could not load cases.");
    setList(b);
  }, [filter, search]);
  useEffect(() => { void load(); }, [load]);

  async function open(id: string) {
    const r = await fetch(`/api/cases/${encodeURIComponent(id)}`, { cache: "no-store" });
    const b = await r.json();
    if (!r.ok) return setError(b.error || "Could not open that case.");
    setDetail(b); setPlan(null); setOwner(b.case.owner ?? "");
  }
  async function act(label: string, body: Record<string, unknown>, done: string, after?: (b: any) => void) {
    if (!detail) return;
    setBusy(label); setError(""); setNotice("");
    try {
      const r = await fetch(`/api/cases/${encodeURIComponent(detail.case.id)}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "The change was refused.");
      setNotice(done); after?.(b);
      await Promise.all([open(detail.case.id), load()]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }
  async function create() {
    setBusy("create"); setError(""); setNotice("");
    try {
      const r = await fetch("/api/cases", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(nc) });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "The case could not be opened.");
      setNotice(`Case ${b.case.caseKey} opened.`); setNc({ title: "", description: "", severity: "medium" });
      await load(); await open(b.case.id);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }
  const transition = (status: CaseStatus) => {
    const needsNote = status === "resolved" || status === "closed";
    const note = needsNote ? window.prompt(`Why are you moving this case to "${status}"? (what was found or decided)`) ?? "" : "";
    if (needsNote && note.trim().length < 10) return setError("A note of at least 10 characters is needed to resolve or close a case.");
    void act(`t-${status}`, { action: "transition", status, note }, `Moved to ${status}.`);
  };

  const c = detail?.case;
  const tile = (label: string, value: number | string, note: string) => <div><span>{label}</span><strong>{value}</strong><em>{note}</em></div>;

  return (
    <section className="preview soc-dash vapt-page" aria-label="Investigation cases">
      <div className="pv-top">
        <span className="pv-logo"><LogoMark size={18} /></span>
        <Link href="/dashboard" className="pv-chip">← Dashboard</Link>
        <span className="pv-chip">Cases</span>
        <div className="pv-actions">
          <Link href="/response" className="pv-btn">Governed response ↗</Link>
          <span className="pv-user" title={roles.join(", ")}>
            <span className="pv-avatar">{displayName.slice(0, 1).toUpperCase()}</span>
            <span className="pv-user-text"><b>{displayName}</b><small>{roles[0] ?? "No role"}</small></span>
          </span>
          <button className="pv-btn" onClick={() => void fullSignOut()}>Sign out</button>
        </div>
      </div>

      <div className="vapt-body">
        <p className="vapt-warning">A case is the written record of one investigation: an owner, a status, the evidence and a timeline of who did what. It <b>records work and suggests next steps</b>; it never changes a system. Any containment action is only a <b>proposal</b> that a second administrator must approve in Governed response, and it does nothing unless execution has been deliberately enabled there. The plan is a rule-based checklist, not an AI verdict.</p>
        {error && <div className="pv-list pv-error" role="alert">{error}</div>}
        {notice && <div className="pv-list vapt-ok" role="status">{notice}</div>}

        {list && (
          <div className="pv-invest-summary fd-tiles">
            {tile("Open cases", list.openCount, "not resolved or closed")}
            {tile("Critical / high", (list.openBySeverity.critical ?? 0) + (list.openBySeverity.high ?? 0), "open")}
            {tile("All cases", list.total, filter ? `filtered by ${filter}` : "in the store")}
          </div>
        )}

        <div className="pv-list">
          <div className="fd-actions">
            <select className="fd-input" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Status filter">
              <option value="">All statuses</option>{STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <input className="fd-input" value={search} maxLength={100} placeholder="Search title or key" onChange={(e) => setSearch(e.target.value)} />
          </div>
          {!list || list.items.length === 0 ? <p className="pv-empty">No cases yet. Use <b>Open case</b> on an investigated alert in the dashboard, or create one below.</p> : list.items.map((x) => (
            <div className="pv-row" key={x.id}>
              <span className={`pv-sev ${sev(x.severity)}`}>{x.severity} {x.priorityScore}</span>
              <strong>{x.title}</strong>
              <span>{x.caseKey} · {x.status} · {x.owner ?? "unassigned"} · {x.evidenceCount} evidence · {when(x.updatedAt)}</span>
              <button className="pv-btn" onClick={() => void open(x.id)}>Open</button>
            </div>
          ))}
        </div>

        <div className="pv-list">
          <small>New case {canWork ? "" : "(SOC_Analyst or SOC_Admin only)"}</small>
          <div className="fd-edit sap-form">
            <label>Title<input className="fd-input" value={nc.title} maxLength={300} disabled={!canWork} onChange={(e) => setNc({ ...nc, title: e.target.value })} /></label>
            <label>Description<textarea className="fd-input" rows={2} value={nc.description} maxLength={4000} disabled={!canWork} onChange={(e) => setNc({ ...nc, description: e.target.value })} /></label>
            <label>Severity<select className="fd-input" value={nc.severity} disabled={!canWork} onChange={(e) => setNc({ ...nc, severity: e.target.value })}>{["low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}</select></label>
            <div className="fd-actions"><button className="pv-btn pv-btn-primary" disabled={!canWork || busy !== "" || nc.title.trim().length < 3} onClick={() => void create()}>{busy === "create" ? "Opening…" : "Open case"}</button></div>
          </div>
        </div>

        {c && (
          <div className="pv-list fd-card" aria-label="Case detail">
            <div className="fd-head"><span className={`pv-sev ${sev(c.severity)}`}>{c.severity} {c.priorityScore}</span><strong className="fd-name">{c.title}</strong><code>{c.caseKey}</code><span className="fd-flag">{c.status}</span></div>
            <p className="fd-meta">Opened by {c.createdBy} · {when(c.createdAt)} · owner {c.owner ?? "unassigned"}{c.closedAt ? ` · closed ${when(c.closedAt)}` : ""}</p>
            {c.description && <p>{c.description}</p>}
            {c.snapshot?.alert && <p className="fd-meta">Alert {c.snapshot.alert.id} · {c.snapshot.alert.agent} · level {c.snapshot.alert.level} · {(c.snapshot.matches?.length ?? 0)} potential intelligence match(es), captured {when(c.snapshot.capturedAt)}</p>}
            {c.snapshot?.matches && c.snapshot.matches.length > 0 && <div className="fd-cves">{c.snapshot.matches.map((m, i) => <code key={i}>{m.matchedValue} ← {m.indicatorName}</code>)}</div>}

            {canWork && c.status !== "closed" && (
              <div className="fd-actions">
                {NEXT[c.status].map((s) => <button key={s} className="pv-btn" disabled={busy !== ""} onClick={() => transition(s)}>→ {s}</button>)}
                <input className="fd-input" value={owner} maxLength={256} placeholder="Assign to (email)" onChange={(e) => setOwner(e.target.value)} />
                <button className="pv-btn" disabled={busy !== ""} onClick={() => void act("assign", { action: "assign", owner }, owner ? `Assigned to ${owner}.` : "Unassigned.")}>Assign</button>
                <button className="pv-btn pv-btn-primary" disabled={busy !== ""} onClick={() => void act("plan", { action: "plan" }, "Plan generated.", (b) => setPlan(b.plan))}>{busy === "plan" ? "Working…" : "Investigation plan"}</button>
              </div>
            )}

            {plan && (
              <div className="fd-card">
                <div className="fd-head"><strong className="fd-name">Investigation plan</strong><span className="fd-flag">Rule-based · decision support</span></div>
                <p className="fd-meta">{plan.assessment}</p>
                <ol>{plan.steps.map((s, i) => <li key={i}><b>{s.step}</b> <em>({s.source})</em><br />{s.detail}</li>)}</ol>
                {plan.suggestedProposals.map((p, i) => (
                  <p className="fd-meta" key={i}>Suggestion only: <code>{p.actionType}</code> on <code>{p.target}</code>. {p.rationale} <button className="pv-btn" disabled={!canWork} onClick={() => setProp({ actionType: p.actionType, target: p.target, rationale: p.rationale })}>Use in proposal form</button></p>
                ))}
                <p className="fd-meta">{plan.execution}</p>
              </div>
            )}

            <h4>Evidence ({c.evidence.length})</h4>
            {c.evidence.map((e) => <div className="fd-card" key={e.id}><div className="fd-head"><strong className="fd-name">{e.title}</strong><code>{e.type}</code></div><p className="fd-meta">{e.source} · {e.createdBy} · {when(e.createdAt)}</p>{Object.keys(e.content).length > 0 && <pre style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(e.content, null, 2)}</pre>}</div>)}
            {canWork && c.status !== "closed" && (
              <div className="fd-edit sap-form">
                <label>Evidence title<input className="fd-input" value={ev.title} maxLength={300} onChange={(e) => setEv({ ...ev, title: e.target.value })} /></label>
                <label>Type<input className="fd-input" value={ev.type} maxLength={80} onChange={(e) => setEv({ ...ev, type: e.target.value })} /></label>
                <label>What you found<textarea className="fd-input" rows={3} value={ev.text} maxLength={5000} onChange={(e) => setEv({ ...ev, text: e.target.value })} /></label>
                <div className="fd-actions"><button className="pv-btn" disabled={busy !== "" || !ev.title.trim() || !ev.type.trim()} onClick={() => void act("evidence", { action: "evidence", type: ev.type, title: ev.title, content: ev.text ? { note: ev.text } : {} }, "Evidence added.", () => setEv({ type: "note", title: "", text: "" }))}>Add evidence</button></div>
              </div>
            )}

            <h4>Response proposals ({detail.proposals.length})</h4>
            {detail.proposals.length === 0 ? <p className="pv-empty">None. A proposal only asks for review; it acts on nothing.</p> : detail.proposals.map((p) => <div className="pv-row" key={p.id}><span className={`pv-sev ${p.status === "rejected" ? "sev-high" : "sev-medium"}`}>{p.status}</span><strong>{p.actionType} → {p.target}</strong><span>by {p.proposedBy}{p.reviewedBy ? ` · reviewed by ${p.reviewedBy}` : ""}</span></div>)}
            {detail.proposals.length > 0 && <p className="fd-meta">Review and execution happen in <Link className="pv-link" href="/response">Governed response</Link>.</p>}
            {canWork && c.status !== "closed" && (
              <div className="fd-edit sap-form">
                <label>Action<select className="fd-input" value={prop.actionType} onChange={(e) => setProp({ ...prop, actionType: e.target.value })}>{ACTIONS.map((a) => <option key={a}>{a}</option>)}</select></label>
                <label>Target<input className="fd-input" value={prop.target} maxLength={300} onChange={(e) => setProp({ ...prop, target: e.target.value })} /></label>
                <label>Why (the reviewer reads this)<textarea className="fd-input" rows={2} value={prop.rationale} maxLength={1000} onChange={(e) => setProp({ ...prop, rationale: e.target.value })} /></label>
                <div className="fd-actions"><button className="pv-btn" disabled={busy !== "" || !prop.target.trim() || prop.rationale.trim().length < 10} onClick={() => void act("propose", { action: "propose", ...prop }, "Proposal sent for review. Nothing was executed.", () => setProp({ actionType: "isolate_endpoint", target: "", rationale: "" }))}>Propose for review</button></div>
              </div>
            )}

            <h4>Timeline</h4>
            {c.events.slice().reverse().map((e) => <div className="pv-row" key={e.id}><span>{when(e.at)}</span><strong>{e.type.replace(/_/g, " ")}</strong><span>{e.actor}{Object.keys(e.details).length ? ` · ${JSON.stringify(e.details).slice(0, 160)}` : ""}</span></div>)}
            <div className="fd-actions"><button className="pv-btn" onClick={() => { setDetail(null); setPlan(null); }}>Close detail</button></div>
          </div>
        )}
      </div>
    </section>
  );
}
