import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { LogoMark } from "./Logo";
import { fullSignOut } from "../lib/signOutClient";

type Tab = "overview" | "agents" | "alerts" | "rules" | "groups" | "mitre";
type Row = Record<string, any>;
type Result = { items?: Row[]; total?: number; data?: any; note?: string; source?: string };
const AGENT_PANELS = [["agent-os", "Operating system"], ["sca", "Configuration assessment (SCA)"], ["syscheck", "File integrity (syscheck)"], ["rootcheck", "Rootcheck"], ["vulnerabilities", "Vulnerabilities"]] as const;
const short = (v: unknown) => (v === null || v === undefined ? "—" : typeof v === "object" ? JSON.stringify(v).slice(0, 110) : String(v).slice(0, 110));

async function get(resource: string, params: Record<string, string | number> = {}): Promise<Result> {
  const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== "" && v !== undefined).map(([k, v]) => [k, String(v)]));
  const r = await fetch(`/api/wazuh/${resource}${qs.toString() ? `?${qs}` : ""}`, { cache: "no-store" });
  const b = await r.json();
  if (!r.ok) throw new Error(b.error || "The request failed.");
  return b;
}

export default function WazuhExplorer({ user, roles }: { user: { name?: string | null; email?: string | null }; roles: string[] }) {
  const [tab, setTab] = useState<Tab>("overview");
  const [overview, setOverview] = useState<Result | null>(null);
  const [agent, setAgent] = useState("");
  const [panels, setPanels] = useState<Record<string, Result | string>>({});
  const [alerts, setAlerts] = useState<Result | null>(null);
  const [af, setAf] = useState({ severityMin: "3", search: "", agent: "" });
  const [rules, setRules] = useState<Result | null>(null);
  const [rq, setRq] = useState("");
  const [groups, setGroups] = useState<{ groups: Result; members: Result | null; selected: string } | null>(null);
  const [mitre, setMitre] = useState<{ kind: "techniques" | "groups"; res: Result } | null>(null);
  const [mq, setMq] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const displayName = user.name || user.email || "Analyst";

  const run = useCallback(async (label: string, fn: () => Promise<void>) => {
    setBusy(label); setError("");
    try { await fn(); } catch (e) { setError((e as Error).message); } finally { setBusy(""); }
  }, []);
  useEffect(() => { void run("overview", async () => setOverview(await get("overview"))); }, [run]);

  const openAgent = (id: string) => run("agent", async () => {
    setAgent(id); setPanels({});
    const out: Record<string, Result | string> = {};
    await Promise.all(AGENT_PANELS.map(async ([res]) => { try { out[res] = await get(res, { agent: id, limit: 8 }); } catch (e) { out[res] = (e as Error).message; } }));
    setPanels(out);
  });
  const loadAlerts = () => run("alerts", async () => setAlerts(await get("alerts", { limit: 25, severityMin: af.severityMin, search: af.search, agent: af.agent })));
  const loadRules = () => run("rules", async () => setRules(await get("rules", { limit: 20, search: rq })));
  const loadGroups = (selected = "") => run("groups", async () => setGroups({ groups: await get("groups"), members: selected ? await get("group-agents", { group: selected }) : null, selected }));
  const loadMitre = (kind: "techniques" | "groups") => run("mitre", async () => setMitre({ kind, res: await get(kind === "techniques" ? "mitre-techniques" : "mitre-groups", { limit: 20, search: mq }) }));

  const table = (items: Row[] | undefined, cols: [string, (r: Row) => unknown][]) => !items || items.length === 0
    ? <p className="pv-empty">Nothing returned.</p>
    : <div style={{ overflowX: "auto" }}><table className="pv-table" style={{ width: "100%", fontSize: "0.78rem" }}><thead><tr>{cols.map(([h]) => <th key={h} style={{ textAlign: "left" }}>{h}</th>)}</tr></thead><tbody>{items.map((r, i) => <tr key={i}>{cols.map(([h, f]) => <td key={h}>{short(f(r))}</td>)}</tr>)}</tbody></table></div>;

  const agentCols: [string, (r: Row) => unknown][] = [["Id", (r) => r.id], ["Name", (r) => r.name], ["Status", (r) => r.status], ["IP", (r) => r.ip], ["OS", (r) => r.os?.name ?? r.os], ["Version", (r) => r.version]];

  return (
    <section className="preview soc-dash vapt-page" aria-label="Wazuh explorer">
      <div className="pv-top">
        <span className="pv-logo"><LogoMark size={18} /></span>
        <Link href="/dashboard" className="pv-chip">← Dashboard</Link>
        <span className="pv-chip">Wazuh explorer</span>
        <div className="pv-actions">
          <span className="pv-user" title={roles.join(", ")}><span className="pv-avatar">{displayName.slice(0, 1).toUpperCase()}</span><span className="pv-user-text"><b>{displayName}</b><small>{roles[0] ?? "No role"}</small></span></span>
          <button className="pv-btn" onClick={() => void fullSignOut()}>Sign out</button>
        </div>
      </div>
      <div className="pv-tabs" role="tablist">
        {([["overview", "Overview"], ["agents", "Agents"], ["alerts", "Alerts"], ["rules", "Rules & decoders"], ["groups", "Groups"], ["mitre", "MITRE ATT&CK"]] as [Tab, string][]).map(([id, label]) => (
          <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? "on" : ""} onClick={() => { setTab(id); if (id === "alerts" && !alerts) void loadAlerts(); if (id === "rules" && !rules) void loadRules(); if (id === "groups" && !groups) void loadGroups(); if (id === "mitre" && !mitre) void loadMitre("techniques"); }}>{label}</button>
        ))}
      </div>
      <div className="vapt-body">
        <p className="vapt-warning">Read-only view of your Wazuh. Every request is a fixed, validated query; nothing here changes Wazuh, restarts a service or triggers active response. {busy && <b>Loading…</b>}</p>
        {error && <div className="pv-list pv-error" role="alert">{error}</div>}

        {tab === "overview" && overview && (
          <div className="pv-list">
            <div className="pv-invest-summary fd-tiles">
              <div><span>Manager</span><strong>{overview.data?.manager?.version ?? "—"}</strong><em>{overview.data?.manager?.name ?? ""}</em></div>
              <div><span>Agents</span><strong>{overview.data?.agentCount ?? 0}</strong><em>{overview.data?.scopeRestricted ? "restricted by WAZUH_AGENT_ALLOWLIST" : "all agents"}</em></div>
              <div><span>Active</span><strong>{overview.data?.agentSummary?.connection?.active ?? 0}</strong><em>{overview.data?.agentSummary?.connection?.disconnected ?? 0} disconnected</em></div>
            </div>
            {overview.note && <p className="fd-meta">{overview.note}</p>}
            {table(overview.items, [["Id", (r) => r.id], ["Name", (r) => r.name], ["Status", (r) => r.status], ["IP", (r) => r.ip], ["OS", (r) => r.os], ["Groups", (r) => (r.groups || []).join(", ")]])}
          </div>
        )}

        {tab === "agents" && (
          <div className="pv-list">
            <small>Choose an agent to see its OS, configuration assessment, file-integrity events, rootcheck and vulnerabilities.</small>
            <div className="fd-actions">{(overview?.items ?? []).map((a) => <button key={a.id} className={`pv-btn ${agent === a.id ? "pv-btn-primary" : ""}`} disabled={busy !== ""} onClick={() => void openAgent(a.id)}>{a.id} · {a.name}</button>)}</div>
            {agent && AGENT_PANELS.map(([res, title]) => {
              const p = panels[res];
              return (
                <div className="fd-card" key={res}>
                  <div className="fd-head"><strong className="fd-name">{title}</strong>{typeof p === "object" && p?.total !== undefined && <code>{p.total} total</code>}</div>
                  {p === undefined ? <p className="pv-empty">Loading…</p> : typeof p === "string" ? <p className="fd-meta">{p}</p> :
                    res === "agent-os" ? table(p.items, [["OS", (r) => r.os?.name], ["Version", (r) => r.os?.version], ["Arch", (r) => r.architecture], ["Hostname", (r) => r.hostname]]) :
                    res === "sca" ? table(p.items, [["Policy", (r) => r.name], ["Score", (r) => r.score], ["Pass", (r) => r.pass], ["Fail", (r) => r.fail], ["Checks", (r) => r.total_checks]]) :
                    res === "syscheck" ? table(p.items, [["File", (r) => r.file], ["Type", (r) => r.type], ["Size", (r) => r.size], ["Modified", (r) => r.date]]) :
                    res === "vulnerabilities" ? table(p.items, [["CVE", (r) => r.cve], ["Severity", (r) => r.severity], ["Score", (r) => r.score], ["Package", (r) => r.package], ["Status", (r) => r.status]]) :
                    table(p.items, [["Event", (r) => r.event ?? r.log ?? r], ["Status", (r) => r.status], ["Date", (r) => r.date_last ?? r.date_first]])}
                </div>
              );
            })}
          </div>
        )}

        {tab === "alerts" && (
          <div className="pv-list">
            <div className="fd-actions">
              <select className="fd-input" value={af.severityMin} onChange={(e) => setAf({ ...af, severityMin: e.target.value })} aria-label="Minimum rule level">{[0, 3, 7, 10, 12, 15].map((n) => <option key={n} value={n}>level ≥ {n}</option>)}</select>
              <select className="fd-input" value={af.agent} onChange={(e) => setAf({ ...af, agent: e.target.value })} aria-label="Agent"><option value="">All agents</option>{(overview?.items ?? []).map((a) => <option key={a.id} value={a.id}>{a.id} · {a.name}</option>)}</select>
              <input className="fd-input" value={af.search} maxLength={200} placeholder="Search text" onChange={(e) => setAf({ ...af, search: e.target.value })} onKeyDown={(e) => { if (e.key === "Enter") void loadAlerts(); }} />
              <button className="pv-btn pv-btn-primary" disabled={busy !== ""} onClick={() => void loadAlerts()}>Search</button>
            </div>
            {alerts && <small>{alerts.total} alert{alerts.total === 1 ? "" : "s"} match; showing the newest {alerts.items?.length}.</small>}
            {alerts && table(alerts.items, [["Time", (r) => r.timestamp], ["Lvl", (r) => r.level], ["Agent", (r) => r.agent?.name], ["Rule", (r) => `${r.ruleId} ${r.description}`], ["MITRE", (r) => (r.mitre || []).join(", ")], ["Source IP", (r) => r.sourceIp]])}
          </div>
        )}

        {tab === "rules" && (
          <div className="pv-list">
            <div className="fd-actions"><input className="fd-input" value={rq} maxLength={200} placeholder="Search rules (for example ssh)" onChange={(e) => setRq(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void loadRules(); }} /><button className="pv-btn pv-btn-primary" disabled={busy !== ""} onClick={() => void loadRules()}>Search</button></div>
            {rules && <small>{rules.total} rule{rules.total === 1 ? "" : "s"} match; showing {rules.items?.length}.</small>}
            {rules && table(rules.items, [["Id", (r) => r.id], ["Level", (r) => r.level], ["Description", (r) => r.description], ["Groups", (r) => (r.groups || []).join(", ")], ["File", (r) => r.filename]])}
          </div>
        )}

        {tab === "groups" && groups && (
          <div className="pv-list">
            <div className="fd-actions">{(groups.groups.items ?? []).map((g) => <button key={g.name} className={`pv-btn ${groups.selected === g.name ? "pv-btn-primary" : ""}`} onClick={() => void loadGroups(g.name)}>{g.name} ({g.count ?? "?"})</button>)}</div>
            {groups.members && table(groups.members.items, agentCols)}
          </div>
        )}

        {tab === "mitre" && (
          <div className="pv-list">
            <div className="fd-actions">
              <button className={`pv-btn ${mitre?.kind === "techniques" ? "pv-btn-primary" : ""}`} onClick={() => void loadMitre("techniques")}>Techniques</button>
              <button className={`pv-btn ${mitre?.kind === "groups" ? "pv-btn-primary" : ""}`} onClick={() => void loadMitre("groups")}>Groups</button>
              <input className="fd-input" value={mq} maxLength={200} placeholder="Search (for example T1110 or APT)" onChange={(e) => setMq(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void loadMitre(mitre?.kind ?? "techniques"); }} />
            </div>
            {mitre && <small>{mitre.res.total} {mitre.kind}; showing {mitre.res.items?.length}. This is Wazuh&apos;s ATT&amp;CK reference data, not a statement about your systems.</small>}
            {mitre && table(mitre.res.items, [["Id", (r) => r.external_id ?? r.id], ["Name", (r) => r.name], ["Description", (r) => r.description]])}
          </div>
        )}
      </div>
    </section>
  );
}
