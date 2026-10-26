import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { LogoMark } from "./Logo";
import { fullSignOut } from "../lib/signOutClient";
import type { RagItem, SapAssessment, SapInput } from "../lib/sap";

type Tab = "assess" | "history" | "knowledge";
type Summary = { id: string; createdAt: string; createdBy: string; assetId: string; summary: string; findingCount: number; findingIds: string[] };
type Form = { assetId: string; saprouttab: string; gatewayProfile: string; reginfo: string; secinfo: string };

const when = (iso: string) => new Date(iso).toLocaleString();
const sevClass = (s: string) => (s === "High" ? "sev-high" : s === "Medium" ? "sev-medium" : "sev-low");
const EMPTY: Form = { assetId: "", saprouttab: "", gatewayProfile: "", reginfo: "", secinfo: "" };

export default function SapWorkspace({ user, roles }: { user: { name?: string | null; email?: string | null }; roles: string[] }) {
  const [tab, setTab] = useState<Tab>("assess");
  const [form, setForm] = useState<Form>(EMPTY);
  const [explain, setExplain] = useState(false);
  const [result, setResult] = useState<(SapAssessment & { auditRecorded?: boolean }) | null>(null);
  const [history, setHistory] = useState<Summary[]>([]);
  const [demo, setDemo] = useState<SapInput | null>(null);
  const [limits, setLimits] = useState<{ asset: number; saprouttab: number; gateway_profile: number; reginfo: number; secinfo: number } | null>(null);
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<RagItem[] | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const canAssess = roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r));
  const displayName = user.name || user.email || "Analyst";

  const loadHistory = useCallback(async () => {
    try {
      const r = await fetch("/api/sap/assessments", { cache: "no-store" });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "Could not load the history.");
      setHistory(b.items);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);
  useEffect(() => {
    void loadHistory();
    (async () => {
      try {
        const r = await fetch("/api/sap/assessments?demo=1", { cache: "no-store" });
        const b = await r.json();
        if (r.ok) { setDemo(b.demo); setLimits(b.limits); }
      } catch { /* demo button simply stays disabled */ }
    })();
  }, [loadHistory]);

  async function run() {
    setBusy("assess"); setError(""); setNotice("");
    try {
      const r = await fetch("/api/sap/assess", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...form, includeExplanation: explain }) });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "The assessment failed.");
      setResult(b);
      setNotice(`${b.findings.length} finding${b.findings.length === 1 ? "" : "s"} for ${b.assetId}.`);
      await loadHistory();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }
  async function open(id: string) {
    setBusy(id); setError("");
    try {
      const r = await fetch(`/api/sap/assessments?id=${encodeURIComponent(id)}`, { cache: "no-store" });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "Could not open that assessment.");
      setResult(b); setTab("assess");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }
  async function search() {
    if (!q.trim()) return;
    setBusy("search"); setError("");
    try {
      const r = await fetch(`/api/sap/assessments?q=${encodeURIComponent(q)}&top_k=6`, { cache: "no-store" });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "Search failed.");
      setHits(b.results);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }
  function download() {
    if (!result) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url; a.download = `${result.id}.json`; a.click();
    URL.revokeObjectURL(url);
  }

  const high = result?.findings.filter((f) => f.severity === "High").length ?? 0;
  const field = (key: keyof Omit<Form, "assetId">, label: string, help: string, max?: number) => (
    <label>{label}<textarea className="fd-input" rows={5} spellCheck={false} value={form[key]} maxLength={max} disabled={!canAssess} placeholder={help} onChange={(e) => setForm({ ...form, [key]: e.target.value })} /></label>
  );

  return (
    <section className="preview soc-dash vapt-page" aria-label="SAP configuration risk">
      <div className="pv-top">
        <span className="pv-logo"><LogoMark size={18} /></span>
        <Link href="/dashboard" className="pv-chip">← Dashboard</Link>
        <span className="pv-chip">SAP configuration risk</span>
        <div className="pv-actions">
          <span className="pv-user" title={roles.join(", ")}>
            <span className="pv-avatar">{displayName.slice(0, 1).toUpperCase()}</span>
            <span className="pv-user-text"><b>{displayName}</b><small>{roles[0] ?? "No role"}</small></span>
          </span>
          <button className="pv-btn" onClick={() => void fullSignOut()}>Sign out</button>
        </div>
      </div>

      <div className="pv-tabs" role="tablist">
        {([["assess", "Assess"], ["history", `History (${history.length})`], ["knowledge", "Knowledge search"]] as [Tab, string][]).map(([id, label]) => (
          <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? "on" : ""} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>

      <div className="vapt-body">
        <p className="vapt-warning">Paste the <b>configuration text</b> of an SAP router or gateway and PrimeSEC lists configuration risks. It works <b>offline</b>: it never connects to an SAP system, scans an address or tests a credential. A finding is a lead to verify against your exact SAP release, not proof that anything is exploitable, and an empty result does not mean the system is secure. Paste only configuration you are authorised to review.</p>
        {error && <div className="pv-list pv-error" role="alert">{error}</div>}
        {notice && <div className="pv-list vapt-ok" role="status">{notice}</div>}

        {tab === "assess" && (
          <>
            <div className="pv-list">
              <small>Configuration to assess {canAssess ? "" : "(SOC_Analyst or SOC_Admin only)"}</small>
              <div className="fd-edit sap-form">
                <label>Asset name or id<input className="fd-input" value={form.assetId} maxLength={limits?.asset ?? 128} disabled={!canAssess} placeholder="e.g. SAP-PRD-GW-01 (letters, digits . _ : -)" onChange={(e) => setForm({ ...form, assetId: e.target.value })} /></label>
                {field("saprouttab", "saprouttab (SAProuter route table)", 'P * * *\nKP "p:CN=router" * sapdp00', limits?.saprouttab)}
                {field("gatewayProfile", "Gateway profile parameters", "snc/enable = 0\nsnc/permit_insecure_start = 1\ngw/acl_mode = 0", limits?.gateway_profile)}
                {field("reginfo", "reginfo (registered programs)", "P TP=Z_APP HOST=10.1.2.3", limits?.reginfo)}
                {field("secinfo", "secinfo (external program starts)", "D TP=* HOST=*", limits?.secinfo)}
                <label className="fd-check"><input type="checkbox" checked={explain} disabled={!canAssess} onChange={(e) => setExplain(e.target.checked)} /> Add an explanation from the local AI model (advisory, can take a minute)</label>
                <div className="fd-actions">
                  <button className="pv-btn pv-btn-primary" disabled={!canAssess || busy !== "" || !(form.saprouttab || form.gatewayProfile || form.reginfo || form.secinfo)} onClick={() => void run()}>{busy === "assess" ? "Assessing…" : "Assess configuration"}</button>
                  <button className="pv-btn" disabled={!canAssess || !demo} onClick={() => demo && setForm({ assetId: demo.assetId, saprouttab: demo.saprouttab, gatewayProfile: demo.gatewayProfile, reginfo: demo.reginfo, secinfo: demo.secinfo })}>Load synthetic demo input</button>
                  <button className="pv-btn" disabled={busy !== ""} onClick={() => { setForm(EMPTY); setResult(null); setNotice(""); }}>Clear</button>
                </div>
              </div>
            </div>

            {result && (
              <div className="pv-list fd-card" aria-label="Assessment result">
                <div className="fd-head"><strong className="fd-name">{result.assetId}</strong><code>{result.id}</code><span className="fd-flag">Configuration evidence only</span></div>
                <p className="fd-meta">{result.summary} · {when(result.createdAt)} · by {result.createdBy}</p>
                <div className="pv-invest-summary fd-tiles">
                  <div><span>Findings</span><strong>{result.findings.length}</strong><em>{high} high</em></div>
                  <div><span>Route table</span><strong>{result.inputs.saprouttabLines}</strong><em>active lines read</em></div>
                  <div><span>Gateway profile</span><strong>{result.inputs.gatewayProfileLines}</strong><em>active lines read</em></div>
                  <div><span>reginfo / secinfo</span><strong>{result.inputs.reginfoLines} / {result.inputs.secinfoLines}</strong><em>active lines read</em></div>
                </div>
                <div className="fd-actions"><button className="pv-btn" onClick={download}>Download JSON report</button></div>

                {result.findings.map((f) => (
                  <div className="fd-card" key={f.id}>
                    <div className="fd-head">
                      <span className={`pv-sev ${sevClass(f.severity)}`}>{f.severity}</span>
                      <strong className="fd-name">{f.title}</strong><code>{f.id}</code>
                      <span className="fd-flag" title="How sure the rule is that this is a real configuration problem">Confidence: {f.confidence}</span>
                    </div>
                    <p className="fd-meta">{f.category} · {f.validation_status} (needs validation)</p>
                    <h4>Evidence</h4>
                    <div className="fd-cves">{f.evidence.map((e, i) => <code key={i}>{e}</code>)}</div>
                    <h4>Why it matters</h4><p>{f.rationale}</p>
                    <h4>Safe remediation</h4><ul>{f.remediation.map((x, i) => <li key={i}>{x}</li>)}</ul>
                    <p className="fd-meta">References: {f.references.map((u, i) => <span key={u}>{i ? " · " : ""}<a className="pv-link" href={u} target="_blank" rel="noreferrer noopener">SAP Help ↗</a></span>)}</p>
                  </div>
                ))}
                {result.findings.length === 0 && <p className="pv-empty">No detection rule matched. This is not proof that the SAP system is secure: only seven specific patterns are checked.</p>}

                {(result.llmExplanation || result.llmNote) && (
                  <div className="fd-card">
                    <div className="fd-head"><strong className="fd-name">AI explanation</strong><span className="fd-flag">Advisory · unverified</span></div>
                    {result.llmExplanation ? <pre style={{ whiteSpace: "pre-wrap" }}>{result.llmExplanation}</pre> : <p className="fd-meta">{result.llmNote}</p>}
                    <p className="fd-meta">Written by a local model from the findings above. It does not decide what is reported.</p>
                  </div>
                )}
                {result.ragContext.length > 0 && (
                  <details><summary className="fd-meta">Reference notes used ({result.ragContext.length})</summary>
                    {result.ragContext.map((c, i) => <div className="fd-meta" key={i}><b>{c.source}</b> · score {c.score}<pre style={{ whiteSpace: "pre-wrap" }}>{c.text}</pre></div>)}
                  </details>
                )}
                <details><summary className="fd-meta">Limitations</summary><ul>{result.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul></details>
              </div>
            )}
          </>
        )}

        {tab === "history" && (
          <div className="pv-list">
            <small>Saved assessments (newest first, last 100 kept). The pasted configuration itself is not saved, only the findings and the matching lines.</small>
            {history.length === 0 ? <p className="pv-empty">No assessments yet. Use the Assess tab, then &quot;Load synthetic demo input&quot; to try it.</p> : history.map((h) => (
              <div className="pv-row" key={h.id}>
                <span>{when(h.createdAt)}</span><strong>{h.assetId}</strong>
                <span>{h.findingCount} finding{h.findingCount === 1 ? "" : "s"}{h.findingIds.length ? ` · ${h.findingIds.join(", ")}` : ""}</span>
                <button className="pv-btn" disabled={busy !== ""} onClick={() => void open(h.id)}>Open</button>
              </div>
            ))}
          </div>
        )}

        {tab === "knowledge" && (
          <div className="pv-list">
            <small>Search the SAP notes bundled with PrimeSEC (word match, not AI)</small>
            <div className="fd-actions">
              <input className="fd-input" value={q} maxLength={200} placeholder="e.g. SNC route order, gateway ACL" onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void search(); }} />
              <button className="pv-btn pv-btn-primary" disabled={busy !== "" || !q.trim()} onClick={() => void search()}>Search</button>
            </div>
            {hits && (hits.length === 0 ? <p className="pv-empty">Nothing matched. Try other words.</p> : hits.map((h, i) => (
              <div className="fd-card" key={i}><div className="fd-head"><strong className="fd-name">{h.source}</strong><code>score {h.score}</code></div><pre style={{ whiteSpace: "pre-wrap" }}>{h.text}</pre></div>
            )))}
          </div>
        )}
      </div>
    </section>
  );
}
