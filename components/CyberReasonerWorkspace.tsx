import Link from "next/link";
import { useEffect, useState } from "react";
import { LogoMark } from "./Logo";
import { fullSignOut } from "../lib/signOutClient";
import type { Finding } from "../lib/findings";
import type { Analysis, DefensivePlan } from "../lib/cyberreasoner";

const when = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : "—");
const sevClass = (s: string) => (s === "Critical" || s === "High" ? "sev-high" : s === "Medium" ? "sev-medium" : "sev-low");

export default function CyberReasonerWorkspace({ user, roles }: { user: { name?: string | null; email?: string | null }; roles: string[] }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<"" | "analyze" | "plan">("");
  const [error, setError] = useState("");
  const [hint, setHint] = useState("");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [plan, setPlan] = useState<DefensivePlan | null>(null);
  const canUse = roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r));
  const displayName = user.name || user.email || "Analyst";

  useEffect(() => {
    (async () => {
      try {
        const r = await fetch("/api/vapt/findings", { cache: "no-store" });
        const b = await r.json();
        if (!r.ok) throw new Error(b.error || "Could not load findings.");
        const open = (b.findings as Finding[]).filter((f) => !["Resolved", "Closed"].includes(f.remediationStatus));
        setFindings(open);
        if (open.length) setSelected(open[0].id);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  async function run(kind: "analyze" | "plan") {
    if (!selected) return;
    setBusy(kind); setError(""); setHint("");
    if (kind === "analyze") setAnalysis(null); else setPlan(null);
    try {
      const r = await fetch(`/api/cyberreasoner/${kind}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ findingId: selected }) });
      const b = await r.json();
      if (!r.ok) { setHint(b.hint || ""); throw new Error(b.error || "Request failed."); }
      if (kind === "analyze") setAnalysis(b.analysis); else setPlan(b.plan);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }

  const current = findings.find((f) => f.id === selected);
  const lists: [string, string[]][] = analysis ? [
    ["Remediation steps", analysis.remediationSteps], ["Safe validation checklist", analysis.safeValidationChecklist],
    ["Evidence gaps", analysis.evidenceGaps], ["False-positive checks", analysis.falsePositiveChecks]
  ] : [];

  return (
    <section className="preview soc-dash vapt-page" aria-label="CyberReasoner">
      <div className="pv-top">
        <span className="pv-logo"><LogoMark size={18} /></span>
        <Link href="/dashboard" className="pv-chip">← Dashboard</Link>
        <Link href="/vapt/findings" className="pv-chip pv-chip-link">Findings</Link>
        <Link href="/risk" className="pv-chip pv-chip-link">Risk &amp; validation</Link>
        <span className="pv-chip">CyberReasoner</span>
        <div className="pv-actions">
          <span className="pv-user" title={roles.join(", ")}>
            <span className="pv-avatar">{displayName.slice(0, 1).toUpperCase()}</span>
            <span className="pv-user-text"><b>{displayName}</b><small>{roles[0] ?? "No role"}</small></span>
          </span>
          <button className="pv-btn" onClick={() => void fullSignOut()}>Sign out</button>
        </div>
      </div>

      <div className="vapt-body">
        <p className="vapt-warning">Defensive analysis only. A model running <b>on this machine</b> reads one imported finding and suggests remediation and safe checks. It is <b>advisory and unverified</b>: it can be wrong, and it never scans, tests, exploits or changes anything. Scanner text is sent to the model as untrusted data.</p>
        {!canUse && <div className="pv-list pv-error" role="alert">CyberReasoner needs the SOC_Analyst or SOC_Admin role.</div>}
        {error && <div className="pv-list pv-error" role="alert">{error}{hint && <><br /><small>{hint}</small></>}</div>}

        <div className="pv-list">
          <small>{loading ? "Loading findings…" : `${findings.length} open finding${findings.length === 1 ? "" : "s"} available`}</small>
          {!loading && findings.length === 0 ? (
            <p className="pv-empty">No open findings. Sync Greenbone findings (or load sample data) on the Findings page first.</p>
          ) : (
            <>
              <select className="fd-input" aria-label="Finding" value={selected} disabled={loading || !canUse} onChange={(e) => { setSelected(e.target.value); setAnalysis(null); setPlan(null); setError(""); }}>
                {findings.map((f) => <option key={f.id} value={f.id}>{f.severity} · {f.name} · {f.host}{f.port ? ` · ${f.port}` : ""}</option>)}
              </select>
              {current && <p className="fd-meta"><span className={`pv-sev ${sevClass(current.severity)}`}>{current.severity} {current.severityScore.toFixed(1)}</span> {current.cves.join(", ") || "No CVE"} · status {current.remediationStatus}</p>}
              <div className="fd-actions">
                <button className="pv-btn pv-btn-primary" disabled={!canUse || !selected || busy !== ""} onClick={() => void run("analyze")}>{busy === "analyze" ? "Analyzing locally… (can take a minute)" : "Analyze with local model"}</button>
                <button className="pv-btn" disabled={!canUse || !selected || busy !== ""} onClick={() => void run("plan")}>{busy === "plan" ? "Preparing…" : "Draft workflow plan"}</button>
              </div>
            </>
          )}
        </div>

        {analysis && (
          <div className="pv-list fd-card" aria-label="Defensive analysis">
            <div className="fd-head"><strong className="fd-name">Defensive analysis</strong><code>{analysis.model}</code><span className="fd-flag">Advisory · unverified</span></div>
            <p className="fd-meta">Confidence (the model&apos;s own claim): {analysis.confidence} · {when(analysis.analyzedAt)}{analysis.removedItems > 0 && ` · ${analysis.removedItems} item(s) withheld by the content screen`}</p>
            <h4>Summary</h4><p>{analysis.summary || "—"}</p>
            <h4>Likely impact</h4><p>{analysis.likelyImpact || "—"}</p>
            <h4>Priority rationale</h4><p>{analysis.priorityRationale || "—"}</p>
            {lists.map(([title, items]) => (
              <div key={title}><h4>{title}</h4>{items.length ? <ul>{items.map((x, i) => <li key={i}>{x}</li>)}</ul> : <p className="pv-empty">None returned.</p>}</div>
            ))}
            <p className="fd-meta">{analysis.disclaimer}</p>
          </div>
        )}

        {plan && (
          <div className="pv-list fd-card" aria-label="Workflow plan">
            <div className="fd-head"><strong className="fd-name">Defensive workflow proposal</strong><code>{plan.planId}</code><span className="fd-flag">Not executed</span></div>
            <p className="fd-meta">A fixed template for this finding. It is not stored, not sent to JEV and nothing runs from it. Map it to JEV&apos;s documented API before any integration.</p>
            <ul>{plan.tasks.map((t) => <li key={t.type}><b>{t.title}</b> · {t.status}{t.requiresApproval ? " · human approval required" : ""}</li>)}</ul>
            <h4>Prohibited</h4>
            <p className="fd-meta">{plan.policy.prohibitedActions.map((a) => a.replace(/_/g, " ")).join(", ")}</p>
            <button className="pv-btn" onClick={() => void navigator.clipboard?.writeText(JSON.stringify(plan, null, 2))}>Copy plan JSON</button>
          </div>
        )}
      </div>
    </section>
  );
}
