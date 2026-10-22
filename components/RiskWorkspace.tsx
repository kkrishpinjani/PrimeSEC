import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { LogoMark } from "./Logo";
import { fullSignOut } from "../lib/signOutClient";
import type { RiskFinding } from "../lib/risk";
import type { Comparison, Outcome } from "../lib/reports";

type HostRow = { host: string; criticality: string; exposure: string; updatedAt: string | null; updatedBy: string | null; findings: number };
type Payload = {
  findings: RiskFinding[];
  summary: { total: number; byBand: Record<string, number>; unclassifiedHosts: number };
  hosts: HostRow[];
  methodology: { model: string; weights: Record<string, number>; note: string };
  options: { criticalities: string[]; exposures: string[]; exploitEvidence: string[] };
  canEdit: boolean;
};
type ReportRow = { reportId: string; capturedAt: string; reportTime: string | null; status: string; complete: boolean; completenessSource: string; taskName: string; findingCount: number; hostsScanned: number | null };

const BANDS = ["Critical", "High", "Medium", "Low", "Unrated"] as const;
const PAGE = 40;
const when = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : "—");
const bandClass = (b: string) => (b === "Critical" || b === "High" ? "sev-high" : b === "Medium" ? "sev-medium" : "sev-low");
const outcomeClass = (o: Outcome) => (o === "FIXED" ? "sev-low" : o === "STILL_PRESENT" ? "sev-high" : "sev-medium");
const outcomeLabel: Record<Outcome, string> = { FIXED: "Fixed", STILL_PRESENT: "Still present", INCONCLUSIVE: "Inconclusive" };

export default function RiskWorkspace({ user, roles }: { user: { name?: string | null; email?: string | null }; roles: string[] }) {
  const [data, setData] = useState<Payload | null>(null);
  const [reports, setReports] = useState<ReportRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [search, setSearch] = useState("");
  const [band, setBand] = useState("All");
  const [showClosed, setShowClosed] = useState(false);
  const [shown, setShown] = useState(PAGE);
  const [open, setOpen] = useState<string | null>(null);
  const [hostDraft, setHostDraft] = useState<Record<string, { criticality?: string; exposure?: string }>>({});
  const [baseline, setBaseline] = useState("");
  const [retest, setRetest] = useState("");
  const [comparison, setComparison] = useState<Comparison | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [q, r] = await Promise.all([fetch(`/api/risk/queue${showClosed ? "?all=1" : ""}`, { cache: "no-store" }), fetch("/api/vapt/reports", { cache: "no-store" })]);
      const [qb, rb] = [await q.json(), await r.json()];
      if (!q.ok) throw new Error(qb.error || "Could not load the risk queue.");
      setData(qb as Payload);
      setHostDraft({});
      if (r.ok) setReports(rb.reports as ReportRow[]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [showClosed]);
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
      await load();
    } finally {
      setBusy("");
    }
  }

  const saveHost = (h: HostRow) => {
    const d = hostDraft[h.host] ?? {};
    void send(`host:${h.host}`, "/api/vapt/assets", {
      method: "PATCH",
      body: JSON.stringify({ host: h.host, criticality: d.criticality ?? h.criticality, exposure: d.exposure ?? h.exposure, expectedUpdatedAt: h.updatedAt })
    }, () => `Saved context for ${h.host}. Every finding on it was re-scored.`);
  };
  const saveExploit = (f: RiskFinding, exploitEvidence: string) =>
    void send(f.id, `/api/vapt/findings/${encodeURIComponent(f.id)}`, { method: "PATCH", body: JSON.stringify({ exploitEvidence, expectedUpdatedAt: f.updatedAt }) }, () => `Recorded exploit evidence for "${f.name}".`);

  async function compare() {
    setBusy("compare"); setError(""); setComparison(null);
    try {
      const r = await fetch(`/api/vapt/reports/compare?baseline=${encodeURIComponent(baseline)}&retest=${encodeURIComponent(retest)}`, { cache: "no-store" });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "Could not compare these reports.");
      setComparison(b as Comparison);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }

  const rows = useMemo(() => {
    const terms = search.toLowerCase().split(/\s+/).filter(Boolean);
    return (data?.findings ?? []).filter((f) => {
      if (band !== "All" && f.risk.band !== band) return false;
      if (terms.length === 0) return true;
      const hay = `${f.host} ${f.port} ${f.name} ${f.cves.join(" ")} ${f.owner} ${f.remediationStatus}`.toLowerCase();
      return terms.every((t) => hay.includes(t));
    });
  }, [data, search, band]);
  useEffect(() => setShown(PAGE), [search, band, showClosed]);

  const canEdit = data?.canEdit ?? roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r));
  const sum = data?.summary;
  const displayName = user.name || user.email || "Analyst";
  const label = (r: ReportRow) => `${r.taskName || "scan"} · ${when(r.reportTime ?? r.capturedAt)} · ${r.complete ? "complete" : r.status} · ${r.findingCount} findings`;

  return (
    <section className="preview soc-dash vapt-page" aria-label="Risk and validation">
      <div className="pv-top">
        <span className="pv-logo"><LogoMark size={18} /></span>
        <Link href="/dashboard" className="pv-chip">← Dashboard</Link>
        <Link href="/vapt" className="pv-chip pv-chip-link">VAPT</Link>
        <Link href="/vapt/findings" className="pv-chip pv-chip-link">Findings</Link>
        <span className="pv-chip">Risk &amp; validation</span>
        <div className="pv-actions">
          <button className="pv-btn" onClick={() => void load()} disabled={loading}>{loading ? "Loading…" : "↻ Refresh"}</button>
          <span className="pv-user" title={roles.join(", ")}>
            <span className="pv-avatar">{displayName.slice(0, 1).toUpperCase()}</span>
            <span className="pv-user-text"><b>{displayName}</b><small>{roles[0] ?? "No role"}</small></span>
          </span>
          <button className="pv-btn" onClick={() => void fullSignOut()}>Sign out</button>
        </div>
      </div>

      <div className="vapt-body">
        <p className="vapt-warning">The risk score is a <b>triage aid, not a probability of exploitation</b> and not a replacement for CVSS. Missing information is shown as <b>unknown</b> (never as zero) and widens the score&apos;s range. Report comparison never closes or changes a finding: a person verifies the evidence and decides.</p>
        {error && <div className="pv-list pv-error" role="alert">{error}</div>}
        {notice && <div className="pv-list vapt-ok" role="status">{notice}</div>}

        <div className="pv-invest-summary fd-tiles">
          <div><span>Critical priority</span><strong>{sum?.byBand.Critical ?? 0}</strong><em>score 80 to 100</em></div>
          <div><span>High</span><strong>{sum?.byBand.High ?? 0}</strong><em>score 60 to 79</em></div>
          <div><span>Ranked findings</span><strong>{sum?.total ?? 0}</strong><em>{showClosed ? "including closed" : "open work only"}</em></div>
          <div><span>Hosts without context</span><strong>{sum?.unclassifiedHosts ?? 0}</strong><em>criticality or exposure unknown</em></div>
        </div>

        {/* ---------------------------------------------------------------- hosts */}
        <div className="pv-list">
          <small>Host context · drives 35% of the score (criticality 20%, exposure 15%) for every finding on the host</small>
          {(data?.hosts ?? []).length === 0 ? <p className="pv-empty">No hosts yet. Sync Greenbone findings on the Findings page first.</p> : (data?.hosts ?? []).map((h) => {
            const d = hostDraft[h.host] ?? {};
            const crit = d.criticality ?? h.criticality, exp = d.exposure ?? h.exposure;
            const dirty = crit !== h.criticality || exp !== h.exposure;
            return (
              <div className="rk-host" key={h.host}>
                <code>{h.host}</code>
                <span className="rk-muted">{h.findings} finding{h.findings === 1 ? "" : "s"}</span>
                <label>Criticality
                  <select className="fd-input" value={crit} disabled={!canEdit} onChange={(e) => setHostDraft({ ...hostDraft, [h.host]: { ...d, criticality: e.target.value } })}>
                    {(data?.options.criticalities ?? []).map((o) => <option key={o}>{o}</option>)}
                  </select>
                </label>
                <label>Exposure
                  <select className="fd-input" value={exp} disabled={!canEdit} onChange={(e) => setHostDraft({ ...hostDraft, [h.host]: { ...d, exposure: e.target.value } })}>
                    {(data?.options.exposures ?? []).map((o) => <option key={o}>{o}</option>)}
                  </select>
                </label>
                <button className="pv-btn pv-btn-primary" disabled={!canEdit || !dirty || busy !== ""} onClick={() => saveHost(h)}>{busy === `host:${h.host}` ? "Saving…" : "Save"}</button>
                <span className="rk-muted">{h.updatedAt ? `set ${when(h.updatedAt)} by ${h.updatedBy}` : "not set"}</span>
              </div>
            );
          })}
        </div>

        {/* ---------------------------------------------------------------- queue */}
        <div className="pv-list fd-filters">
          <input className="fd-input" placeholder="Search host, name, CVE, owner, status…" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search the risk queue" />
          <select className="fd-input" value={band} onChange={(e) => setBand(e.target.value)} aria-label="Filter by risk band">
            <option>All</option>{BANDS.map((b) => <option key={b}>{b}</option>)}
          </select>
          <label className="fd-check"><input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} /> Include Resolved and Closed</label>
        </div>

        <div className="pv-list">
          <small>Prioritised remediation queue · {rows.length} finding{rows.length === 1 ? "" : "s"} · {data?.methodology.model}</small>
          {loading && !data ? <p className="pv-empty">Loading…</p> : rows.length === 0 ? (
            <p className="pv-empty">{(data?.findings.length ?? 0) === 0 ? "Nothing to prioritise yet. Import findings from the Findings page." : "No findings match these filters."}</p>
          ) : rows.slice(0, shown).map((f) => {
            const r = f.risk;
            const expanded = open === f.id;
            return (
              <div className="fd-card" key={f.id}>
                <div className="fd-head">
                  <span className={`pv-sev ${bandClass(r.band)} rk-score`} title={r.model}>{r.score === null ? "—" : r.score} {r.band}</span>
                  <strong className="fd-name">{f.name}</strong>
                  <code>{f.host}{f.port ? ` · ${f.port}` : ""}</code>
                  {f.notInLatestSync && <span className="fd-flag" title="Absent from this host's latest scan: it may be fixed. Verify before resolving.">May be fixed</span>}
                </div>
                <div className="rk-meta">
                  <span>{r.provisional ? <>Provisional: could be <b>{r.scoreMin}</b> to <b>{r.scoreMax}</b></> : "All factors known"}</span>
                  <span>Confidence {r.confidence}%</span>
                  <span>Severity {f.severityScore.toFixed(1)}</span>
                  <span>{f.remediationStatus}{f.owner ? ` · ${f.owner}` : ""}</span>
                  {f.cves.length > 0 && <span>{f.cves.slice(0, 3).join(", ")}{f.cves.length > 3 ? " …" : ""}</span>}
                  <button className="pv-btn" onClick={() => setOpen(expanded ? null : f.id)}>{expanded ? "Hide why" : "Why this score?"}</button>
                </div>
                {expanded && (
                  <div className="fd-detail">
                    <table className="rk-table">
                      <thead><tr><th>Factor</th><th>Value</th><th>Weight</th><th>Adds</th><th>Where it comes from</th></tr></thead>
                      <tbody>
                        {r.factors.map((x) => (
                          <tr key={x.id} className={x.known ? "" : "rk-unknown"}>
                            <td>{x.label}</td>
                            <td>{x.known ? x.value : "Unknown"}</td>
                            <td>{Math.round(x.weight * 100)}%</td>
                            <td>{x.contribution === null ? "excluded" : x.contribution}</td>
                            <td>{x.source}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {r.note && <p className="pv-empty">{r.note}</p>}
                    <p className="pv-empty">Unknown factors are excluded and the known ones renormalised, so the score reflects only what is known ({r.confidence}% of the weight). The range shows how far it could move once the unknowns are filled in.</p>
                    <label className="rk-exploit">Exploit evidence (an input to the score; record what you have verified, for example from CISA KEV or the vendor advisory)
                      <select className="fd-input" value={f.exploitEvidence} disabled={!canEdit || busy !== ""} onChange={(e) => saveExploit(f, e.target.value)}>
                        {(data?.options.exploitEvidence ?? []).map((o) => <option key={o}>{o}</option>)}
                      </select>
                    </label>
                  </div>
                )}
              </div>
            );
          })}
          {rows.length > shown && <button className="pv-btn" onClick={() => setShown(shown + PAGE)}>Show {Math.min(PAGE, rows.length - shown)} more ({rows.length - shown} hidden)</button>}
        </div>

        {/* ---------------------------------------------------------------- compare */}
        <div className="pv-list">
          <small>Retest report comparison · &quot;fixed&quot; needs proof, and nothing is closed automatically</small>
          {reports.length < 2 ? (
            <p className="pv-empty">You need at least two imported reports: a baseline scan and a later retest. Run a scan, request a retest from the Findings page, then sync after each scan finishes.</p>
          ) : (
            <div className="rk-compare">
              <label>Baseline (earlier)
                <select className="fd-input" value={baseline} onChange={(e) => { setBaseline(e.target.value); setComparison(null); }}>
                  <option value="">Choose a report…</option>{reports.map((r) => <option key={r.reportId} value={r.reportId}>{label(r)}</option>)}
                </select>
              </label>
              <label>Retest (later)
                <select className="fd-input" value={retest} onChange={(e) => { setRetest(e.target.value); setComparison(null); }}>
                  <option value="">Choose a report…</option>{reports.map((r) => <option key={r.reportId} value={r.reportId}>{label(r)}</option>)}
                </select>
              </label>
              <button className="pv-btn pv-btn-primary" disabled={!baseline || !retest || baseline === retest || busy !== ""} onClick={() => void compare()}>{busy === "compare" ? "Comparing…" : "Compare reports"}</button>
            </div>
          )}

          {comparison && (
            <div className="rk-result">
              <div className="pv-invest-summary fd-tiles">
                <div><span>Fixed</span><strong>{comparison.summary.fixed}</strong><em>proven absent</em></div>
                <div><span>Still present</span><strong>{comparison.summary.stillPresent}</strong><em>in both reports</em></div>
                <div><span>Inconclusive</span><strong>{comparison.summary.inconclusive}</strong><em>absence is not proof</em></div>
                <div><span>New in retest</span><strong>{comparison.summary.new}</strong><em>not in the baseline</em></div>
              </div>
              {comparison.warnings.map((w) => <p key={w} className="vapt-warning">{w}</p>)}
              <p className="pv-empty">Baseline {comparison.baselineComplete ? "complete" : "not confirmed complete"} · retest {comparison.retestComplete ? "complete" : "not confirmed complete"}. Nothing was changed: review the evidence, then resolve findings on the Findings page.</p>
              {comparison.results.map((x) => (
                <div className="rk-row" key={x.finding.id}>
                  <span className={`pv-sev ${outcomeClass(x.outcome)}`}>{outcomeLabel[x.outcome]}</span>
                  <strong>{x.finding.name}</strong>
                  <code>{x.finding.host} · {x.finding.port}</code>
                  <span className="rk-muted">{x.explanation}</span>
                </div>
              ))}
              {comparison.newInRetest.length > 0 && <small>New in the retest report</small>}
              {comparison.newInRetest.map((f) => (
                <div className="rk-row" key={f.id}>
                  <span className="pv-sev sev-high">New</span><strong>{f.name}</strong><code>{f.host} · {f.port}</code><span className="rk-muted">Severity {f.severityScore.toFixed(1)}: appears only in the retest report.</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="pv-list">
          <small>How the score works</small>
          <p className="pv-empty">{data?.methodology.note}</p>
          <p className="pv-empty">Weights: {data ? Object.entries(data.methodology.weights).map(([k, v]) => `${k} ${Math.round(v * 100)}%`).join(" · ") : ""}. Severity 0.0 (informational) findings are capped at Low. Exploit evidence is what an analyst has recorded; corroborating detection has no automated source yet, so it stays unknown.</p>
        </div>
      </div>
    </section>
  );
}
