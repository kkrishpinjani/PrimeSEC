import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { LogoMark } from "./Logo";
import { fullSignOut } from "../lib/signOutClient";
import type { Finding, FindingStatus } from "../lib/findings";

type Summary = { total: number; bySeverity: Record<string, number>; byStatus: Record<string, number>; notInLatestSync: number };
type Payload = { findings: Finding[]; summary: Summary; statuses: FindingStatus[]; canEdit: boolean; isAdmin: boolean };
type Draft = { status: FindingStatus; owner: string; notes: string };

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"] as const;
const PAGE = 50;
const when = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : "—");
const sevClass = (s: string) => (s === "Critical" || s === "High" ? "sev-high" : s === "Medium" ? "sev-medium" : "sev-low");
const draftOf = (f: Finding): Draft => ({ status: f.remediationStatus, owner: f.owner, notes: f.remediationNotes });

export default function FindingsWorkspace({ user, roles }: { user: { name?: string | null; email?: string | null }; roles: string[] }) {
  const [data, setData] = useState<Payload | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("All");
  const [severity, setSeverity] = useState("All");
  const [staleOnly, setStaleOnly] = useState(false);
  const [shown, setShown] = useState(PAGE);
  const [open, setOpen] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Record<string, Draft>>({});

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/vapt/findings", { cache: "no-store" });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "Could not load findings.");
      setData(b as Payload);
      setDrafts({}); // always start from what the server holds
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function call(id: string, url: string, init: RequestInit, done: (b: any) => string) {
    setBusy(id); setError(""); setNotice("");
    try {
      const r = await fetch(url, { ...init, headers: { "Content-Type": "application/json" } });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "Request failed.");
      setNotice(done(b));
      await load();
    } catch (e) {
      setError((e as Error).message);
      await load(); // a conflict or a refusal: show what the server really holds now
    } finally {
      setBusy("");
    }
  }

  const sync = () => call("sync", "/api/vapt/findings/sync", { method: "POST" }, (b) =>
    `Synced Greenbone findings: ${b.imported} new, ${b.updated} updated${b.missing ? `, ${b.missing} no longer in the latest scan of their host` : ""}.${b.truncated ? " The import was truncated, so nothing was flagged as missing." : ""}`);
  const save = (f: Finding) => {
    const d = drafts[f.id] ?? draftOf(f);
    void call(f.id, `/api/vapt/findings/${encodeURIComponent(f.id)}`, {
      method: "PATCH",
      body: JSON.stringify({ remediationStatus: d.status, owner: d.owner, remediationNotes: d.notes, expectedUpdatedAt: f.updatedAt })
    }, () => `Saved "${f.name}" on ${f.host}.`);
  };
  const retest = (f: Finding) => {
    if (!window.confirm(`Request a new Greenbone scan of ${f.host}?\n\nIt must be inside a current approved scope. The whole host is scanned; nothing is fixed or changed on it.`)) return;
    void call(f.id, `/api/vapt/findings/${encodeURIComponent(f.id)}/retest`, { method: "POST" }, (b) =>
      `Retest started for ${f.host} (task ${b.assessment.taskId}). Sync again once the scan has finished to see whether this finding is gone.${b.warning ? " " + b.warning : ""}`);
  };

  const canEdit = data?.canEdit ?? roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r));
  const rows = useMemo(() => {
    // Every word must match somewhere (any order), so "apache 10.0.0.5" works.
    const terms = search.toLowerCase().split(/\s+/).filter(Boolean);
    return (data?.findings ?? []).filter((f) => {
      if (status !== "All" && f.remediationStatus !== status) return false;
      if (severity !== "All" && f.severity !== severity) return false;
      if (staleOnly && !f.notInLatestSync) return false;
      if (terms.length === 0) return true;
      const hay = `${f.host} ${f.port} ${f.name} ${f.cves.join(" ")} ${f.owner} ${f.oid} ${f.severity} ${f.remediationStatus}`.toLowerCase();
      return terms.every((t) => hay.includes(t));
    });
  }, [data, search, status, severity, staleOnly]);
  useEffect(() => setShown(PAGE), [search, status, severity, staleOnly]);

  const sum = data?.summary;
  const openCount = (data?.findings ?? []).filter((f) => !["Resolved", "Closed"].includes(f.remediationStatus)).length;
  const displayName = user.name || user.email || "Analyst";

  return (
    <section className="preview soc-dash vapt-page" aria-label="Findings and remediation">
      <div className="pv-top">
        <span className="pv-logo"><LogoMark size={18} /></span>
        <Link href="/vapt" className="pv-chip">← VAPT workspace</Link>
        <Link href="/risk" className="pv-chip pv-chip-link">Risk &amp; validation →</Link>
        <span className="pv-chip">Findings &amp; remediation</span>
        <div className="pv-actions">
          {canEdit && <button className="pv-btn pv-btn-primary" onClick={() => void sync()} disabled={busy !== ""}>{busy === "sync" ? "Syncing…" : "Sync Greenbone findings"}</button>}
          <button className="pv-btn" onClick={() => void load()} disabled={loading}>{loading ? "Loading…" : "↻ Refresh"}</button>
          <span className="pv-user" title={roles.join(", ")}>
            <span className="pv-avatar">{displayName.slice(0, 1).toUpperCase()}</span>
            <span className="pv-user-text"><b>{displayName}</b><small>{roles[0] ?? "No role"}</small></span>
          </span>
          <button className="pv-btn" onClick={() => void fullSignOut()}>Sign out</button>
        </div>
      </div>

      <div className="vapt-body">
        <p className="vapt-warning">Scanner output is <b>evidence for analyst triage, not proof that an asset is compromised</b>. A retest launches a new authorized scan (same scope, audit and rate-limit rules as any scan); nothing is fixed or changed on the host. A finding can be closed only after a retest was requested, or by a SOC_Admin who writes a justification in the notes.</p>
        {error && <div className="pv-list pv-error" role="alert">{error}</div>}
        {notice && <div className="pv-list vapt-ok" role="status">{notice}</div>}

        <div className="pv-invest-summary fd-tiles">
          <div><span>Findings</span><strong>{sum?.total ?? 0}</strong><em>imported from Greenbone</em></div>
          <div><span>Critical</span><strong>{sum?.bySeverity.Critical ?? 0}</strong><em>{sum?.bySeverity.High ?? 0} high</em></div>
          <div><span>Still open</span><strong>{openCount}</strong><em>not Resolved or Closed</em></div>
          <div><span>Not in latest scan</span><strong>{sum?.notInLatestSync ?? 0}</strong><em>verify, then resolve</em></div>
        </div>

        <div className="pv-list fd-filters">
          <input className="fd-input" placeholder="Search host, port, name, CVE, owner…" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search findings" />
          <select className="fd-input" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status">
            <option>All</option>{(data?.statuses ?? []).map((s) => <option key={s}>{s}</option>)}
          </select>
          <select className="fd-input" value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Filter by severity">
            <option>All</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
          <label className="fd-check"><input type="checkbox" checked={staleOnly} onChange={(e) => setStaleOnly(e.target.checked)} /> Not in latest scan only</label>
        </div>

        <div className="pv-list">
          <small>{rows.length} finding{rows.length === 1 ? "" : "s"}{rows.length !== (data?.findings.length ?? 0) ? ` (filtered from ${data?.findings.length})` : ""}</small>
          {loading && !data ? <p className="pv-empty">Loading…</p> : rows.length === 0 ? (
            <p className="pv-empty">{(data?.findings.length ?? 0) === 0 ? "No findings yet. Complete an authorized scan in the VAPT workspace, wait for Greenbone to finish it, then use Sync Greenbone findings." : "No findings match these filters."}</p>
          ) : rows.slice(0, shown).map((f) => {
            const d = drafts[f.id] ?? draftOf(f);
            const dirty = d.status !== f.remediationStatus || d.owner !== f.owner || d.notes !== f.remediationNotes;
            const expanded = open === f.id;
            const set = (patch: Partial<Draft>) => setDrafts({ ...drafts, [f.id]: { ...d, ...patch } });
            return (
              <div className="fd-card" key={f.id}>
                <div className="fd-head">
                  <span className={`pv-sev ${sevClass(f.severity)}`} title={`CVSS ${f.severityScore}`}>{f.severity} {f.severityScore.toFixed(1)}</span>
                  <strong className="fd-name">{f.name}</strong>
                  <code>{f.host}{f.port ? ` · ${f.port}` : ""}</code>
                  {f.notInLatestSync && <span className="fd-flag" title="Seen in an older scan of this host but absent from its latest one. It may be fixed: verify, then resolve.">Not in latest scan</span>}
                </div>
                {f.cves.length > 0 && <div className="fd-cves">{f.cves.map((c) => <code key={c}>{c}</code>)}</div>}
                <div className="fd-edit">
                  <label>Status
                    <select className="fd-input" value={d.status} disabled={!canEdit} onChange={(e) => set({ status: e.target.value as FindingStatus })}>
                      {(data?.statuses ?? []).map((s) => <option key={s}>{s}</option>)}
                    </select>
                  </label>
                  <label>Owner<input className="fd-input" value={d.owner} maxLength={120} disabled={!canEdit} onChange={(e) => set({ owner: e.target.value })} placeholder="Who is fixing this" /></label>
                  <div className="fd-actions">
                    <button className="pv-btn pv-btn-primary" disabled={!canEdit || !dirty || busy !== ""} onClick={() => save(f)}>{busy === f.id ? "Saving…" : "Save"}</button>
                    <button className="pv-btn" disabled={!canEdit || busy !== ""} onClick={() => retest(f)} title={canEdit ? "Request a new authorized scan of this host" : "SOC_Analyst or SOC_Admin role required"}>Request retest</button>
                    <button className="pv-btn" onClick={() => setOpen(expanded ? null : f.id)}>{expanded ? "Hide details" : "Details"}</button>
                  </div>
                </div>
                {expanded && (
                  <div className="fd-detail">
                    <label>Remediation notes<textarea className="fd-input" rows={3} maxLength={2000} value={d.notes} disabled={!canEdit} onChange={(e) => set({ notes: e.target.value })} placeholder="What was done, ticket numbers, justification if closing without a retest…" /></label>
                    <div className="fd-grid">
                      <div><span>Scanner description</span><pre>{f.description || "—"}</pre></div>
                      <div><span>Suggested solution</span><pre>{f.solution || "—"}</pre></div>
                    </div>
                    <p className="fd-meta">
                      NVT <code>{f.oid || "—"}</code> · task {f.taskName || "—"} · report <code>{f.reportId || "—"}</code> · first seen {when(f.firstSeen)} · last imported {when(f.lastSeen)}
                      {f.retestRequestedAt && <> · retest requested {when(f.retestRequestedAt)} (task <code>{f.retestTaskId ?? "—"}</code>)</>}
                      {f.updatedAt && <> · edited {when(f.updatedAt)} by {f.updatedBy}</>}
                    </p>
                  </div>
                )}
              </div>
            );
          })}
          {rows.length > shown && <button className="pv-btn" onClick={() => setShown(shown + PAGE)}>Show {Math.min(PAGE, rows.length - shown)} more ({rows.length - shown} hidden)</button>}
        </div>
      </div>
    </section>
  );
}
