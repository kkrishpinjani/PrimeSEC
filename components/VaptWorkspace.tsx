import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { LogoMark } from "./Logo";
import { fullSignOut } from "../lib/signOutClient";
import type { VaptOverview, VaptScope } from "../lib/vapt";
import type { AuditEvent } from "../lib/audit";

type Overview = {
  scanner: VaptOverview;
  scopes: VaptScope[];
  audit: AuditEvent[];
  scopesError?: string | null;
  canApprove: boolean;
  canScan: boolean;
};

const when = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : "—");
/** yyyy-mm-dd for today + N days in the viewer's LOCAL time (the same calendar the date picker and the 23:59:59 expiry use). */
const localDay = (daysAhead: number) => {
  const d = new Date(Date.now() + daysAhead * 86_400_000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
};
// The server allows at most 90 days from now. End-of-day on today+89 is always inside that, in every timezone.
const MIN_DAYS = 1;
const MAX_DAYS = 89;
const active = (s: VaptScope) => s.status === "Approved" && Date.parse(s.expiresAt) > Date.now();

function describe(e: AuditEvent): { label: string; detail: string; tone: "ok" | "warn" | "bad" } {
  switch (e.action) {
    case "vapt_scope_approved": return { label: "Scope approved", detail: `${e.scope.name} · ${e.scope.targets.join(", ")}`, tone: "ok" };
    case "vapt_scope_revoked": return { label: "Scope revoked", detail: e.scope.name, tone: "warn" };
    case "vapt_assessment_requested": return { label: "Scan requested", detail: e.target, tone: "ok" };
    case "vapt_assessment_started": return { label: "Scan started", detail: e.target, tone: "ok" };
    case "vapt_assessment_failed": return { label: "Scan failed", detail: `${e.target}: ${e.reason ?? "error"}`, tone: "bad" };
    case "vapt_assessment_denied": return { label: "Scan refused", detail: `${e.target}: ${e.reason ?? "not in scope"}`, tone: "bad" };
    case "vapt_findings_synchronized": return { label: "Findings synced", detail: `${e.imported} new, ${e.updated} updated${e.missing ? `, ${e.missing} not in latest scan` : ""}${e.truncated ? " (truncated)" : ""}`, tone: e.truncated ? "warn" : "ok" };
    case "vapt_finding_updated": return { label: "Finding updated", detail: `${e.finding.name} on ${e.finding.host}: ${e.changes.join(", ") || "no change"}${e.status.from !== e.status.to ? ` (${e.status.from} → ${e.status.to})` : ""}`, tone: "ok" };
    case "vapt_finding_retest_requested": return { label: "Retest requested", detail: `${e.finding.name} on ${e.target}`, tone: "ok" };
    default: return { label: "Event", detail: "", tone: "ok" };
  }
}

export default function VaptWorkspace({ user, roles }: { user: { name?: string | null; email?: string | null }; roles: string[] }) {
  const [data, setData] = useState<Overview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [scope, setScope] = useState({ name: "", authorizationReference: "", targets: "", expiresAt: localDay(30), acknowledgePublic: false });
  const [scan, setScan] = useState({ name: "Authorized infrastructure assessment", target: "" });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/vapt/overview", { cache: "no-store" });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "Could not load the VAPT overview.");
      setData(b as Overview);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function call(url: string, method: string, body: unknown, done: (b: any) => string) {
    setBusy(true); setError(""); setNotice("");
    try {
      const r = await fetch(url, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "Request failed.");
      setNotice(done(b));
      await load();
    } catch (e) {
      setError((e as Error).message);
      await load(); // a refused scan still lands in the audit list
    } finally {
      setBusy(false);
    }
  }

  const createScope = (e: React.FormEvent) => {
    e.preventDefault();
    void call(
      "/api/vapt/scopes", "POST",
      { ...scope, targets: scope.targets.split(/[\n,;]+/).map((x) => x.trim()).filter(Boolean), expiresAt: new Date(`${scope.expiresAt}T23:59:59`).toISOString() },
      (b) => { setScope({ ...scope, name: "", authorizationReference: "", targets: "", acknowledgePublic: false }); return `Scope "${b.scope.name}" approved until ${when(b.scope.expiresAt)}.`; }
    );
  };
  const startScan = (e: React.FormEvent) => {
    e.preventDefault();
    void call("/api/vapt/assessments", "POST", scan, (b) => `Greenbone accepted task ${b.assessment.taskId} for ${b.assessment.target} (scope: ${b.scope.name}).`);
  };
  const revoke = (s: VaptScope) => {
    if (!window.confirm(`Revoke scope "${s.name}"? New scans in it will be refused immediately.`)) return;
    void call("/api/vapt/scopes", "DELETE", { id: s.id }, () => `Scope "${s.name}" revoked.`);
  };

  const scanner = data?.scanner;
  const canScan = data?.canScan ?? roles.some((r) => ["SOC_Admin", "SOC_Analyst"].includes(r));
  const canApprove = data?.canApprove ?? roles.includes("SOC_Admin");
  const activeScopes = (data?.scopes ?? []).filter(active);
  const displayName = user.name || user.email || "Analyst";

  return (
    <section className="preview soc-dash vapt-page" aria-label="Vulnerability assessment workspace">
      <div className="pv-top">
        <span className="pv-logo"><LogoMark size={18} /></span>
        <Link href="/dashboard" className="pv-chip">← Dashboard</Link>
        <span className="pv-chip">Vulnerability assessment (VAPT)</span>
        <Link href="/vapt/findings" className="pv-chip pv-chip-link">Findings &amp; remediation →</Link>
        <div className="pv-actions">
          <button className="pv-btn" onClick={() => void load()} disabled={loading}>{loading ? "Checking…" : "↻ Refresh"}</button>
          <button className="pv-btn" onClick={() => void fullSignOut()}>Sign out</button>
          <span className="pv-user" title={roles.join(", ")}>
            <span className="pv-avatar">{displayName.slice(0, 1).toUpperCase()}</span>
            <span className="pv-user-text"><b>{displayName}</b><small>{roles[0] ?? "No role"}</small></span>
          </span>
        </div>
      </div>

      <div className="vapt-body">
        <p className="vapt-warning"><b>Only scan systems you are explicitly authorized to assess.</b> A scan can start only inside a scope a SOC_Admin approved with a written authorization reference and an expiry. Every approval, revocation, launch and refusal is audited.</p>
        {data?.scopesError && <div className="pv-list pv-error" role="alert">{data.scopesError}</div>}
        {error && <div className="pv-list pv-error" role="alert">{error}</div>}
        {notice && <div className="pv-list vapt-ok" role="status">{notice}</div>}

        <div className="vapt-grid">
          <div className="pv-list">
            <small>Scanner</small>
            <div className="pv-invest-summary">
              <div><span>Status</span><strong>{loading && !scanner ? "…" : scanner?.status.connected ? "Online" : "Offline"}</strong><em>{scanner?.version ? `GMP ${scanner.version}` : "Greenbone bridge"}</em></div>
              <div><span>Active scopes</span><strong>{activeScopes.length}</strong><em>approved and unexpired</em></div>
              <div><span>Tasks</span><strong>{scanner?.tasks.length ?? 0}</strong><em>in Greenbone</em></div>
            </div>
            {scanner && !scanner.status.connected && <p className="pv-empty">{scanner.status.message}</p>}
          </div>

          <form className="pv-list vapt-form" onSubmit={startScan}>
            <small>Launch assessment</small>
            <label>Assessment name<input required maxLength={80} value={scan.name} onChange={(e) => setScan({ ...scan, name: e.target.value })} /></label>
            <label>Target (IPv4 address or CIDR, /24 or narrower)<input required value={scan.target} placeholder="10.20.5.0/24" onChange={(e) => setScan({ ...scan, target: e.target.value })} /></label>
            <button className="pv-btn pv-btn-primary" disabled={busy || !canScan || !scanner?.status.connected} title={!canScan ? "SOC_Analyst or SOC_Admin role required" : !scanner?.status.connected ? "Greenbone is not connected" : "Start an authorized scan"}>
              {busy ? "Working…" : "Start authorized scan"}
            </button>
            {!canScan && <p className="pv-empty">Your role is read-only. SOC_Analyst or SOC_Admin is required to start scans.</p>}
          </form>
        </div>

        <div className="pv-list">
          <small>Authorized scopes</small>
          {(data?.scopes ?? []).length === 0 ? <p className="pv-empty">No scopes yet. A SOC_Admin must register written authorization before anything can be scanned.</p> : data!.scopes.slice().reverse().map((s) => (
            <div className="pv-row pv-scope" key={s.id}>
              <strong>{s.name}</strong>
              <code>{s.targets.join(", ")}</code>
              <span title="Authorization reference">{s.authorizationReference}</span>
              <span>until {when(s.expiresAt)}</span>
              <span className={`pv-sev ${active(s) ? "sev-medium" : "sev-high"}`}>{s.status === "Revoked" ? "Revoked" : active(s) ? (s.includesPublicRanges ? "Active · public" : "Active") : "Expired"}</span>
              {canApprove && active(s) ? <button type="button" className="pv-btn" onClick={() => revoke(s)} disabled={busy}>Revoke</button> : <span />}
            </div>
          ))}
        </div>

        {canApprove && (
          <form className="pv-list vapt-form vapt-scope-form" onSubmit={createScope}>
            <small>Register authorized scope (SOC_Admin only)</small>
            <label>Scope name<input required maxLength={100} value={scope.name} onChange={(e) => setScope({ ...scope, name: e.target.value })} /></label>
            <label>Authorization reference (contract, ticket or approval id)<input required minLength={8} maxLength={120} value={scope.authorizationReference} onChange={(e) => setScope({ ...scope, authorizationReference: e.target.value })} /></label>
            <label>Approved targets (one per line, /24 or narrower)<textarea required rows={3} value={scope.targets} placeholder={"10.20.5.0/24\n10.20.9.14"} onChange={(e) => setScope({ ...scope, targets: e.target.value })} /></label>
            <label>Authorization expires (max 90 days)<input type="date" required min={localDay(MIN_DAYS)} max={localDay(MAX_DAYS)} value={scope.expiresAt} onChange={(e) => setScope({ ...scope, expiresAt: e.target.value })} /></label>
            <label className="vapt-check"><input type="checkbox" checked={scope.acknowledgePublic} onChange={(e) => setScope({ ...scope, acknowledgePublic: e.target.checked })} /> These include publicly routable (internet) addresses, and I hold written authorization from their owner.</label>
            <button className="pv-btn pv-btn-primary" disabled={busy}>{busy ? "Working…" : "Approve scope"}</button>
          </form>
        )}

        <div className="vapt-grid">
          <div className="pv-list">
            <small>Greenbone tasks</small>
            {(scanner?.tasks ?? []).length === 0 ? <p className="pv-empty">No tasks reported by Greenbone.</p> : scanner!.tasks.slice(0, 10).map((t) => (
              <div className="pv-row pv-task" key={t.id}>
                <strong>{t.name}</strong><span>{t.target || "—"}</span><span className="pv-sev sev-medium">{t.status}</span><b>{t.progress}%</b>
              </div>
            ))}
          </div>
          <div className="pv-list">
            <small>VAPT audit trail</small>
            {(data?.audit ?? []).length === 0 ? <p className="pv-empty">No VAPT events recorded yet.</p> : data!.audit.slice(0, 8).map((e) => {
              const d = describe(e);
              return (
                <div className="pv-row pv-vaudit" key={e.eventId}>
                  <span className={`pv-sev ${d.tone === "bad" ? "sev-high" : d.tone === "warn" ? "sev-medium" : "sev-low"}`}>{d.label}</span>
                  <span className="pv-vdetail">{d.detail}</span>
                  <span>{e.actor.email || e.actor.name}</span>
                  <span>{when(e.timestamp)}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
