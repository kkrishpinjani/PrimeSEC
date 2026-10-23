import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { LogoMark } from "./Logo";
import { fullSignOut } from "../lib/signOutClient";

type Service = { name: string; state: "connected" | "degraded" | "unavailable" | "not_configured"; latencyMs: number | null; message: string };
type Health = { checkedAt: string; service: string; telemetryEnabled: boolean; services: Service[] };

const LABEL: Record<Service["state"], string> = { connected: "Connected", degraded: "Degraded", unavailable: "Unavailable", not_configured: "Not configured" };
const TONE: Record<Service["state"], string> = { connected: "sev-low", degraded: "sev-medium", unavailable: "sev-high", not_configured: "sev-medium" };

export default function ObserveWorkspace({ user, roles, jaegerUrl, prometheusUrl }: { user: { name?: string | null; email?: string | null }; roles: string[]; jaegerUrl: string; prometheusUrl: string }) {
  const [health, setHealth] = useState<Health | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const displayName = user.name || user.email || "Analyst";

  const refresh = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const r = await fetch("/api/observe/health", { cache: "no-store" });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "Could not check the telemetry services.");
      setHealth(b as Health);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);

  const services = health?.services ?? [];
  const up = services.filter((s) => s.state === "connected").length;

  return (
    <section className="preview soc-dash vapt-page" aria-label="Observe">
      <div className="pv-top">
        <span className="pv-logo"><LogoMark size={18} /></span>
        <Link href="/dashboard" className="pv-chip">← Dashboard</Link>
        <span className="pv-chip">Observe</span>
        <div className="pv-actions">
          <button className="pv-btn pv-btn-primary" onClick={() => void refresh()} disabled={loading}>{loading ? "Checking…" : "↻ Refresh health"}</button>
          <span className="pv-user" title={roles.join(", ")}>
            <span className="pv-avatar">{displayName.slice(0, 1).toUpperCase()}</span>
            <span className="pv-user-text"><b>{displayName}</b><small>{roles[0] ?? "No role"}</small></span>
          </span>
          <button className="pv-btn" onClick={() => void fullSignOut()}>Sign out</button>
        </div>
      </div>

      <div className="vapt-body">
        <p className="vapt-warning">These checks only show that each telemetry service <b>answers</b>. They do not prove that traces or metrics are arriving: confirm that in Jaeger and Prometheus. Telemetry is for diagnosing PrimeSEC itself, not a security detection source.</p>
        {error && <div className="pv-list pv-error" role="alert">{error}</div>}
        {health && !health.telemetryEnabled && <div className="pv-list" role="status">Application telemetry is <b>off</b>. Set <code>OTEL_ENABLED=true</code> in <code>.env</code> and restart PrimeSEC to export traces and metrics.</div>}

        <div className="pv-invest-summary fd-tiles">
          <div><span>Services up</span><strong>{loading && !health ? "…" : `${up} / ${services.length || 3}`}</strong><em>Collector, Jaeger, Prometheus</em></div>
          <div><span>App telemetry</span><strong>{health ? (health.telemetryEnabled ? "On" : "Off") : "…"}</strong><em>opt-in via OTEL_ENABLED</em></div>
          <div><span>Service name</span><strong>{health?.service ?? "…"}</strong><em>as shown in Jaeger</em></div>
        </div>

        <div className="pv-list">
          <small>Telemetry pipeline</small>
          {services.length === 0 ? <p className="pv-empty">{loading ? "Checking…" : "No result yet."}</p> : services.map((s) => (
            <div className="pv-row" key={s.name}>
              <span className={`pv-sev ${TONE[s.state]}`}>{LABEL[s.state]}</span>
              <strong>{s.name}</strong>
              <span>{s.message}</span>
              <code>{s.latencyMs === null ? "—" : `${s.latencyMs} ms`}</code>
            </div>
          ))}
        </div>

        <div className="pv-list">
          <small>Where to look</small>
          <p className="fd-meta">Traces: open Jaeger, pick service <b>primesec-web</b>, search recent traces. Integration spans are named like <code>integration.wazuh.request</code>. Metrics: in Prometheus query <code>primesec_integration_calls_total</code>, <code>primesec_integration_errors_total</code> or <code>primesec_integration_duration_milliseconds_count</code> (exact names depend on the exporter).</p>
          <div className="fd-actions">
            <a className="pv-btn pv-btn-primary" href={jaegerUrl} target="_blank" rel="noreferrer">Open Jaeger ↗</a>
            <a className="pv-btn" href={prometheusUrl} target="_blank" rel="noreferrer">Open Prometheus ↗</a>
          </div>
        </div>
      </div>
    </section>
  );
}
