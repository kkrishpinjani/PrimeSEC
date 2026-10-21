import dynamic from "next/dynamic";
import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { LogoMark } from "./Logo";
import type { DashboardData, SectionId } from "../lib/dashboardData";
import type { Correlation } from "../lib/correlation";
import type { InvestigationEvent } from "../lib/audit";

const Globe = dynamic(() => import("./Globe"), { ssr: false });

/** Smoothly counts toward a target value. */
function useCount(target: number, ms = 900) {
  const [v, setV] = useState(0);
  const from = useRef(0);
  useEffect(() => {
    const start = performance.now(), a = from.current;
    let raf = 0;
    const step = (t: number) => {
      const k = Math.min((t - start) / ms, 1);
      const cur = a + (target - a) * (1 - Math.pow(1 - k, 3));
      setV(cur); from.current = cur;
      if (k < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return Math.round(v);
}

const TABS = [
  { id: "overview", label: "Overview", title: "Security Operations Center", sub: "Threat intelligence and incident monitoring", icon: "M3 12 12 3l9 9M5 10v10h14V10" },
  { id: "intel", label: "Threat Intel", title: "Threat Intelligence", sub: "Indicators and actors correlated from OpenCTI", icon: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Zm0-5v3m0 12v3M3 12h3m12 0h3" },
  { id: "vapt", label: "Vulnerabilities", title: "Vulnerability Assessment", sub: "Authorized scans and prioritized findings", icon: "M12 3 4 7v5c0 5 3.5 8 8 9 4.5-1 8-4 8-9V7l-8-4Z" },
  { id: "invest", label: "Investigations", title: "Alert Investigations", sub: "Wazuh alerts enriched with threat intelligence", icon: "M4 6h16M4 12h16M4 18h10" }
] as const;
type TabId = (typeof TABS)[number]["id"];

const fmt = (n: number) => n.toLocaleString("en-US");

/** Scales raw counts to 0..100 of the series maximum (flat series render as a low baseline). */
const normalise = (values: number[]) => {
  const max = Math.max(...values, 0);
  return values.map((v) => (max === 0 ? 4 : Math.max(4, Math.round((v / max) * 100))));
};

function StatRow({ items }: { items: readonly (readonly [string, string])[] }) {
  return (
    <div className="pv-stats pv-stats-bottom">
      {items.map(([k, v]) => <div key={k}><small>{k}</small><b>{v}</b></div>)}
    </div>
  );
}

function IntelView({ data }: { data: DashboardData["intel"] }) {
  return (
    <div className="pv-split">
      <div className="pv-list">
        <small>Latest indicators</small>
        {data.indicators.map((r) => (
          <div className={`pv-row ${r.conf == null ? "pv-row-plain" : ""}`} key={r.type + r.value}>
            <span className="pv-type">{r.type}</span>
            <code>{r.value}</code>
            <em>{r.tag}</em>
            {r.conf != null && <><span className="pv-meter"><i style={{ width: `${r.conf}%` }} /></span><b>{r.conf}%</b></>}
          </div>
        ))}
      </div>
      <div className="pv-list">
        <small>Active threat actors (relative activity)</small>
        {data.actors.map(([n, v]) => (
          v == null
            ? <div className="pv-bar-row pv-bar-plain" key={n}><span>{n}</span></div>
            : <div className="pv-bar-row" key={n}><span>{n}</span><span className="pv-meter"><i style={{ width: `${v}%` }} /></span><b>{v}</b></div>
        ))}
      </div>
    </div>
  );
}

function VaptView({ items }: { items: DashboardData["vulns"]["items"] }) {
  return (
    <div className="pv-list">
      <small>Priority queue · <Link href="/vapt" className="pv-link">Run authorized Greenbone scans in the VAPT workspace →</Link> · <Link href="/vapt/findings" className="pv-link">Findings &amp; remediation →</Link></small>
      {items.map((v) => (
        <div className="pv-row pv-vrow" key={v.host + v.title}>
          <span className={`pv-sev sev-${v.sev.toLowerCase()}`}>{v.sev}</span>
          <strong>{v.title}</strong>
          <code>{v.host}</code>
          <span className="pv-meter"><i style={{ width: `${v.score}%` }} /></span>
          <b>{v.score}</b>
        </div>
      ))}
    </div>
  );
}

type InvestigationResult = {
  investigationId: string;
  createdAt: string;
  alert: { id: string; level: number; description: string; agent: string; sourceIp: string };
  openCti: { configured: boolean; connected: boolean; message: string };
  correlation: Correlation;
};

const when = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : "—");

function InvestView({
  alerts, canInvestigate, busyId, onInvestigate
}: {
  alerts: DashboardData["investigations"]["alerts"];
  canInvestigate: boolean;
  busyId: string;
  onInvestigate: (id: string) => void;
}) {
  return (
    <div className="pv-list">
      <small>Recent alerts</small>
      {alerts.map((a) => (
        <div className="pv-row pv-arow pv-arow-act" key={a.id}>
          <span className="pv-sev sev-high">L{a.level}</span>
          <strong>{a.rule}</strong>
          <code>{a.agent}</code>
          <em>{a.detail}</em>
          <button
            className="pv-btn"
            disabled={!a.investigable || !canInvestigate || Boolean(busyId)}
            onClick={() => onInvestigate(a.id)}
            title={!a.investigable ? "Sample alert: connect Wazuh to investigate real alerts" : !canInvestigate ? "SOC_Analyst or SOC_Admin role required" : "Run a read-only investigation"}
          >
            {busyId === a.id ? "Investigating…" : "Investigate"}
          </button>
        </div>
      ))}
    </div>
  );
}

function InvestigationPanel({ result, error }: { result: InvestigationResult | null; error: string }) {
  if (error) return <div className="pv-list pv-error" role="alert">{error}</div>;
  if (!result) {
    return (
      <div className="pv-list">
        <small>Alert investigation</small>
        <p className="pv-empty">Select <b>Investigate</b> on an alert. PrimeSEC re-reads the alert from Wazuh, searches OpenCTI for its IPs, domains and file hashes, and records an audit event. It performs no response or remediation action.</p>
      </div>
    );
  }
  const { correlation: c } = result;
  return (
    <div className="pv-list pv-invest">
      <small>Investigation {result.investigationId} · {when(result.createdAt)} · no automated action taken</small>
      <div className="pv-invest-summary">
        <div><span>Wazuh alert</span><strong>{result.alert.description}</strong><em>{result.alert.agent} · level {result.alert.level}</em></div>
        <div>
          <span>OpenCTI</span>
          <strong>{!result.openCti.configured ? "Not configured" : !result.openCti.connected ? "Unavailable" : c.observables.length === 0 ? "Nothing to search" : "Searched"}</strong>
          <em>{!result.openCti.connected ? "No reliable correlation possible" : c.observables.length === 0 ? "No IP, domain or hash in this alert" : `${c.observables.length} observable${c.observables.length === 1 ? "" : "s"} checked`}</em>
        </div>
        <div><span>Result</span><strong>{c.matchCount} potential match{c.matchCount === 1 ? "" : "es"}</strong><em>Analyst validation required</em></div>
      </div>
      {c.observables.length > 0 && (
        <p className="pv-obs">Checked: {c.observables.map((o) => <code key={o.type + o.value}>{o.value}</code>)}</p>
      )}
      {c.matches.length > 0 ? (
        c.matches.map((m) => (
          <div className="pv-row pv-mrow" key={m.indicatorId + m.matchedValue}>
            <strong>{m.indicatorName}</strong>
            <span className="pv-type">{m.patternType}</span>
            <code>{m.matchedValue}</code>
            <b>{m.score == null ? "—" : m.score}</b>
            <span className="pv-sev sev-medium">Analyst review</span>
          </div>
        ))
      ) : (
        <p className="pv-empty">{!result.openCti.connected
          ? "OpenCTI could not be searched, so nothing can be said about this alert's indicators."
          : c.observables.length === 0
            ? "This alert contains no IP address, domain or file hash, so there was nothing to look up in OpenCTI. That says nothing about whether the alert is benign."
            : "No potential matches. This is not proof the alert is benign: only observables present in the alert and OpenCTI's current data were compared."}</p>
      )}
    </div>
  );
}

function AuditPanel({ events }: { events: InvestigationEvent[] | null }) {
  return (
    <div className="pv-list">
      <small>Recent investigation audit</small>
      {events === null ? <p className="pv-empty">Loading…</p> : events.length === 0 ? <p className="pv-empty">No investigations recorded yet.</p> : events.slice(0, 6).map((e) => (
        <div className="pv-row pv-audit" key={e.eventId}>
          <strong>{e.alert.description}</strong>
          <span>{e.actor.email || e.actor.name || "user"}</span>
          <span>{when(e.timestamp)}</span>
          <b>{e.correlation.matchCount} match{e.correlation.matchCount === 1 ? "" : "es"}</b>
        </div>
      ))}
    </div>
  );
}

type Props = {
  data: DashboardData;
  user: { name?: string | null; email?: string | null };
  roles: string[];
  wazuhUrl: string;
  onSignOut: () => void;
};

const SECTION_LABEL: Record<SectionId, string> = { overview: "Overview", intel: "Threat Intel", vulns: "Vulnerabilities", investigations: "Investigations" };

function buildNote(data: DashboardData): string {
  const parts: string[] = [];
  for (const i of [data.integrations.wazuh, data.integrations.opencti]) {
    if (!i.configured) parts.push(`${i.name} is not configured.`);
    else if (!i.connected) parts.push(`${i.name} unavailable: ${i.message}`);
    else if (i.partial) parts.push(`${i.name}: ${i.message}`);
  }
  const sample = (Object.keys(data.sources) as SectionId[]).filter((k) => data.sources[k] === "sample").map((k) => SECTION_LABEL[k]);
  if (sample.length) parts.push(`Sample data shown for: ${sample.join(", ")}.`);
  if (data.demo) parts.unshift("Connected to the local demo integrations: every record is fake (marked \"(demo)\"). Point .env at real Wazuh/OpenCTI to see real data.");
  parts.push(...data.notes);
  return parts.join(" ");
}

export default function SocDashboard({ data, user, roles, wazuhUrl, onSignOut }: Props) {
  const [tab, setTab] = useState<TabId>("overview");
  const canInvestigate = roles.includes("SOC_Admin") || roles.includes("SOC_Analyst");
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [busyId, setBusyId] = useState("");
  const [invError, setInvError] = useState("");
  const [audit, setAudit] = useState<InvestigationEvent[] | null>(null);

  const loadAudit = useCallback(async () => {
    try {
      const r = await fetch("/api/investigations", { headers: { Accept: "application/json" }, cache: "no-store" });
      if (r.ok) setAudit(((await r.json()) as { events: InvestigationEvent[] }).events);
      else setAudit([]);
    } catch {
      setAudit([]);
    }
  }, []);
  useEffect(() => { if (tab === "invest") void loadAudit(); }, [tab, loadAudit]);

  const investigate = async (alertId: string) => {
    setBusyId(alertId); setResult(null); setInvError("");
    try {
      const r = await fetch("/api/investigations", {
        method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify({ alertId })
      });
      const body = await r.json();
      if (!r.ok) throw new Error((body as { error?: string }).error || "Investigation failed.");
      setResult(body as InvestigationResult);
      void loadAudit();
    } catch (e) {
      setInvError((e as Error).message || "Investigation failed.");
    } finally {
      setBusyId("");
    }
  };
  const radar = useCount(data.radar.score, 900);
  const trendPct = normalise(data.trend);
  const timelinePct = normalise(data.timeline);

  const arc = Math.max(0, Math.min(100, Math.round((data.radar.score / 1000) * 100)));
  const dash = 2 * Math.PI * 52 * 0.75;
  const current = TABS.find((t) => t.id === tab)!;
  const sources = Object.values(data.sources);
  const anyLive = sources.some((x) => x !== "sample");
  const allLive = sources.every((x) => x === "live");
  const badge = data.demo && anyLive ? "Demo data" : allLive ? "Live" : anyLive ? "Partly live" : "Sample data";
  const note = buildNote(data);
  const displayName = user.name || user.email || "Analyst";

  return (
    <section className="preview soc-dash" aria-label="Security operations dashboard">
      <div className="pv-top">
        <span className="pv-logo"><LogoMark size={18} /></span>
        {data.scope.team && <span className="pv-chip">Team: {data.scope.team}</span>}
        {data.scope.region && <span className="pv-chip">Region: {data.scope.region}</span>}
        <span className="pv-chip pv-hide">Range: {data.scope.range}</span>
        <div className="pv-actions">
          <span className={`pv-live ${allLive && !data.demo ? "" : "pv-sample"}`}><i /> {badge}</span>
          <Link href="/vapt" className="pv-btn">VAPT ↗</Link>
          {wazuhUrl
            ? <a className="pv-btn" href={wazuhUrl} target="_blank" rel="noreferrer">Open Wazuh ↗</a>
            : <span className="pv-btn pv-btn-off" title="Set WAZUH_DASHBOARD_URL in .env">Wazuh not configured</span>}
          <span className="pv-user" title={roles.join(", ") || "No role"}>
            <span className="pv-avatar">{displayName.slice(0, 1).toUpperCase()}</span>
            <span className="pv-user-text"><b>{displayName}</b><small>{roles[0] ?? "No role"}</small></span>
          </span>
          <button className="pv-btn" onClick={onSignOut}>Sign out</button>
        </div>
      </div>

      <div className="pv-tabs" role="tablist">
        {TABS.map((t) => (
          <button key={t.id} role="tab" aria-selected={tab === t.id} className={tab === t.id ? "on" : ""} onClick={() => setTab(t.id)}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d={t.icon} /></svg>
            {t.label}
            {tab === t.id && <motion.i layoutId="soc-tab-underline" className="pv-underline" />}
          </button>
        ))}
      </div>

      <div className="pv-body">
        <div className="pv-rail">
          {TABS.map((t) => (
            <button key={t.id} aria-label={t.label} title={t.label} className={tab === t.id ? "on" : ""} onClick={() => setTab(t.id)}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d={t.icon} /></svg>
            </button>
          ))}
        </div>

        <div className="pv-main">
          <div className="pv-head">
            <h3>{current.title}</h3>
            <p>{current.sub}</p>
          </div>
          <AnimatePresence mode="wait">
            <motion.div key={tab} className="pv-pane" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.28 }}>
              {tab === "overview" && (
                <>
                  <div className="pv-globe">
                    <div className="pv-globe-glow" />
                    <Globe className="pv-canvas" markers={data.map.markers} home={data.map.home} />
                    {data.map.markers.length > 0 && <span className="pv-map-legend"><i /> {data.map.markers.length} geolocated alert sources (24h)</span>}
                    <div className="pv-timeline">
                      <span>High-severity alerts per hour (24h)</span>
                      <div className="pv-bars">{timelinePct.map((h, i) => <i key={i} style={{ height: `${h}%` }} title={`${data.timeline[i]} high-severity alerts`} />)}</div>
                    </div>
                  </div>
                  <StatRow items={data.overview.stats} />
                </>
              )}
              {tab === "intel" && <><IntelView data={data.intel} /><StatRow items={data.intel.stats} /></>}
              {tab === "vapt" && <><VaptView items={data.vulns.items} /><StatRow items={data.vulns.stats} /></>}
              {tab === "invest" && (
                <>
                  <InvestView alerts={data.investigations.alerts} canInvestigate={canInvestigate} busyId={busyId} onInvestigate={investigate} />
                  <InvestigationPanel result={result} error={invError} />
                  <AuditPanel events={audit} />
                  <StatRow items={data.investigations.stats} />
                </>
              )}
            </motion.div>
          </AnimatePresence>
        </div>

        <aside className="pv-side">
          <div className="pv-card">
            <small title={data.radar.basis}>Global threat radar</small>
            <svg viewBox="0 0 120 100" className="pv-gauge">
              <defs><linearGradient id="gaugeG" x1="0" x2="1"><stop offset="0" stopColor="#14b8a6" /><stop offset="1" stopColor="#f43f5e" /></linearGradient></defs>
              <circle cx="60" cy="62" r="52" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="7" strokeLinecap="round" strokeDasharray={`${dash} 999`} transform="rotate(135 60 62)" />
              <circle cx="60" cy="62" r="52" fill="none" stroke="url(#gaugeG)" strokeWidth="7" strokeLinecap="round" strokeDasharray={`${(dash * arc) / 100} 999`} transform="rotate(135 60 62)" style={{ transition: "stroke-dasharray .6s ease" }} />
              <text x="60" y="64" textAnchor="middle" fill="#fff" fontSize="22" fontWeight="700">{radar}</text>
              <text x="60" y="78" textAnchor="middle" fill="#8aa7a3" fontSize="7">Active threat level</text>
            </svg>
          </div>
          <div className="pv-card">
            <small>Alert volume per hour (24h)</small>
            <svg viewBox="0 0 120 40" className="pv-area" preserveAspectRatio="none">
              <defs><linearGradient id="areaG" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#2dd4bf" stopOpacity=".45" /><stop offset="1" stopColor="#2dd4bf" stopOpacity="0" /></linearGradient></defs>
              {(() => {
                const pts = trendPct.map((h, i) => `${(i / (trendPct.length - 1)) * 120},${40 - (h / 100) * 34}`).join(" ");
                return (<><polygon points={`0,40 ${pts} 120,40`} fill="url(#areaG)" /><polyline points={pts} fill="none" stroke="#5eead4" strokeWidth="1.2" /></>);
              })()}
            </svg>
          </div>
          <div className="pv-card">
            <small>Alerts by severity (24h)</small>
            <div className="pv-grid4">
              <div><b>{fmt(data.severity.high)}</b><span>High</span></div>
              <div><b>{fmt(data.severity.medium)}</b><span>Medium</span></div>
              <div><b>{fmt(data.severity.low)}</b><span>Low</span></div>
              <div><b>{fmt(data.severity.info)}</b><span>Info</span></div>
            </div>
          </div>
        </aside>
      </div>
      {note && <p className="soc-note">{note}</p>}
    </section>
  );
}
