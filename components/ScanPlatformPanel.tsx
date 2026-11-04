import { useState } from "react";
import type { ScanPlatform } from "../lib/vapt";

/** Collapsible, read-only view of how the Greenbone instance is set up. Loads only when opened. */
export default function ScanPlatformPanel() {
  const [data, setData] = useState<ScanPlatform | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function load() {
    if (data || loading) return;
    setLoading(true); setError("");
    try {
      const r = await fetch("/api/vapt/platform", { cache: "no-store" });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "Could not load the scan platform.");
      setData(b);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }
  const section = <T,>(title: string, s: { items: T[]; error?: string }, row: (x: T, i: number) => React.ReactNode) => (
    <div className="fd-card">
      <div className="fd-head"><strong className="fd-name">{title}</strong><code>{s.items.length}</code></div>
      {s.error && <p className="fd-meta">{s.error}</p>}
      {s.items.length === 0 && !s.error ? <p className="pv-empty">None configured.</p> : s.items.map(row)}
    </div>
  );

  return (
    <details className="pv-list" onToggle={(e) => { if ((e.target as HTMLDetailsElement).open) void load(); }}>
      <summary><small>Scan platform (read-only): scanners, scan configurations, port lists, schedules, alert definitions, feed status</small></summary>
      {loading && <p className="pv-empty">Loading…</p>}
      {error && <div className="pv-list pv-error" role="alert">{error}</div>}
      {data && !data.status.connected && <p className="pv-empty">{data.status.message}</p>}
      {data?.status.connected && (
        <>
          <p className="fd-meta">This shows how Greenbone is set up. Nothing here creates, edits or deletes anything. Alert definitions show names only, never their delivery settings.</p>
          {section("Feeds", data.feeds, (f, i) => <div className="pv-row" key={i}><span className={`pv-sev ${f.syncing ? "sev-medium" : "sev-low"}`}>{f.syncing ? "syncing" : "idle"}</span><strong>{f.name && f.name !== "unknown" ? f.name : `${f.type} feed`}</strong><span>{f.type} · version {f.version}</span></div>)}
          {section("Scanners", data.scanners, (s) => <div className="pv-row" key={s.id}><strong>{s.name}</strong><span>{s.type}{s.host ? ` · ${s.host}` : ""}</span><code>{s.id.slice(0, 8)}</code></div>)}
          {section("Scan configurations", data.configs, (c) => <div className="pv-row" key={c.id}><strong>{c.name}</strong><span>{c.nvtCount || "?"} tests · {c.familyCount || "?"} families{c.comment ? ` · ${c.comment.slice(0, 80)}` : ""}</span><code>{c.id.slice(0, 8)}</code></div>)}
          {section("Port lists", data.portLists, (p) => <div className="pv-row" key={p.id}><strong>{p.name}</strong><span>{p.ports} ports</span><code>{p.id.slice(0, 8)}</code></div>)}
          {section("Schedules", data.schedules, (s) => <div className="pv-row" key={s.id}><strong>{s.name}</strong><span>{s.timezone}{s.comment ? ` · ${s.comment.slice(0, 80)}` : ""}</span></div>)}
          {section("Alert definitions", data.alerts, (a) => <div className="pv-row" key={a.id}><span className={`pv-sev ${a.active === "1" ? "sev-low" : "sev-medium"}`}>{a.active === "1" ? "active" : "inactive"}</span><strong>{a.name}</strong><span>on “{a.event}” via {a.method}</span></div>)}
        </>
      )}
    </details>
  );
}
