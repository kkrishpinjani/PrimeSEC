import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { LogoMark } from "./Logo";
import GraphDiagram from "./GraphDiagram";
import { fullSignOut } from "../lib/signOutClient";
import type { AssetRow, DetailVuln, InventoryAsset, Observation, StaleSource } from "../lib/inventory";
import type { IntelObject, SyncRun, Watermark } from "../lib/sync";

type Tab = "assets" | "sync" | "intel" | "graph" | "dupes";
type Candidate = { a: AssetRow; b: AssetRow; reasons: string[]; strength: "strong" | "medium" | "weak" };
type GraphState = { configured: boolean; reachable: boolean; message?: string };
type Exposure = { assetId: string; name: string; vulnerabilityCount: number; vulnerabilities: { id: string; severity: string | null; cve: string | null }[] };
type GraphPath = { nodes: { type: string; id: string; name: string }[]; relationships: string[] };
type Summary = { staleAssets?: number; totalAssets: number; byRisk: Record<string, number>; internetFacing: number; highCriticality: number; criticalityUnknown: number; bySource: Record<string, number> };
type Detail = InventoryAsset & { openVulnerabilities: number; staleSources: StaleSource[]; vulnerabilities: DetailVuln[]; observations: Observation[] };
const ENTITIES = ["indicators", "vulnerabilities", "reports", "threat_actors", "malwares"] as const;

const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");
const sev = (level: string) => (level === "critical" || level === "high" ? "sev-high" : level === "medium" ? "sev-medium" : "sev-low");

export default function InventoryWorkspace({ user, roles }: { user: { name?: string | null; email?: string | null }; roles: string[] }) {
  const [tab, setTab] = useState<Tab>("assets");
  const [assets, setAssets] = useState<AssetRow[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [q, setQ] = useState("");
  const [risk, setRisk] = useState("");
  const [detail, setDetail] = useState<Detail | null>(null);
  const [runs, setRuns] = useState<SyncRun[]>([]);
  const [marks, setMarks] = useState<Watermark[]>([]);
  const [scheduler, setScheduler] = useState<{ enabled: boolean; intervalMinutes: number | null; sources: string[]; lastTickAt: string | null; nextTickAt: string | null } | null>(null);
  const [intel, setIntel] = useState<IntelObject[]>([]);
  const [entity, setEntity] = useState<(typeof ENTITIES)[number]>("indicators");
  const [cands, setCands] = useState<Candidate[]>([]);
  const [pick, setPick] = useState({ keep: "", fold: "" });
  const [graph, setGraph] = useState<GraphState | null>(null);
  const [exposure, setExposure] = useState<Exposure[]>([]);
  const [paths, setPaths] = useState<{ asset: string; items: GraphPath[] } | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const isAdmin = roles.includes("SOC_Admin");
  const displayName = user.name || user.email || "Analyst";

  const call = useCallback(async (url: string, init?: RequestInit) => {
    const r = await fetch(url, { cache: "no-store", ...init });
    const b = await r.json();
    return { ok: r.ok, status: r.status, body: b };
  }, []);

  const loadAssets = useCallback(async () => {
    const params = new URLSearchParams({ limit: "200" });
    if (q.trim()) params.set("q", q.trim());
    if (risk) params.set("riskLevel", risk);
    const r = await call(`/api/inventory?${params}`);
    if (!r.ok) return setError(r.body.error || "Could not load the inventory.");
    setAssets(r.body.items); setSummary(r.body.summary);
  }, [call, q, risk]);
  const loadSync = useCallback(async () => {
    const r = await call("/api/sync");
    if (!r.ok) return setError(r.body.error || "Could not load the synchronization history.");
    setRuns(r.body.runs); setMarks(r.body.watermarks); setScheduler(r.body.scheduler ?? null);
  }, [call]);
  const loadIntel = useCallback(async () => {
    const r = await call(`/api/sync?intel=1&entity=${entity}&limit=100`);
    if (!r.ok) return setError(r.body.error || "Could not load the intelligence snapshot.");
    setIntel(r.body.items);
  }, [call, entity]);

  const loadGraph = useCallback(async () => {
    const r = await call("/api/graph");
    if (!r.ok) return setError(r.body.error || "Could not reach the graph service.");
    setGraph(r.body);
    if (r.body.reachable) {
      const e = await call("/api/graph?view=exposure&limit=50");
      // A failed graph query still answers 200, with a message and no items.
      if (e.ok && e.body.reachable === false) setGraph(e.body);
      setExposure(e.ok && Array.isArray(e.body.items) ? e.body.items : []);
    }
  }, [call]);
  async function graphWrite(action: "schema" | "project") {
    setBusy(`graph-${action}`); setError(""); setNotice("");
    const r = await call("/api/graph/write", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action }) });
    setBusy("");
    if (!r.ok) setError(r.body.error || "The graph write failed.");
    else setNotice(action === "schema" ? `Indexes ready (${r.body.indexes}).` : `Projected ${r.body.nodes} nodes and ${r.body.linked} links${r.body.skipped ? ` (${r.body.skipped} skipped: an end node was missing)` : ""}.${r.body.prunedAssets || r.body.prunedLinks || r.body.prunedVulnerabilities ? ` Removed what the inventory no longer has: ${r.body.prunedAssets} asset(s), ${r.body.prunedLinks} link(s), ${r.body.prunedVulnerabilities} vulnerability node(s).` : ""}`);
    await loadGraph();
  }
  async function showPaths(asset: string) {
    setBusy(asset); setError("");
    const r = await call(`/api/graph?view=paths&asset=${encodeURIComponent(asset)}&limit=25`);
    setBusy("");
    if (!r.ok) return setError(r.body.error || "Could not read paths.");
    if (!Array.isArray(r.body.paths)) return setError(r.body.message || "Could not read paths.");
    setPaths({ asset, items: r.body.paths });
  }

  const loadCands = useCallback(async () => {
    const r = await call("/api/inventory/merge");
    if (!r.ok) return setError(r.body.error || "Could not load duplicate suggestions.");
    setCands(r.body.candidates);
  }, [call]);
  async function decide(action: "merge" | "dismiss", keep: AssetRow | { id: string; name: string }, fold: AssetRow | { id: string; name: string }) {
    const prompt = action === "merge"
      ? `Merge "${fold.name}" INTO "${keep.name}"?\n\nThe merged asset keeps "${keep.name}" as its name, and this cannot be undone automatically. Why are they the same machine? (at least 10 characters)`
      : `Why are "${keep.name}" and "${fold.name}" different machines? (at least 10 characters)`;
    const note = window.prompt(prompt) ?? "";
    if (note.trim().length < 10) return setError("A reason of at least 10 characters is needed: it is recorded with the decision.");
    setBusy(`m-${keep.id}`); setError(""); setNotice("");
    const r = await call("/api/inventory/merge", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action, survivorId: keep.id, absorbedId: fold.id, note }) });
    setBusy("");
    if (!r.ok) setError(r.body.error || "The decision was refused.");
    else { setNotice(action === "merge" ? `Merged "${fold.name}" into "${keep.name}".` : "Marked as different machines."); setPick({ keep: "", fold: "" }); }
    await Promise.all([loadCands(), loadAssets()]);
  }

  useEffect(() => { void loadAssets(); }, [loadAssets]);
  useEffect(() => { if (tab === "dupes") { void loadCands(); void loadAssets(); } }, [tab, loadCands, loadAssets]);
  useEffect(() => { if (tab === "graph") void loadGraph(); }, [tab, loadGraph]);
  useEffect(() => { if (tab === "sync") void loadSync(); }, [tab, loadSync]);
  useEffect(() => { if (tab === "intel") void loadIntel(); }, [tab, loadIntel]);

  async function open(id: string) {
    setBusy(id); setError("");
    const r = await call(`/api/inventory/${encodeURIComponent(id)}`);
    setBusy("");
    if (!r.ok) return setError(r.body.error || "Could not open that asset.");
    setDetail(r.body);
  }
  async function runSync(source: "wazuh" | "greenbone" | "opencti") {
    setBusy(`sync-${source}`); setError(""); setNotice("");
    const r = await call("/api/sync", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(source === "opencti" ? { source, entity } : { source }) });
    setBusy("");
    if (r.body.run) {
      const run: SyncRun = r.body.run;
      run.status === "failed" ? setError(`${run.source} sync failed: ${run.error}`) : setNotice(`${run.source} sync read ${run.recordsSeen} record${run.recordsSeen === 1 ? "" : "s"}${r.body.created || r.body.updated ? ` (${r.body.created} new, ${r.body.updated} updated assets)` : ""}.${run.note ? ` ${run.note}` : ""}`);
    } else setError(r.body.error || "The synchronization could not be started.");
    await Promise.all([loadSync(), loadAssets(), tab === "intel" ? loadIntel() : Promise.resolve()]);
  }

  const tile = (label: string, value: number | string, note: string) => <div><span>{label}</span><strong>{value}</strong><em>{note}</em></div>;

  return (
    <section className="preview soc-dash vapt-page" aria-label="Asset inventory">
      <div className="pv-top">
        <span className="pv-logo"><LogoMark size={18} /></span>
        <Link href="/dashboard" className="pv-chip">← Dashboard</Link>
        <span className="pv-chip">Asset inventory</span>
        <div className="pv-actions">
          <span className="pv-user" title={roles.join(", ")}>
            <span className="pv-avatar">{displayName.slice(0, 1).toUpperCase()}</span>
            <span className="pv-user-text"><b>{displayName}</b><small>{roles[0] ?? "No role"}</small></span>
          </span>
          <button className="pv-btn" onClick={() => void fullSignOut()}>Sign out</button>
        </div>
      </div>

      <div className="pv-tabs" role="tablist">
        {([["assets", `Assets${summary ? ` (${summary.totalAssets})` : ""}`], ["sync", "Synchronization"], ["dupes", "Duplicates"], ["intel", "Intelligence snapshot"], ["graph", "Graph"]] as [Tab, string][]).map(([id, label]) => (
          <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? "on" : ""} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>

      <div className="vapt-body">
        <p className="vapt-warning">One record per asset, built from what Wazuh, Greenbone and other sources report. Records merge only on <b>durable identifiers</b> (agent id, cloud instance id, CMDB id), never on IP or hostname, so the same machine seen by two tools can appear twice until an analyst reconciles it. The exposure score is a documented heuristic for ordering work, not a probability. Nothing here scans or changes a host.</p>
        {error && <div className="pv-list pv-error" role="alert">{error}</div>}
        {notice && <div className="pv-list vapt-ok" role="status">{notice}</div>}

        {tab === "assets" && (
          <>
            {summary && (
              <div className="pv-invest-summary fd-tiles">
                {tile("Assets", summary.totalAssets, `${summary.internetFacing} internet-facing`)}
                {tile("Critical / high", summary.byRisk.critical + summary.byRisk.high, `${summary.byRisk.critical} critical`)}
                {tile("High criticality", summary.highCriticality, `${summary.criticalityUnknown} not yet rated`)}
                {tile("Possibly gone", summary.staleAssets ?? 0, "a source has not reported them in days")}
                {tile("Sources", Object.keys(summary.bySource).length, Object.entries(summary.bySource).map(([k, v]) => `${k} ${v}`).join(" · ") || "none yet")}
              </div>
            )}
            <div className="pv-list">
              <div className="fd-actions">
                <input className="fd-input" value={q} maxLength={100} placeholder="Search name, host, IP or key" onChange={(e) => setQ(e.target.value)} />
                <select className="fd-input" value={risk} onChange={(e) => setRisk(e.target.value)} aria-label="Risk level">
                  <option value="">All risk levels</option>
                  {["critical", "high", "medium", "low"].map((l) => <option key={l} value={l}>{l}</option>)}
                </select>
              </div>
              {assets.length === 0 ? <p className="pv-empty">No assets yet. Open the Synchronization tab and run a sync.</p> : assets.map((a) => (
                <div className="pv-row" key={a.id}>
                  <span className={`pv-sev ${sev(a.riskLevel)}`}>{a.riskLevel} {a.riskScore}</span>
                  <strong>{a.name}</strong>
                  <span>{a.primaryIp ?? a.hostname ?? a.canonicalKey} · {a.openVulnerabilities} open · {Object.keys(a.sources).join(", ")}{a.internetFacing ? " · internet-facing" : ""}{a.staleSources.length > 0 ? ` · not reported by ${a.staleSources.map((x) => `${x.source} for ${x.days}d`).join(", ")}` : ""}</span>
                  <button className="pv-btn" disabled={busy !== ""} onClick={() => void open(a.id)}>Open</button>
                </div>
              ))}
            </div>
            {detail && (
              <div className="pv-list fd-card" aria-label="Asset detail">
                <div className="fd-head"><strong className="fd-name">{detail.name}</strong><code>{detail.canonicalKey}</code><span className={`pv-sev ${sev(detail.riskLevel)}`}>{detail.riskLevel} {detail.riskScore}</span></div>
                <p className="fd-meta">{[detail.assetType, detail.operatingSystem, detail.environment, detail.businessUnit].filter(Boolean).join(" · ") || "No further attributes"} · criticality {detail.criticality ?? "not rated (scored as 3)"} · updated {when(detail.updatedAt)}</p>
                {detail.staleSources.length > 0 && <p className="fd-meta">Not reported by {detail.staleSources.map((x) => `${x.source} for ${x.days} days`).join(", ")}. It may be gone, renamed, or that source may be failing. Nothing was changed.</p>}
                <h4>Vulnerabilities ({detail.openVulnerabilities} open)</h4>
                {detail.vulnerabilities.length === 0 ? <p className="pv-empty">None recorded.</p> : detail.vulnerabilities.map((v) => (
                  <div className="pv-row" key={v.key}><span className={`pv-sev ${sev(v.severity)}`}>{v.severity}{v.cvss !== null ? ` ${v.cvss}` : ""}</span><strong>{v.cve ?? v.key}</strong><span>{v.title} · {v.status} · {v.source}{v.notInLatestSync ? " · not in the latest " + v.source + " sync: it may be fixed, verify before closing" : ""}</span></div>
                ))}
                {detail.mergedFrom && detail.mergedFrom.length > 0 && <><h4>Merged from</h4>{detail.mergedFrom.map((m) => <p className="fd-meta" key={m.id}>{m.name} ({m.sources.join(", ")}) · by {m.by} · {when(m.at)} · {m.note}</p>)}</>}
                <h4>Seen by</h4>
                <div className="fd-cves">{detail.observations.slice(0, 8).map((o, i) => <code key={i}>{o.source}:{o.sourceAssetId} · {when(o.observedAt)}</code>)}</div>
                <div className="fd-actions"><button className="pv-btn" onClick={() => setDetail(null)}>Close</button></div>
              </div>
            )}
          </>
        )}

        {tab === "sync" && (
          <>
            <div className="pv-list">
              <small>Start a sync {isAdmin ? "" : "(SOC_Admin only)"}. Each one reads from the source and writes only PrimeSEC&apos;s own data. A source already syncing cannot be started again.</small>
              <div className="fd-actions">
                <button className="pv-btn pv-btn-primary" disabled={!isAdmin || busy !== ""} onClick={() => void runSync("wazuh")}>{busy === "sync-wazuh" ? "Syncing…" : "Sync Wazuh agents"}</button>
                <button className="pv-btn pv-btn-primary" disabled={!isAdmin || busy !== ""} title="Uses findings already imported in the VAPT workspace; does not call Greenbone" onClick={() => void runSync("greenbone")}>{busy === "sync-greenbone" ? "Syncing…" : "Sync Greenbone findings"}</button>
                <select className="fd-input" value={entity} onChange={(e) => setEntity(e.target.value as (typeof ENTITIES)[number])} aria-label="OpenCTI entity type">{ENTITIES.map((e) => <option key={e} value={e}>{e}</option>)}</select>
                <button className="pv-btn pv-btn-primary" disabled={!isAdmin || busy !== ""} onClick={() => void runSync("opencti")}>{busy === "sync-opencti" ? "Syncing…" : "Sync OpenCTI page"}</button>
              </div>
            </div>
            <div className="pv-list">
              <small>Automatic sync</small>
              {scheduler?.enabled ? <p className="fd-meta">On: every {scheduler.intervalMinutes} minutes ({scheduler.sources.join(", ")}). Last pass {when(scheduler.lastTickAt)}; next {when(scheduler.nextTickAt)}. It runs the same read-only syncs as the buttons above and never starts a scan.</p> : <p className="fd-meta">Off. Set <code>SYNC_SCHEDULE_MINUTES</code> (5 to 1440) in .env and restart to run these syncs automatically.</p>}
            </div>
            <div className="pv-list">
              <small>Watermarks</small>
              {marks.length === 0 ? <p className="pv-empty">No successful sync yet.</p> : marks.map((m) => <div className="pv-row" key={`${m.source}/${m.stream}`}><strong>{m.source} / {m.stream}</strong><span>last success {when(m.updatedAt)}</span><code>{JSON.stringify(m.cursor)}</code></div>)}
            </div>
            <div className="pv-list">
              <small>Run history (newest first)</small>
              {runs.length === 0 ? <p className="pv-empty">No runs yet.</p> : runs.map((r) => (
                <div className="pv-row" key={r.id}>
                  <span className={`pv-sev ${r.status === "failed" ? "sev-high" : r.status === "running" ? "sev-medium" : "sev-low"}`}>{r.status}</span>
                  <strong>{r.source} / {r.stream}</strong>
                  <span>{when(r.startedAt)} · {r.recordsSeen} read · {r.recordsIngested} stored · by {r.triggeredBy}{r.error ? ` · ${r.error}` : ""}{r.note ? ` · ${r.note}` : ""}</span>
                </div>
              ))}
            </div>
          </>
        )}

        {tab === "dupes" && (
          <div className="pv-list">
            <small>The same machine can appear twice when two tools see it differently. A suggestion is only a lead: you decide, and every decision needs a written reason that is recorded. Merging changes PrimeSEC&apos;s inventory only. Two assets reported by the same source cannot be merged, because that source already lists them as separate machines.</small>
            {cands.length === 0 ? <p className="pv-empty">No suggestions. The pair you have in mind may share no IP or name (for example an agent&apos;s address and a scanner&apos;s view): use the picker below.</p> : cands.map((c) => (
              <div className="fd-card" key={`${c.a.id}|${c.b.id}`}>
                <div className="fd-head"><span className={`pv-sev ${c.strength === "strong" ? "sev-high" : c.strength === "medium" ? "sev-medium" : "sev-low"}`}>{c.strength} lead</span><strong className="fd-name">{c.reasons.join(" · ")}</strong></div>
                {[c.a, c.b].map((x) => <p className="fd-meta" key={x.id}><b>{x.name}</b> · {Object.keys(x.sources).join(", ")} · {x.primaryIp ?? x.hostname ?? x.canonicalKey} · {x.openVulnerabilities} open · {x.riskLevel} {x.riskScore}</p>)}
                <div className="fd-actions">
                  <button className="pv-btn pv-btn-primary" disabled={busy !== ""} onClick={() => void decide("merge", c.a, c.b)}>Merge into “{c.a.name.slice(0, 24)}”</button>
                  <button className="pv-btn pv-btn-primary" disabled={busy !== ""} onClick={() => void decide("merge", c.b, c.a)}>Merge into “{c.b.name.slice(0, 24)}”</button>
                  <button className="pv-btn" disabled={busy !== ""} onClick={() => void decide("dismiss", c.a, c.b)}>Not the same machine</button>
                </div>
              </div>
            ))}
            <div className="fd-card">
              <div className="fd-head"><strong className="fd-name">Merge two assets by hand</strong></div>
              <div className="fd-actions">
                <select className="fd-input" value={pick.keep} onChange={(e) => setPick({ ...pick, keep: e.target.value })} aria-label="Asset to keep"><option value="">Keep this one…</option>{assets.map((a) => <option key={a.id} value={a.id}>{a.name} ({Object.keys(a.sources).join(", ")})</option>)}</select>
                <select className="fd-input" value={pick.fold} onChange={(e) => setPick({ ...pick, fold: e.target.value })} aria-label="Asset to merge into it"><option value="">…and merge this one into it</option>{assets.filter((a) => a.id !== pick.keep).map((a) => <option key={a.id} value={a.id}>{a.name} ({Object.keys(a.sources).join(", ")})</option>)}</select>
                <button className="pv-btn pv-btn-primary" disabled={busy !== "" || !pick.keep || !pick.fold} onClick={() => { const k = assets.find((a) => a.id === pick.keep), f = assets.find((a) => a.id === pick.fold); if (k && f) void decide("merge", k, f); }}>Merge</button>
              </div>
            </div>
          </div>
        )}

        {tab === "graph" && (
          <div className="pv-list">
            <small>Neo4j security graph. It holds only what an administrator projects into it from this inventory; open vulnerabilities become links, fixed ones do not.</small>
            {graph && !graph.configured && <p className="pv-empty">{graph.message}</p>}
            {graph && graph.configured && !graph.reachable && <p className="pv-empty">Neo4j is configured but not reachable: {graph.message}</p>}
            {graph?.reachable && (
              <>
                <div className="fd-actions">
                  <button className="pv-btn" disabled={!isAdmin || busy !== ""} onClick={() => void graphWrite("schema")}>Create indexes</button>
                  <button className="pv-btn pv-btn-primary" disabled={!isAdmin || busy !== ""} onClick={() => void graphWrite("project")}>{busy === "graph-project" ? "Projecting…" : "Project inventory into graph"}</button>
                </div>
                {exposure.length === 0 ? <p className="pv-empty">The graph has no assets yet. Project the inventory (SOC_Admin).</p> : exposure.map((x) => (
                  <div className="pv-row pv-row-graph" key={x.assetId}>
                    <strong>{x.name}</strong>
                    <span>{x.vulnerabilityCount} open vulnerabilit{x.vulnerabilityCount === 1 ? "y" : "ies"}{x.vulnerabilities.length ? ` · ${x.vulnerabilities.slice(0, 3).map((v) => v.cve ?? v.id).join(", ")}` : ""}</span>
                    <button className="pv-btn" disabled={busy !== ""} onClick={() => void showPaths(x.assetId)}>Paths</button>
                  </div>
                ))}
                {paths && (
                  <div className="fd-card">
                    <div className="fd-head"><strong className="fd-name">Connections from {exposure.find((x) => x.assetId === paths.asset)?.name ?? paths.asset}</strong></div>
                    {paths.items.length === 0 ? <p className="pv-empty">No connections found.</p> : (
                      <>
                        <GraphDiagram paths={paths.items} label={`Connections from ${paths.asset}`} />
                        <details className="gd-text">
                          <summary>Show as text</summary>
                          {paths.items.map((p, i) => <p className="fd-meta" key={i}>{p.nodes.map((n, j) => <span key={j}>{j > 0 ? ` —${p.relationships[j - 1]}→ ` : ""}<b>{n.name}</b></span>)}</p>)}
                        </details>
                      </>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {tab === "intel" && (
          <div className="pv-list">
            <small>Threat intelligence stored by OpenCTI syncs. Objects outside <code>OPENCTI_ALLOWED_MARKINGS</code> keep only their id and markings. An intelligence object is never turned into an asset.</small>
            <div className="fd-actions">
              <select className="fd-input" value={entity} onChange={(e) => setEntity(e.target.value as (typeof ENTITIES)[number])} aria-label="Entity type">{ENTITIES.map((e) => <option key={e} value={e}>{e}</option>)}</select>
            </div>
            {intel.length === 0 ? <p className="pv-empty">Nothing stored for {entity} yet.</p> : intel.map((o) => (
              <div className="pv-row" key={`${o.entityType}/${o.externalId}`}>
                <span className={`pv-sev ${o.restricted ? "sev-high" : "sev-low"}`}>{o.restricted ? "restricted" : "open"}</span>
                <strong>{o.restricted ? o.externalId : o.name || o.externalId}</strong>
                <span>{o.markings.join(", ") || "unmarked"} · {when(o.updatedAt)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
