import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { LogoMark } from "./Logo";
import { fullSignOut } from "../lib/signOutClient";
import type { Entity, Observable, Page } from "../lib/opencti";

type Kind = "vulnerabilities" | "threat_actors" | "malwares" | "reports" | "indicators" | "observables";
const KINDS: [Kind, string][] = [["vulnerabilities", "Vulnerabilities"], ["threat_actors", "Threat actors"], ["malwares", "Malware"], ["reports", "Reports"], ["indicators", "Indicators"], ["observables", "Observable search"]];
const DETAIL_TYPE: Record<string, string> = { vulnerabilities: "vulnerability", threat_actors: "threat_actor", malwares: "malware", reports: "report", indicators: "indicator" };

export default function ThreatIntelExplorer({ user, roles }: { user: { name?: string | null; email?: string | null }; roles: string[] }) {
  const [kind, setKind] = useState<Kind>("vulnerabilities");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState<Page<Entity> | Page<Observable> | null>(null);
  const [detail, setDetail] = useState<Entity | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const displayName = user.name || user.email || "Analyst";

  const load = useCallback(async (k: Kind, q: string, after = "") => {
    setBusy(true); setError(""); setDetail(null);
    try {
      const params = new URLSearchParams({ first: "25" });
      if (k === "observables") params.set("value", q); else if (q) params.set("search", q);
      if (after) params.set("after", after);
      const r = await fetch(`/api/opencti/${k}?${params}`, { cache: "no-store" });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "The request failed.");
      setPage(b);
    } catch (e) {
      setError((e as Error).message); setPage(null);
    } finally {
      setBusy(false);
    }
  }, []);
  useEffect(() => { if (kind !== "observables") void load(kind, ""); else { setPage(null); } }, [kind, load]);

  async function open(id: string) {
    setBusy(true); setError("");
    try {
      const r = await fetch(`/api/opencti/entity?type=${DETAIL_TYPE[kind]}&id=${encodeURIComponent(id)}`, { cache: "no-store" });
      const b = await r.json();
      if (!r.ok) throw new Error(b.error || "Could not open that entity.");
      setDetail(b.item);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const isObs = kind === "observables";

  return (
    <section className="preview soc-dash vapt-page" aria-label="Threat intelligence explorer">
      <div className="pv-top">
        <span className="pv-logo"><LogoMark size={18} /></span>
        <Link href="/dashboard" className="pv-chip">← Dashboard</Link>
        <span className="pv-chip">Threat intelligence</span>
        <div className="pv-actions">
          <span className="pv-user" title={roles.join(", ")}><span className="pv-avatar">{displayName.slice(0, 1).toUpperCase()}</span><span className="pv-user-text"><b>{displayName}</b><small>{roles[0] ?? "No role"}</small></span></span>
          <button className="pv-btn" onClick={() => void fullSignOut()}>Sign out</button>
        </div>
      </div>
      <div className="pv-tabs" role="tablist">
        {KINDS.map(([id, label]) => <button key={id} role="tab" aria-selected={kind === id} className={kind === id ? "on" : ""} onClick={() => { setKind(id); setSearch(""); }}>{label}</button>)}
      </div>
      <div className="vapt-body">
        <p className="vapt-warning">Read-only view of your OpenCTI, through a read-only account. Intelligence is a lead, not a verdict: a match means something is worth checking, and no match does not mean something is safe. {page?.markingPolicy ? <>Only objects marked <b>{page.markingPolicy.join(", ").toUpperCase()}</b> are shown in full; others appear as an id only.</> : null}</p>
        {error && <div className="pv-list pv-error" role="alert">{error}</div>}
        <div className="pv-list">
          <div className="fd-actions">
            <input className="fd-input" value={search} maxLength={255} placeholder={isObs ? "IP, domain or hash" : "Search by name (for example log4j)"} onChange={(e) => setSearch(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && (search.trim() || !isObs)) void load(kind, search.trim()); }} />
            <button className="pv-btn pv-btn-primary" disabled={busy || (isObs && !search.trim())} onClick={() => void load(kind, search.trim())}>{busy ? "Loading…" : "Search"}</button>
          </div>
          {page && <small>{page.total ?? "?"} match{page.total === 1 ? "" : "es"}{page.restrictedCount ? ` · ${page.restrictedCount} hidden by the marking policy` : ""}; showing {page.items.length}.</small>}
          {page && page.items.length === 0 && <p className="pv-empty">{isObs ? "No observable matches that value." : kind === "indicators" || kind === "reports" || kind === "threat_actors" || kind === "malwares" ? "Nothing here yet. The free feeds loaded so far (OpenCTI datasets, MITRE ATT&CK, CISA Known Exploited Vulnerabilities) fill the Vulnerabilities tab; indicators and malware need an additional feed." : "Nothing returned."}</p>}
          {page && !isObs && (page.items as Entity[]).map((e) => (
            <div className="pv-row" key={e.id}>
              <span className={`pv-sev ${e.restricted ? "sev-high" : "sev-low"}`}>{e.restricted ? "restricted" : e.markings[0] ?? "unmarked"}</span>
              <strong>{e.restricted ? e.id : e.name}</strong>
              <span>{e.restricted ? `markings: ${e.markings.join(", ") || "none"}` : [e.fields.x_opencti_cvss_base_score ? `CVSS ${e.fields.x_opencti_cvss_base_score}` : "", e.fields.x_opencti_score ? `score ${e.fields.x_opencti_score}` : "", String(e.fields.description ?? "").slice(0, 110)].filter(Boolean).join(" · ")}</span>
              <button className="pv-btn" disabled={busy || e.restricted} onClick={() => void open(e.id)}>Open</button>
            </div>
          ))}
          {page && isObs && (page.items as Observable[]).map((o) => (
            <div className="pv-row" key={o.id}><span className={`pv-sev ${o.restricted ? "sev-high" : "sev-low"}`}>{o.restricted ? "restricted" : o.type}</span><strong>{o.restricted ? o.id : o.value}</strong><span>{o.markings.join(", ") || "unmarked"} · {o.created ?? "—"}</span></div>
          ))}
          {page?.hasNextPage && page.endCursor && <div className="fd-actions"><button className="pv-btn" disabled={busy} onClick={() => void load(kind, search.trim(), page.endCursor ?? "")}>Next page</button></div>}
        </div>
        {detail && (
          <div className="pv-list fd-card" aria-label="Entity detail">
            <div className="fd-head"><strong className="fd-name">{detail.name}</strong><code>{detail.id}</code>{detail.markings.map((m) => <span className="fd-flag" key={m}>{m}</span>)}</div>
            {detail.labels.length > 0 && <div className="fd-cves">{detail.labels.map((l) => <code key={l}>{l}</code>)}</div>}
            <dl style={{ display: "grid", gridTemplateColumns: "max-content 1fr", gap: "4px 14px", fontSize: "0.8rem" }}>
              {Object.entries(detail.fields).filter(([, v]) => v !== null && !(Array.isArray(v) && v.length === 0)).map(([k, v]) => <><dt key={k + "k"} className="fd-meta">{k}</dt><dd key={k + "v"} style={{ margin: 0, overflowWrap: "anywhere" }}>{Array.isArray(v) ? v.join(", ") : String(v)}</dd></>)}
            </dl>
            <div className="fd-actions"><button className="pv-btn" onClick={() => setDetail(null)}>Close</button></div>
          </div>
        )}
      </div>
    </section>
  );
}
