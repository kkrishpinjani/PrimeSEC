import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type GNode = { type: string; id: string; name: string; props: Record<string, unknown> };
type GRel = { source: string; target: string; type: string };
type Sim = { key: string; node: GNode; x: number; y: number; vx: number; vy: number; fixed: boolean; deg: number };

const TONES: Record<string, string> = {
  Asset: "#5eead4", Vulnerability: "#fb7185", Alert: "#fbbf24", Indicator: "#f0abfc", ThreatActor: "#f87171",
  Technique: "#fdba74", Software: "#a5b4fc", BusinessApplication: "#60a5fa", Identity: "#86efac"
};
const toneOf = (t: string) => TONES[t] ?? "#7fa39f";
const RISK: Record<string, string> = { critical: "#fb7185", high: "#fb923c", medium: "#fbbf24", low: "#5eead4" };
const W = 1100, H = 680;
const DEFAULT_OFF = new Set(["Vulnerability", "Software"]);

/** Interactive picture of the whole security graph: drag nodes, scroll to zoom, filter by type, click a node to see how it connects. */
export default function GraphExplorer() {
  const [data, setData] = useState<{ nodes: GNode[]; relationships: GRel[] } | null>(null);
  const [error, setError] = useState("");
  const [off, setOff] = useState<Set<string>>(new Set(DEFAULT_OFF));
  const [selected, setSelected] = useState<string | null>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [, setTick] = useState(0);
  const sim = useRef<Map<string, Sim>>(new Map());
  const raf = useRef(0);
  const alpha = useRef(1);
  const drag = useRef<{ key: string | null; pan: boolean; sx: number; sy: number; vx: number; vy: number } | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    let live = true;
    fetch("/api/graph?view=overview", { cache: "no-store" }).then((r) => r.json()).then((b) => {
      if (!live) return;
      if (!Array.isArray(b.nodes)) return setError(b.error || b.message || "The graph could not be read.");
      setData({ nodes: b.nodes, relationships: b.relationships });
    }).catch(() => live && setError("The graph could not be read."));
    return () => { live = false; };
  }, []);

  const types = useMemo(() => {
    const c = new Map<string, number>();
    for (const n of data?.nodes ?? []) c.set(n.type, (c.get(n.type) ?? 0) + 1);
    return [...c.entries()].sort((a, b) => b[1] - a[1]);
  }, [data]);

  const visible = useMemo(() => {
    if (!data) return { nodes: [] as GNode[], rels: [] as GRel[] };
    const nodes = data.nodes.filter((n) => !off.has(n.type));
    const keys = new Set(nodes.map((n) => `${n.type}/${n.id}`));
    return { nodes, rels: data.relationships.filter((r) => keys.has(r.source) && keys.has(r.target)) };
  }, [data, off]);

  // (re)build the simulation whenever the visible set changes
  useEffect(() => {
    const prev = sim.current;
    const next = new Map<string, Sim>();
    const deg = new Map<string, number>();
    for (const r of visible.rels) { deg.set(r.source, (deg.get(r.source) ?? 0) + 1); deg.set(r.target, (deg.get(r.target) ?? 0) + 1); }
    visible.nodes.forEach((n, i) => {
      const key = `${n.type}/${n.id}`;
      const old = prev.get(key);
      const a = (i / Math.max(1, visible.nodes.length)) * Math.PI * 2;
      next.set(key, old ? { ...old, node: n, deg: deg.get(key) ?? 0 } : { key, node: n, x: W / 2 + Math.cos(a) * 260, y: H / 2 + Math.sin(a) * 200, vx: 0, vy: 0, fixed: false, deg: deg.get(key) ?? 0 });
    });
    sim.current = next;
    alpha.current = 1;
  }, [visible]);

  const step = useCallback(() => {
    const nodes = [...sim.current.values()];
    const a = alpha.current;
    if (a > 0.015 && nodes.length) {
      for (let i = 0; i < nodes.length; i++) {
        const p = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const q = nodes[j];
          let dx = p.x - q.x, dy = p.y - q.y;
          let d2 = dx * dx + dy * dy;
          if (d2 > 90000) continue;
          if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
          const f = (2200 / d2) * a;
          const d = Math.sqrt(d2);
          p.vx += (dx / d) * f; p.vy += (dy / d) * f; q.vx -= (dx / d) * f; q.vy -= (dy / d) * f;
        }
      }
      for (const r of visibleRels.current) {
        const s = sim.current.get(r.source), t = sim.current.get(r.target);
        if (!s || !t) continue;
        const dx = t.x - s.x, dy = t.y - s.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = (d - 70) * 0.03 * a;
        s.vx += (dx / d) * f; s.vy += (dy / d) * f; t.vx -= (dx / d) * f; t.vy -= (dy / d) * f;
      }
      for (const n of nodes) {
        n.vx += (W / 2 - n.x) * 0.004 * a; n.vy += (H / 2 - n.y) * 0.006 * a;
        if (!n.fixed) { n.x += n.vx; n.y += n.vy; }
        n.vx *= 0.82; n.vy *= 0.82;
      }
      alpha.current = a * 0.985;
      setTick((t) => t + 1);
    }
    raf.current = requestAnimationFrame(step);
  }, []);
  const visibleRels = useRef<GRel[]>([]);
  visibleRels.current = visible.rels;
  useEffect(() => { raf.current = requestAnimationFrame(step); return () => cancelAnimationFrame(raf.current); }, [step]);

  const toWorld = (e: { clientX: number; clientY: number }) => {
    const r = svgRef.current!.getBoundingClientRect();
    const sx = ((e.clientX - r.left) / r.width) * W, sy = ((e.clientY - r.top) / r.height) * H;
    return { x: (sx - view.x) / view.k, y: (sy - view.y) / view.k, sx, sy };
  };
  const down = (e: React.PointerEvent, key: string | null) => {
    e.stopPropagation();
    (e.currentTarget as Element).setPointerCapture?.(e.pointerId);
    const w = toWorld(e);
    drag.current = { key, pan: key === null, sx: w.sx, sy: w.sy, vx: view.x, vy: view.y };
    if (key) { const n = sim.current.get(key); if (n) n.fixed = true; setSelected(key); alpha.current = Math.max(alpha.current, 0.4); }
  };
  const move = (e: React.PointerEvent) => {
    const d = drag.current;
    if (!d) return;
    const w = toWorld(e);
    if (d.pan) setView((v) => ({ ...v, x: d.vx + (w.sx - d.sx), y: d.vy + (w.sy - d.sy) }));
    else if (d.key) { const n = sim.current.get(d.key); if (n) { n.x = w.x; n.y = w.y; n.vx = n.vy = 0; alpha.current = Math.max(alpha.current, 0.3); } }
  };
  const up = () => { const d = drag.current; if (d?.key) { const n = sim.current.get(d.key); if (n) n.fixed = false; } drag.current = null; };
  const wheel = (e: React.WheelEvent) => {
    const w = toWorld(e);
    const k = Math.min(3.5, Math.max(0.35, view.k * (e.deltaY < 0 ? 1.12 : 0.89)));
    setView({ k, x: w.sx - w.x * k, y: w.sy - w.y * k });
  };

  const sel = selected ? sim.current.get(selected) : null;
  const neighbours = useMemo(() => {
    const s = new Set<string>();
    if (selected) for (const r of visible.rels) { if (r.source === selected) s.add(r.target); if (r.target === selected) s.add(r.source); }
    return s;
  }, [selected, visible]);
  const toggle = (t: string) => setOff((o) => { const n = new Set(o); if (n.has(t)) n.delete(t); else n.add(t); return n; });
  const radius = (s: Sim) => Math.min(17, 5 + Math.sqrt(s.deg) * 1.6 + (s.node.type === "Asset" ? 2 : 0));
  const fill = (s: Sim) => (s.node.type === "Asset" ? RISK[String(s.node.props.riskLevel)] ?? toneOf("Asset") : toneOf(s.node.type));

  if (error) return <p className="pv-empty">{error}</p>;
  if (!data) return <p className="pv-empty">Loading the graph…</p>;
  if (data.nodes.length === 0) return <p className="pv-empty">The graph is empty. Project the inventory first.</p>;

  const detail = sel ? [...visible.rels.filter((r) => r.source === sel.key || r.target === sel.key)] : [];
  return (
    <div className="gx-wrap">
      <div className="gx-filters">
        {types.map(([t, c]) => (
          <button key={t} className={`gx-chip ${off.has(t) ? "off" : ""}`} onClick={() => toggle(t)} aria-pressed={!off.has(t)}>
            <i style={{ background: toneOf(t) }} />{t} <b>{c}</b>
          </button>
        ))}
        <span className="gx-hint">Drag nodes · scroll to zoom · drag the background to pan · assets are coloured by risk</span>
      </div>
      <div className="gx-stage">
        <svg ref={svgRef} className="gx-svg" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Security graph" onPointerDown={(e) => down(e, null)} onPointerMove={move} onPointerUp={up} onPointerLeave={up} onWheel={wheel}>
          <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
            {visible.rels.map((r, i) => {
              const s = sim.current.get(r.source), t = sim.current.get(r.target);
              if (!s || !t) return null;
              const hot = selected && (r.source === selected || r.target === selected);
              return <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke={hot ? "#5eead4" : "rgba(255,255,255,0.16)"} strokeWidth={hot ? 1.6 : 0.8} opacity={selected && !hot ? 0.35 : 1} />;
            })}
            {[...sim.current.values()].map((s) => {
              const dim = selected && s.key !== selected && !neighbours.has(s.key);
              const r = radius(s);
              return (
                <g key={s.key} transform={`translate(${s.x} ${s.y})`} opacity={dim ? 0.25 : 1} style={{ cursor: "grab" }} onPointerDown={(e) => down(e, s.key)}>
                  <circle r={r} fill={fill(s)} fillOpacity={0.85} stroke={s.key === selected ? "#fff" : toneOf(s.node.type)} strokeWidth={s.key === selected ? 2.2 : 1} />
                  {(s.deg >= 6 || s.key === selected || neighbours.has(s.key) || view.k > 1.6) && <text y={r + 11} textAnchor="middle" className="gx-label">{s.node.name.length > 24 ? `${s.node.name.slice(0, 23)}…` : s.node.name}</text>}
                  <title>{`${s.node.type}: ${s.node.name}`}</title>
                </g>
              );
            })}
          </g>
        </svg>
        <aside className="gx-panel">
          {sel ? (
            <>
              <small>{sel.node.type}</small>
              <strong>{sel.node.name}</strong>
              <dl>
                {Object.entries(sel.node.props).filter(([, v]) => v !== null && v !== "").map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{Array.isArray(v) ? v.join(", ") : String(v)}</dd></div>)}
              </dl>
              <small>{detail.length} connection{detail.length === 1 ? "" : "s"}</small>
              <ul>
                {detail.slice(0, 14).map((r, i) => { const other = sim.current.get(r.source === sel.key ? r.target : r.source); return <li key={i}><span>{r.source === sel.key ? "→" : "←"} {r.type.replace(/_/g, " ").toLowerCase()}</span> <button onClick={() => setSelected(other?.key ?? null)}>{other?.node.name ?? "?"}</button></li>; })}
              </ul>
              <button className="pv-btn" onClick={() => setSelected(null)}>Clear selection</button>
            </>
          ) : (
            <>
              <small>{visible.nodes.length} nodes · {visible.rels.length} links shown</small>
              <p className="fd-meta">Click a node to see what it is connected to: the hosts a business application depends on, the alerts a machine raised, the indicators and threat actors behind them. Turn types on or off above. Vulnerability nodes start hidden because there are hundreds.</p>
              <div className="gd-legend">{types.map(([t]) => <span key={t}><i style={{ background: toneOf(t) }} />{t}</span>)}</div>
              <div className="gd-legend">{Object.entries(RISK).map(([k, c]) => <span key={k}><i style={{ background: c }} />{k} risk</span>)}</div>
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
