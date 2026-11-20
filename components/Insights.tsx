import { useEffect, useState } from "react";
import type { Chart, Item } from "../lib/insights";

const PALETTE = ["#5eead4", "#7dd3fc", "#a5b4fc", "#f0abfc", "#fbbf24", "#fb923c", "#86efac", "#f87171", "#60a5fa"];
const colorOf = (it: Item, i: number) => it.color ?? PALETTE[i % PALETTE.length];
const fmt = (n: number) => n.toLocaleString("en-US");
const short = (s: string, n = 26) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

function Donut({ items }: { items: Item[] }) {
  const rows = items.filter((i) => i.value > 0);
  const total = rows.reduce((s, i) => s + i.value, 0);
  const R = 42, C = 2 * Math.PI * R;
  let acc = 0;
  return (
    <div className="ins-donut">
      <svg viewBox="0 0 120 120" role="img" aria-label="Distribution">
        <circle cx="60" cy="60" r={R} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="14" />
        {rows.map((it, i) => {
          const len = (it.value / total) * C;
          const el = <circle key={it.label} cx="60" cy="60" r={R} fill="none" stroke={colorOf(it, i)} strokeWidth="14" strokeDasharray={`${Math.max(0, len - 1.5)} ${C}`} strokeDashoffset={-acc} transform="rotate(-90 60 60)"><title>{`${it.label}: ${fmt(it.value)}`}</title></circle>;
          acc += len;
          return el;
        })}
        <text x="60" y="58" textAnchor="middle" className="ins-total">{fmt(total)}</text>
        <text x="60" y="72" textAnchor="middle" className="ins-sub">total</text>
      </svg>
      <ul>{rows.map((it, i) => <li key={it.label}><i style={{ background: colorOf(it, i) }} /><span>{short(it.label, 22)}</span><b>{fmt(it.value)}</b></li>)}</ul>
    </div>
  );
}

function Bars({ items }: { items: Item[] }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div className="ins-bars">
      {items.map((it, i) => (
        <div key={it.label} title={`${it.label}: ${fmt(it.value)}`}>
          <span>{short(it.label, 34)}</span>
          <em><i style={{ width: `${Math.max(2, (it.value / max) * 100)}%`, background: it.color ?? "#5eead4" }} /></em>
          <b>{fmt(it.value)}</b>
        </div>
      ))}
    </div>
  );
}

function Columns({ items }: { items: Item[] }) {
  const W = 320, H = 130, pad = 18;
  const max = Math.max(1, ...items.map((i) => i.value));
  const bw = (W - pad) / items.length;
  const every = Math.ceil(items.length / 10);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="ins-cols" role="img" aria-label="Column chart">
      {[0.5, 1].map((g) => <line key={g} x1={pad} x2={W} y1={H - 16 - g * (H - 34)} y2={H - 16 - g * (H - 34)} stroke="rgba(255,255,255,0.07)" />)}
      {items.map((it, i) => {
        const h = (it.value / max) * (H - 34);
        const x = pad + i * bw + bw * 0.15;
        return (
          <g key={it.label + i}>
            <rect x={x} y={H - 16 - h} width={bw * 0.7} height={Math.max(h, it.value > 0 ? 1.5 : 0)} rx="2" fill={colorOf(it, i)}><title>{`${it.label}: ${fmt(it.value)}`}</title></rect>
            {it.value > 0 && items.length <= 12 && <text x={x + bw * 0.35} y={H - 19 - h} textAnchor="middle" className="ins-val">{fmt(it.value)}</text>}
            {i % every === 0 && <text x={x + bw * 0.35} y={H - 4} textAnchor="middle" className="ins-axis">{short(it.label, 8)}</text>}
          </g>
        );
      })}
      <text x="0" y="12" className="ins-axis">{fmt(max)}</text>
    </svg>
  );
}

function Stacked({ chart }: { chart: Extract<Chart, { kind: "stacked" }> }) {
  const W = 320, H = 130, pad = 18;
  const totals = chart.items.map((i) => i.values.reduce((a, b) => a + b, 0));
  const max = Math.max(1, ...totals);
  const bw = (W - pad) / Math.max(1, chart.items.length);
  const every = Math.ceil(chart.items.length / 10);
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="ins-cols" role="img" aria-label="Stacked column chart">
        {[0.5, 1].map((g) => <line key={g} x1={pad} x2={W} y1={H - 16 - g * (H - 34)} y2={H - 16 - g * (H - 34)} stroke="rgba(255,255,255,0.07)" />)}
        {chart.items.map((it, i) => {
          let y = H - 16;
          const x = pad + i * bw + bw * 0.12;
          return (
            <g key={it.label + i}>
              {it.values.map((v, s) => { const h = (v / max) * (H - 34); y -= h; return h > 0 ? <rect key={s} x={x} y={y} width={bw * 0.76} height={h} fill={chart.series[s].color}><title>{`${it.label} · ${chart.series[s].name}: ${fmt(v)}`}</title></rect> : null; })}
              {i % every === 0 && <text x={x + bw * 0.38} y={H - 4} textAnchor="middle" className="ins-axis">{short(it.label, 8)}</text>}
            </g>
          );
        })}
        <text x="0" y="12" className="ins-axis">{fmt(max)}</text>
      </svg>
      <div className="gd-legend">{chart.series.map((s) => <span key={s.name}><i style={{ background: s.color }} />{s.name}</span>)}</div>
    </div>
  );
}

function ChartCard({ chart }: { chart: Chart }) {
  return (
    <div className={`ins-card ins-k-${chart.kind}`}>
      <small>{chart.title}</small>
      {chart.kind === "donut" && <Donut items={chart.items} />}
      {chart.kind === "bars" && <Bars items={chart.items} />}
      {chart.kind === "columns" && <Columns items={chart.items} />}
      {chart.kind === "stacked" && <Stacked chart={chart} />}
      {chart.note && <em className="ins-note">{chart.note}</em>}
    </div>
  );
}

/** A grid of charts for one topic, fetched from /api/insights. Renders nothing while loading or when there is nothing to draw. */
export default function Insights({ topic, title = "Insights", limit }: { topic: string; title?: string; limit?: number }) {
  const [data, setData] = useState<{ charts: Chart[]; note?: string } | null>(null);
  useEffect(() => {
    let live = true;
    setData(null);
    fetch(`/api/insights?topic=${encodeURIComponent(topic)}`, { cache: "no-store" }).then((r) => r.json()).then((b) => live && setData(Array.isArray(b.charts) ? b : { charts: [], note: b.error })).catch(() => live && setData({ charts: [] }));
    return () => { live = false; };
  }, [topic]);
  if (!data) return <div className="ins-wrap"><small className="ins-head">{title}</small><p className="pv-empty">Loading charts…</p></div>;
  if (data.charts.length === 0) return data.note ? <div className="ins-wrap"><small className="ins-head">{title}</small><p className="pv-empty">{data.note}</p></div> : null;
  const charts = limit ? data.charts.slice(0, limit) : data.charts;
  return (
    <div className="ins-wrap">
      <small className="ins-head">{title}</small>
      <div className="ins-grid">{charts.map((c) => <ChartCard key={c.id} chart={c} />)}</div>
    </div>
  );
}
