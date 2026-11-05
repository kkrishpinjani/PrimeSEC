import { useMemo } from "react";

export type DiagramPath = { nodes: { type: string; id: string; name: string }[]; relationships: string[] };

type Node = { key: string; type: string; name: string; col: number; row: number };
type Edge = { from: string; to: string; label: string };

const COL_W = 300;
const ROW_H = 54;
const NODE_W = 210;
const NODE_H = 30;
const PAD = 16;

const TONES: Record<string, string> = {
  Asset: "#5eead4",
  Vulnerability: "#fb7185",
  Software: "#a5b4fc",
  Service: "#fcd34d",
  Technique: "#fdba74",
  Indicator: "#f0abfc"
};
const toneOf = (type: string) => TONES[type] ?? "#7fa39f";
/** Long ids (scanner OIDs) are told apart by their end, so keep the tail; ordinary names keep their start. */
const clip = (s: string, n: number) => {
  if (s.length <= n) return s;
  return /^[\w.-]+$/.test(s) && s.includes(".") ? `…${s.slice(-(n - 1))}` : `${s.slice(0, n - 1)}…`;
};

/** Lay paths out left to right: a node sits in the column of the step it first appears at. */
export function layout(paths: DiagramPath[]): { nodes: Node[]; edges: Edge[]; cols: number; rows: number } {
  const nodes = new Map<string, Node>();
  const edges = new Map<string, Edge>();
  const perCol: number[] = [];
  for (const p of paths) {
    p.nodes.forEach((n, i) => {
      const key = `${n.type}/${n.id}`;
      if (!nodes.has(key)) {
        const row = perCol[i] ?? 0;
        perCol[i] = row + 1;
        nodes.set(key, { key, type: n.type, name: n.name || n.id, col: i, row });
      }
      if (i > 0) {
        const from = `${p.nodes[i - 1].type}/${p.nodes[i - 1].id}`;
        const label = p.relationships[i - 1] ?? "";
        edges.set(`${from}>${key}>${label}`, { from, to: key, label });
      }
    });
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()], cols: perCol.length, rows: Math.max(1, ...perCol) };
}

/** A small, dependency-free picture of how an asset connects to what is around it. */
export default function GraphDiagram({ paths, label }: { paths: DiagramPath[]; label: string }) {
  const g = useMemo(() => layout(paths), [paths]);
  if (g.nodes.length === 0) return null;
  const width = PAD * 2 + (g.cols - 1) * COL_W + NODE_W;
  const height = PAD * 2 + (g.rows - 1) * ROW_H + NODE_H + 12;
  const at = (n: Node) => ({ x: PAD + n.col * COL_W, y: PAD + 12 + n.row * ROW_H });
  const byKey = new Map(g.nodes.map((n) => [n.key, n]));
  const types = [...new Set(g.nodes.map((n) => n.type))];
  // name the relationship once per gap between columns, not on every line
  const gapLabels = [...new Set(g.edges.map((e) => byKey.get(e.from)!.col))].map((col) => ({
    col,
    text: [...new Set(g.edges.filter((e) => byKey.get(e.from)!.col === col && e.label).map((e) => e.label))].map((t) => clip(t, 24)).join(" / ")
  })).filter((l) => l.text);

  return (
    <div className="gd-wrap">
      <svg className="gd-svg" viewBox={`0 0 ${width} ${height}`} width={width} height={height} role="img" aria-label={label}>
        {g.edges.map((e, i) => {
          const a = byKey.get(e.from)!, b = byKey.get(e.to)!;
          const p = at(a), q = at(b);
          const x1 = p.x + NODE_W, y1 = p.y + NODE_H / 2, x2 = q.x, y2 = q.y + NODE_H / 2;
          const mx = (x1 + x2) / 2;
          return <path key={i} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none" stroke="rgba(255,255,255,0.28)" strokeWidth="1.4" />;
        })}
        {gapLabels.map((l) => <text key={l.col} x={PAD + l.col * COL_W + NODE_W + (COL_W - NODE_W) / 2} y={PAD - 4} textAnchor="middle" className="gd-edge">{l.text}</text>)}
        {g.nodes.map((n) => {
          const { x, y } = at(n);
          const tone = toneOf(n.type);
          return (
            <g key={n.key}>
              <title>{`${n.type}: ${n.name}`}</title>
              <rect x={x} y={y} width={NODE_W} height={NODE_H} rx="8" fill="rgba(0,0,0,0.4)" stroke={tone} strokeWidth="1.3" />
              <text x={x + 10} y={y + NODE_H / 2 + 4} className="gd-node" fill="#ecfdfa">{clip(n.name, 28)}</text>
            </g>
          );
        })}
      </svg>
      <div className="gd-legend">
        {types.map((t) => <span key={t}><i style={{ background: toneOf(t) }} />{t}</span>)}
      </div>
    </div>
  );
}
