/**
 * Chart data for the "Insights" panels shown on most pages. Every function returns plain chart descriptions (donut, bars, columns,
 * stacked columns) computed from what the platform already holds: Wazuh and OpenCTI through their existing read-only adapters,
 * and PrimeSEC's own stores. Nothing here writes anything or calls a platform with anything but a read.
 */
import { listWazuhAgents, openCtiConfigured, openCtiRequest, wazuhApiRequest, wazuhIndexerSearch, wazuhIndexerReady, wazuhApiConfigured, wazuhSafeError } from "./integrations.ts";
import { browse, type Deps } from "./opencti.ts";
import { readFindings } from "./findings.ts";
import { readAssets, hostKey } from "./assets.ts";
import { rankFindings } from "./risk.ts";
import { readSnapshots } from "./reports.ts";
import { readScopes, getVaptOverview } from "./vapt.ts";
import { readCases } from "./cases.ts";
import { readResponse } from "./response.ts";
import { readInventory, CLOSED_STATUSES } from "./inventory.ts";
import { listRuns } from "./sync.ts";
import { readState } from "./agentsec.ts";
import { readAssessments } from "./sap.ts";

export type Item = { label: string; value: number; color?: string };
export type Chart =
  | { id: string; title: string; note?: string; kind: "donut" | "bars" | "columns"; items: Item[] }
  | { id: string; title: string; note?: string; kind: "stacked"; series: { name: string; color: string }[]; items: { label: string; values: number[] }[] };
export type Insights = { topic: string; charts: Chart[]; note?: string };

export const TOPICS = ["alerts", "vulns", "wazuh-agents", "wazuh-rules", "wazuh-mitre", "intel", "findings", "risk", "vapt", "cases", "response", "inventory", "sync", "agentsec", "sap"] as const;

const SEV: Record<string, string> = { critical: "#fb7185", high: "#fb923c", medium: "#fbbf24", low: "#5eead4", info: "#7dd3fc", unknown: "#64748b", unrated: "#64748b" };
const PALETTE = ["#5eead4", "#7dd3fc", "#a5b4fc", "#f0abfc", "#fbbf24", "#fb923c", "#86efac", "#f87171", "#60a5fa"];
const cap = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s);
const sevColor = (label: string) => SEV[label.toLowerCase()];

function tally(values: (string | null | undefined)[], top = 0, colorBySeverity = false): Item[] {
  const m = new Map<string, number>();
  for (const v of values) { const k = (v ?? "").toString().trim() || "Unknown"; m.set(k, (m.get(k) ?? 0) + 1); }
  let rows = [...m.entries()].sort((a, b) => b[1] - a[1]);
  if (top && rows.length > top) { const rest = rows.slice(top).reduce((s, [, n]) => s + n, 0); rows = [...rows.slice(0, top), ["Other", rest]]; }
  return rows.map(([label, value], i) => ({ label, value, color: colorBySeverity ? sevColor(label) ?? PALETTE[i % PALETTE.length] : undefined }));
}
const bucketItems = (labels: string[], counts: number[], colors?: string[]): Item[] => labels.map((label, i) => ({ label, value: counts[i] ?? 0, color: colors?.[i] }));
const day = (iso: string) => new Date(iso).toISOString().slice(5, 10);
const daysBack = (n: number) => Array.from({ length: n }, (_, i) => new Date(Date.now() - (n - 1 - i) * 86_400_000).toISOString().slice(0, 10));
const nonEmpty = (c: Chart) => (c.kind === "stacked" ? c.items.some((i) => i.values.some((v) => v > 0)) : c.items.some((i) => i.value > 0));

/* ------------------------------------------ Wazuh indexer ------------------------------------------ */

const buckets = (agg: any): any[] => (Array.isArray(agg?.buckets) ? agg.buckets : []);
const terms = (agg: any, color?: boolean): Item[] => buckets(agg).map((b, i) => ({ label: String(b.key_as_string ?? b.key), value: Number(b.doc_count ?? 0), color: color ? sevColor(String(b.key)) ?? PALETTE[i % PALETTE.length] : undefined }));

async function alertCharts(): Promise<Chart[]> {
  const index = process.env.WAZUH_ALERT_INDEX_PATTERN || "wazuh-alerts-4.x-*";
  const body = await wazuhIndexerSearch(index, {
    size: 0, query: { range: { timestamp: { gte: "now-24h" } } },
    aggs: {
      ins_hour: { date_histogram: { field: "timestamp", fixed_interval: "1h", min_doc_count: 0, extended_bounds: { min: "now-24h", max: "now" } }, aggs: { ins_lvl: { range: { field: "rule.level", ranges: [{ key: "info", to: 4 }, { key: "low", from: 4, to: 7 }, { key: "medium", from: 7, to: 12 }, { key: "high", from: 12 }] } } } },
      ins_rule: { terms: { field: "rule.description", size: 8 } }, ins_agent: { terms: { field: "agent.name", size: 8 } },
      ins_tactic: { terms: { field: "rule.mitre.tactic", size: 8 } }, ins_group: { terms: { field: "rule.groups", size: 8 } }, ins_country: { terms: { field: "GeoLocation.country_name", size: 8 } }
    }
  });
  const a = body?.aggregations ?? {};
  const hours = buckets(a.ins_hour).slice(-24);
  const keys = ["info", "low", "medium", "high"];
  const lvl = (h: any, k: string) => Number(buckets(h.ins_lvl).find((b) => b.key === k)?.doc_count ?? 0);
  const totals = keys.map((k) => hours.reduce((s, h) => s + lvl(h, k), 0));
  return [
    { id: "hour", title: "Alerts per hour by severity (24 h)", kind: "stacked", series: keys.map((k) => ({ name: cap(k), color: SEV[k] })), items: hours.map((h) => ({ label: `${String(new Date(Number(h.key)).getHours()).padStart(2, "0")}h`, values: keys.map((k) => lvl(h, k)) })) },
    { id: "sev", title: "Severity mix", kind: "donut", items: keys.map((k, i) => ({ label: cap(k), value: totals[i], color: SEV[k] })).reverse() },
    { id: "rule", title: "Top detection rules", kind: "bars", items: terms(a.ins_rule) },
    { id: "agent", title: "Noisiest endpoints", kind: "bars", items: terms(a.ins_agent) },
    { id: "tactic", title: "MITRE ATT&CK tactics seen", kind: "bars", items: terms(a.ins_tactic) },
    { id: "group", title: "Rule groups", kind: "donut", items: terms(a.ins_group) },
    { id: "country", title: "Attack sources by country", kind: "bars", items: terms(a.ins_country) }
  ];
}

async function vulnCharts(): Promise<Chart[]> {
  const index = process.env.WAZUH_VULN_INDEX_PATTERN || "wazuh-states-vulnerabilities-*";
  const body = await wazuhIndexerSearch(index, {
    size: 0, query: { match_all: {} },
    aggs: {
      ins_sev: { terms: { field: "vulnerability.severity", size: 6 } }, ins_pkg: { terms: { field: "package.name", size: 8 } }, ins_host: { terms: { field: "agent.name", size: 8 } }, ins_cve: { terms: { field: "vulnerability.id", size: 8 } },
      ins_score: { range: { field: "vulnerability.score.base", ranges: [{ key: "0-3.9", to: 4 }, { key: "4-6.9", from: 4, to: 7 }, { key: "7-8.9", from: 7, to: 9 }, { key: "9-10", from: 9 }] } }
    }
  });
  const a = body?.aggregations ?? {};
  const order = ["Critical", "High", "Medium", "Low"];
  const sev = terms(a.ins_sev, true).sort((x, y) => order.indexOf(x.label) - order.indexOf(y.label));
  return [
    { id: "sev", title: "Open vulnerabilities by severity", kind: "donut", items: sev },
    { id: "score", title: "CVSS score distribution", kind: "columns", items: terms(a.ins_score).map((i, n) => ({ ...i, color: [SEV.low, SEV.medium, SEV.high, SEV.critical][n] })) },
    { id: "host", title: "Most exposed hosts", kind: "bars", items: terms(a.ins_host) },
    { id: "pkg", title: "Most affected packages", kind: "bars", items: terms(a.ins_pkg) },
    { id: "cve", title: "Most widespread CVEs", kind: "bars", items: terms(a.ins_cve) }
  ];
}

/* --------------------------------------------- Wazuh API --------------------------------------------- */

const osFamily = (os: string | null) => { const s = os ?? ""; return /windows/i.test(s) ? "Windows" : /mac/i.test(s) ? "macOS" : /ubuntu/i.test(s) ? "Ubuntu" : /debian/i.test(s) ? "Debian" : /red hat|rhel/i.test(s) ? "Red Hat" : /oracle/i.test(s) ? "Oracle Linux" : /amazon/i.test(s) ? "Amazon Linux" : s ? "Other" : "Unknown"; };

async function agentCharts(): Promise<Chart[]> {
  const { items } = await listWazuhAgents();
  const statusColor: Record<string, string> = { active: "#5eead4", disconnected: "#fb923c", never_connected: "#64748b", pending: "#fbbf24" };
  return [
    { id: "status", title: "Agent status", kind: "donut", items: tally(items.map((a) => a.status)).map((i) => ({ ...i, label: i.label.replace("_", " "), color: statusColor[i.label] })) },
    { id: "os", title: "Operating systems", kind: "bars", items: tally(items.map((a) => osFamily(a.os))) },
    { id: "ver", title: "Agent versions", kind: "donut", items: tally(items.map((a) => (a.version ?? "unknown").replace("Wazuh ", ""))) },
    { id: "grp", title: "Agents per group", kind: "bars", items: tally(items.flatMap((a) => a.groups.filter((g) => g !== "default")), 8) }
  ];
}

const apiItems = async (path: string): Promise<any[]> => (await wazuhApiRequest(path))?.data?.affected_items ?? [];
async function rulesCharts(): Promise<Chart[]> {
  const rules = await apiItems("/rules?limit=500&sort=id");
  const levels = Array.from({ length: 16 }, (_, i) => rules.filter((r) => Number(r.level) === i).length);
  return [
    { id: "lvl", title: "Rules by level", kind: "columns", items: levels.map((v, i) => ({ label: String(i), value: v, color: i >= 12 ? SEV.critical : i >= 7 ? SEV.medium : i >= 4 ? SEV.low : SEV.info })) },
    { id: "grp", title: "Rules by group", kind: "bars", items: tally(rules.flatMap((r) => r.groups ?? []), 8) },
    { id: "file", title: "Rule files", kind: "donut", items: tally(rules.map((r) => r.filename), 6) }
  ];
}
async function mitreCharts(): Promise<Chart[]> {
  const t = await apiItems("/mitre/techniques?limit=500");
  const g = await apiItems("/mitre/groups?limit=500");
  return [
    { id: "tactic", title: "Techniques per tactic", kind: "bars", items: tally(t.flatMap((x) => (Array.isArray(x.tactics) ? x.tactics : [])), 10) },
    { id: "plat", title: "Platforms covered", kind: "donut", items: tally(t.flatMap((x) => (Array.isArray(x.platforms) ? x.platforms : []))) },
    { id: "grp", title: "Known groups and their aliases", kind: "bars", items: g.map((x) => ({ label: String(x.name), value: Array.isArray(x.aliases) ? x.aliases.length + 1 : 1 })).sort((a, b) => b.value - a.value).slice(0, 8) }
  ];
}

/* --------------------------------------------- OpenCTI --------------------------------------------- */

const ctiDeps = (): Deps => ({ query: openCtiRequest, configured: openCtiConfigured, safeError: wazuhSafeError, env: process.env });
async function intelCharts(): Promise<Chart[]> {
  const deps = ctiDeps();
  const [ind, vul, mal, rep] = await Promise.allSettled([browse("indicators", { first: 100 }, deps), browse("vulnerabilities", { first: 100 }, deps), browse("malwares", { first: 100 }, deps), browse("reports", { first: 100 }, deps)]);
  const charts: Chart[] = [];
  if (ind.status === "fulfilled") {
    const items = ind.value.items;
    const open = items.filter((i) => !i.restricted);
    const kind = (p: string, t: string) => (/^\[ipv4|^\[ipv6/.test(p) ? "IP address" : /^\[domain/.test(p) ? "Domain" : /^\[url/.test(p) ? "URL" : /^\[file/.test(p) ? "File hash" : /^\[email/.test(p) ? "Email" : t === "yara" || t === "sigma" ? t.toUpperCase() : "Other");
    charts.push({ id: "type", title: "Indicators by type", kind: "donut", items: tally(open.map((i) => kind(String(i.fields.pattern ?? ""), String(i.fields.pattern_type ?? "")))) });
    const sc = open.map((i) => Number(i.fields.x_opencti_score)).filter(Number.isFinite);
    charts.push({ id: "score", title: "Indicator confidence", kind: "columns", items: bucketItems(["<40", "40-59", "60-79", "80+"], [sc.filter((s) => s < 40).length, sc.filter((s) => s >= 40 && s < 60).length, sc.filter((s) => s >= 60 && s < 80).length, sc.filter((s) => s >= 80).length], [SEV.info, SEV.low, SEV.medium, SEV.high]) });
    charts.push({ id: "mark", title: "Handling markings (TLP)", note: ind.value.markingPolicy ? `Shown in full: ${ind.value.markingPolicy.join(", ").toUpperCase()}` : undefined, kind: "donut", items: tally(items.map((i) => i.markings[0] ?? "No marking")).map((i) => ({ ...i, color: ({ "TLP:CLEAR": "#e2e8f0", "TLP:GREEN": "#86efac", "TLP:AMBER": "#fbbf24", "TLP:RED": "#fb7185" } as Record<string, string>)[i.label.toUpperCase()] })) });
    charts.push({ id: "days", title: "New indicators per day (last 10 days)", kind: "columns", items: daysBack(10).map((d) => ({ label: d.slice(5), value: open.filter((i) => String(i.fields.created ?? "").startsWith(d)).length })) });
    charts.push({ id: "labels", title: "Top indicator labels", kind: "bars", items: tally(open.flatMap((i) => i.labels), 8) });
  }
  if (vul.status === "fulfilled") {
    const open = vul.value.items.filter((i) => !i.restricted);
    const cv = open.map((i) => Number(i.fields.x_opencti_cvss_base_score)).filter(Number.isFinite);
    charts.push({ id: "kev", title: "Vulnerabilities exploited in the wild (CISA KEV)", kind: "donut", items: [{ label: "Known exploited", value: open.filter((i) => i.fields.x_opencti_cisa_kev === true).length, color: SEV.critical }, { label: "Not listed", value: open.filter((i) => i.fields.x_opencti_cisa_kev !== true).length, color: SEV.low }] });
    charts.push({ id: "cvss", title: "Vulnerability CVSS", kind: "columns", items: bucketItems(["<4", "4-6.9", "7-8.9", "9+"], [cv.filter((s) => s < 4).length, cv.filter((s) => s >= 4 && s < 7).length, cv.filter((s) => s >= 7 && s < 9).length, cv.filter((s) => s >= 9).length], [SEV.low, SEV.medium, SEV.high, SEV.critical]) });
  }
  if (mal.status === "fulfilled") charts.push({ id: "mal", title: "Malware by type", kind: "bars", items: tally(mal.value.items.filter((i) => !i.restricted).flatMap((i) => (Array.isArray(i.fields.malware_types) ? i.fields.malware_types : [])), 8) });
  if (rep.status === "fulfilled") {
    const dates = rep.value.items.filter((i) => !i.restricted).map((i) => Date.parse(String(i.fields.published ?? ""))).filter(Number.isFinite);
    const weeks = Array.from({ length: 8 }, (_, i) => 7 - i);
    charts.push({ id: "rep", title: "Reports published per week", kind: "columns", items: weeks.map((w) => ({ label: w === 0 ? "now" : `-${w}w`, value: dates.filter((d) => Math.floor((Date.now() - d) / (7 * 86_400_000)) === w).length })) });
  }
  return charts;
}

/* ----------------------------------------- PrimeSEC's own stores ----------------------------------------- */

const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
async function findingCharts(): Promise<Chart[]> {
  const f = await readFindings();
  const open = f.filter((x) => !["Resolved", "Closed"].includes(x.remediationStatus));
  const hosts = tally(open.map((x) => x.host), 8).filter((h) => h.label !== "Other").map((h) => h.label);
  const sevSeries = SEV_ORDER.slice(0, 4);
  const weeks = [4, 3, 2, 1, 0];
  return [
    { id: "sev", title: "Findings by severity", kind: "donut", items: SEV_ORDER.map((s) => ({ label: s, value: f.filter((x) => x.severity === s).length, color: sevColor(s) })) },
    { id: "status", title: "Remediation status", kind: "bars", items: tally(f.map((x) => x.remediationStatus)) },
    { id: "host", title: "Open findings per host", kind: "stacked", series: sevSeries.map((s) => ({ name: s, color: sevColor(s)! })), items: hosts.map((h) => ({ label: h, values: sevSeries.map((s) => open.filter((x) => x.host === h && x.severity === s).length) })) },
    { id: "exploit", title: "Exploit evidence", kind: "donut", items: tally(f.map((x) => x.exploitEvidence)).map((i) => ({ ...i, color: ({ "Exploited in the wild": SEV.critical, "Public exploit": SEV.high, "None known": SEV.low, Unknown: SEV.unknown } as Record<string, string>)[i.label] })) },
    { id: "owner", title: "Work by owner", kind: "bars", items: tally(open.map((x) => x.owner || "Unassigned"), 8) },
    { id: "weeks", title: "New findings per week", kind: "columns", items: weeks.map((w) => ({ label: w === 0 ? "this week" : `-${w}w`, value: f.filter((x) => Math.floor((Date.now() - Date.parse(x.firstImportedAt)) / (7 * 86_400_000)) === w).length })) }
  ];
}

async function riskCharts(): Promise<Chart[]> {
  const [f, assets] = await Promise.all([readFindings(), readAssets()]);
  const ranked = rankFindings(f, new Map(assets.map((a) => [hostKey(a.host), a])));
  const scores = ranked.map((r) => r.risk.score).filter((s): s is number => s !== null);
  const dec = Array.from({ length: 10 }, (_, i) => scores.filter((s) => (i === 9 ? s >= 90 : s >= i * 10 && s < i * 10 + 10)).length);
  const byHost = new Map<string, number>();
  for (const r of ranked) byHost.set(r.host, Math.max(byHost.get(r.host) ?? 0, r.risk.score ?? 0));
  const bandColor: Record<string, string> = { Critical: SEV.critical, High: SEV.high, Medium: SEV.medium, Low: SEV.low, Unrated: SEV.unrated };
  return [
    { id: "band", title: "Priority bands", kind: "donut", items: tally(ranked.map((r) => r.risk.band)).map((i) => ({ ...i, color: bandColor[i.label] })) },
    { id: "dist", title: "Risk score distribution", kind: "columns", items: dec.map((v, i) => ({ label: `${i * 10}`, value: v, color: i >= 8 ? SEV.critical : i >= 6 ? SEV.high : i >= 3 ? SEV.medium : SEV.low })) },
    { id: "host", title: "Highest risk by host", kind: "bars", items: [...byHost.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([label, value]) => ({ label, value: Math.round(value) })) },
    { id: "crit", title: "Host criticality", kind: "donut", items: tally(ranked.map((r) => r.asset.criticality)) },
    { id: "expo", title: "Host exposure", kind: "donut", items: tally(ranked.map((r) => r.asset.exposure)) }
  ];
}

async function vaptCharts(): Promise<Chart[]> {
  const [overview, scopes, snaps, f] = await Promise.all([getVaptOverview(), readScopes(), readSnapshots(), readFindings()]);
  const sevSeries = SEV_ORDER.slice(0, 4);
  const ordered = [...snaps].sort((a, b) => (a.reportTime ?? a.capturedAt).localeCompare(b.reportTime ?? b.capturedAt)).slice(-8);
  const scopeState = (s: (typeof scopes)[number]) => (s.status === "Revoked" ? "Revoked" : Date.parse(s.expiresAt) < Date.now() ? "Expired" : "Active");
  return [
    { id: "trend", title: "Findings per scan report", kind: "stacked", series: sevSeries.map((s) => ({ name: s, color: sevColor(s)! })), items: ordered.map((r) => ({ label: day(r.reportTime ?? r.capturedAt), values: sevSeries.map((s) => r.findings.filter((x) => x.severity === s).length) })) },
    { id: "tasks", title: "Scan tasks by status", kind: "donut", items: tally(overview.tasks.map((t) => t.status)) },
    { id: "scopes", title: "Scan scopes", kind: "donut", items: tally(scopes.map(scopeState)).map((i) => ({ ...i, color: ({ Active: SEV.low, Expired: SEV.medium, Revoked: SEV.critical } as Record<string, string>)[i.label] })) },
    { id: "ports", title: "Most affected services", kind: "bars", items: tally(f.filter((x) => x.severity !== "Info").map((x) => x.port), 8) }
  ];
}

async function caseCharts(): Promise<Chart[]> {
  const cases = await readCases();
  const days = daysBack(7);
  const sevs = ["critical", "high", "medium", "low"];
  const statusColor: Record<string, string> = { new: "#7dd3fc", triaged: "#a5b4fc", investigating: "#fbbf24", contained: "#fb923c", resolved: "#5eead4", closed: "#64748b" };
  return [
    { id: "status", title: "Cases by status", kind: "donut", items: ["new", "triaged", "investigating", "contained", "resolved", "closed"].map((s) => ({ label: cap(s), value: cases.filter((c) => c.status === s).length, color: statusColor[s] })) },
    { id: "sev", title: "Cases by severity", kind: "donut", items: sevs.map((s) => ({ label: cap(s), value: cases.filter((c) => c.severity === s).length, color: SEV[s] })) },
    { id: "owner", title: "Workload by owner", kind: "bars", items: tally(cases.filter((c) => !["resolved", "closed"].includes(c.status)).map((c) => c.owner ?? "Unassigned"), 8) },
    { id: "days", title: "Cases opened per day (7 days)", kind: "stacked", series: sevs.map((s) => ({ name: cap(s), color: SEV[s] })), items: days.map((d) => ({ label: d.slice(5), values: sevs.map((s) => cases.filter((c) => c.severity === s && c.createdAt.startsWith(d)).length) })) },
    { id: "prio", title: "Priority score distribution", kind: "columns", items: bucketItems(["0-24", "25-49", "50-74", "75-100"], [0, 25, 50, 75].map((lo, i, a) => cases.filter((c) => c.priorityScore >= lo && c.priorityScore < (a[i + 1] ?? 101)).length), [SEV.low, SEV.medium, SEV.high, SEV.critical]) },
    { id: "ev", title: "Evidence collected per case", kind: "bars", items: cases.map((c) => ({ label: c.caseKey, value: c.evidence.length })).filter((x) => x.value > 0).sort((a, b) => b.value - a.value).slice(0, 8) }
  ];
}

async function responseCharts(): Promise<Chart[]> {
  const { proposals, executions } = await readResponse();
  const st: Record<string, string> = { proposed: "#7dd3fc", approved: "#a5b4fc", rejected: "#fb7185", executing: "#fbbf24", executed: "#5eead4", execution_failed: "#f87171", cancelled: "#64748b" };
  const ex: Record<string, string> = { executed: "#a5b4fc", verified: "#5eead4", failed: "#f87171", verification_failed: "#fb923c", rolled_back: "#fbbf24", rollback_failed: "#fb7185", executing: "#7dd3fc" };
  return [
    { id: "prop", title: "Proposals by status", kind: "donut", items: tally(proposals.map((p) => p.status)).map((i) => ({ ...i, color: st[i.label] })) },
    { id: "action", title: "Requested actions", kind: "bars", items: tally(proposals.map((p) => p.actionType)) },
    { id: "exec", title: "Executions by outcome", kind: "donut", items: tally(executions.map((e) => e.status)).map((i) => ({ ...i, label: i.label.replace("_", " "), color: ex[i.label.replace(" ", "_")] })) },
    { id: "who", title: "Proposals per analyst", kind: "bars", items: tally(proposals.map((p) => p.proposedBy), 8) },
    { id: "rev", title: "Reviews per approver", kind: "bars", items: tally(proposals.filter((p) => p.reviewedBy).map((p) => p.reviewedBy), 8) }
  ];
}

async function inventoryCharts(): Promise<Chart[]> {
  const inv = await readInventory();
  const open = inv.vulns.filter((v) => !CLOSED_STATUSES.has(v.status));
  const risk: Record<string, string> = { critical: SEV.critical, high: SEV.high, medium: SEV.medium, low: SEV.low };
  return [
    { id: "risk", title: "Assets by exposure level", kind: "donut", items: ["critical", "high", "medium", "low"].map((l) => ({ label: cap(l), value: inv.assets.filter((a) => a.riskLevel === l).length, color: risk[l] })) },
    { id: "type", title: "Asset types", kind: "bars", items: tally(inv.assets.map((a) => a.assetType)) },
    { id: "src", title: "Assets per source", kind: "bars", items: tally(inv.assets.flatMap((a) => Object.keys(a.sources))) },
    { id: "bu", title: "Assets per business unit", kind: "bars", items: tally(inv.assets.map((a) => a.businessUnit ?? "Unassigned"), 8) },
    { id: "env", title: "Environment", kind: "donut", items: tally(inv.assets.map((a) => a.environment ?? "Unknown")) },
    { id: "net", title: "Internet-facing", kind: "donut", items: [{ label: "Internet-facing", value: inv.assets.filter((a) => a.internetFacing).length, color: SEV.high }, { label: "Internal", value: inv.assets.filter((a) => !a.internetFacing).length, color: SEV.low }] },
    { id: "vuln", title: "Open vulnerabilities by severity", kind: "donut", items: ["critical", "high", "medium", "low", "info", "unknown"].map((s) => ({ label: cap(s), value: open.filter((v) => v.severity.toLowerCase() === s).length, color: SEV[s] })) }
  ];
}

async function syncCharts(): Promise<Chart[]> {
  const runs = await listRuns({ limit: 200 });
  const days = daysBack(7);
  const states = ["completed", "failed", "running"];
  const color: Record<string, string> = { completed: SEV.low, failed: SEV.critical, running: SEV.info };
  const seen = new Map<string, number>();
  for (const r of runs) seen.set(r.source, (seen.get(r.source) ?? 0) + r.recordsIngested);
  return [
    { id: "days", title: "Sync runs per day", kind: "stacked", series: states.map((s) => ({ name: cap(s), color: color[s] })), items: days.map((d) => ({ label: d.slice(5), values: states.map((s) => runs.filter((r) => r.status === s && r.startedAt.startsWith(d)).length) })) },
    { id: "src", title: "Runs by source", kind: "donut", items: tally(runs.map((r) => r.source)) },
    { id: "rec", title: "Records ingested by source", kind: "bars", items: [...seen.entries()].map(([label, value]) => ({ label, value })) },
    { id: "who", title: "Triggered by", kind: "donut", items: tally(runs.map((r) => r.triggeredBy), 5) }
  ];
}

async function agentSecCharts(): Promise<Chart[]> {
  const s = await readState();
  const dec: Record<string, string> = { DENY: SEV.critical, REQUIRE_APPROVAL: SEV.medium, REVIEW: SEV.info, ALLOW: SEV.low };
  return [
    { id: "dec", title: "Flagged actions by decision", kind: "donut", items: tally(s.findings.map((f) => f.decision)).map((i) => ({ ...i, label: i.label.replace("_", " "), color: dec[i.label.replace(" ", "_")] })) },
    { id: "fw", title: "Agents by framework", kind: "bars", items: tally(s.agents.map((a) => a.framework)) },
    { id: "env", title: "Agents by environment", kind: "donut", items: tally(s.agents.map((a) => a.environment)) },
    { id: "priv", title: "Agent privilege level", kind: "donut", items: tally(s.agents.map((a) => a.privileges)).map((i) => ({ ...i, color: ({ high: SEV.critical, moderate: SEV.medium, low: SEV.low } as Record<string, string>)[i.label] })) },
    { id: "agent", title: "Most flagged agents", kind: "bars", items: tally(s.findings.flatMap((f) => Array(Math.max(1, f.count)).fill(f.agentName)), 8) },
    { id: "apr", title: "Approval requests", kind: "donut", items: tally(s.approvals.map((a) => a.status)).map((i) => ({ ...i, color: ({ pending: SEV.medium, approved: SEV.low, rejected: SEV.critical, expired: SEV.unknown, used: SEV.info } as Record<string, string>)[i.label] })) }
  ];
}

async function sapCharts(): Promise<Chart[]> {
  const a = await readAssessments();
  const all = a.flatMap((x) => x.findings);
  return [
    { id: "sev", title: "SAP findings by severity", kind: "donut", items: tally(all.map((f) => f.severity), 0, true) },
    { id: "cat", title: "By category", kind: "bars", items: tally(all.map((f) => f.category), 8) },
    { id: "top", title: "Most frequent findings", kind: "bars", items: tally(all.map((f) => f.title), 8) },
    { id: "sys", title: "Findings per system (latest assessment each)", kind: "columns", items: [...new Map([...a].sort((x, y) => x.createdAt.localeCompare(y.createdAt)).map((x) => [x.assetId, x.findings.length])).entries()].map(([label, value]) => ({ label, value })) }
  ];
}

/* ------------------------------------------------ entry ------------------------------------------------ */

export async function insights(topic: string): Promise<Insights> {
  let charts: Chart[] = [];
  let note: string | undefined;
  try {
    switch (topic) {
      case "alerts": if (!wazuhIndexerReady()) note = "Needs the Wazuh Indexer."; else charts = await alertCharts(); break;
      case "vulns": if (!wazuhIndexerReady()) note = "Needs the Wazuh Indexer."; else charts = await vulnCharts(); break;
      case "wazuh-agents": if (!wazuhApiConfigured()) note = "Needs the Wazuh Manager API."; else charts = await agentCharts(); break;
      case "wazuh-rules": if (!wazuhApiConfigured()) note = "Needs the Wazuh Manager API."; else charts = await rulesCharts(); break;
      case "wazuh-mitre": if (!wazuhApiConfigured()) note = "Needs the Wazuh Manager API."; else charts = await mitreCharts(); break;
      case "intel": if (!openCtiConfigured()) note = "Needs OpenCTI."; else charts = await intelCharts(); break;
      case "findings": charts = await findingCharts(); break;
      case "risk": charts = await riskCharts(); break;
      case "vapt": charts = await vaptCharts(); break;
      case "cases": charts = await caseCharts(); break;
      case "response": charts = await responseCharts(); break;
      case "inventory": charts = await inventoryCharts(); break;
      case "sync": charts = await syncCharts(); break;
      case "agentsec": charts = await agentSecCharts(); break;
      case "sap": charts = await sapCharts(); break;
      default: note = "Unknown topic.";
    }
  } catch (error) {
    note = "The charts could not be built: " + wazuhSafeError(error);
  }
  return { topic, charts: charts.filter(nonEmpty), note };
}
