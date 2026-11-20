#!/usr/bin/env node
/**
 * PrimeSEC demo integrations: a local FAKE Wazuh (Manager API + Indexer), OpenCTI (GraphQL) and Greenbone bridge, backed by a
 * rich synthetic dataset (scripts/demo/*): a fictional 53-agent enterprise, ~2,900 alerts per 24 h from 44 cities, planted
 * multi-step incidents, ~700 vulnerabilities, a 400-object threat-intelligence graph and four weeks of scan history.
 * Nothing here is real telemetry, nothing is scanned and nothing touches a network. Run with: npm run demo:integrations
 *
 * Endpoints (single port, default 9099):
 *   /wazuh   Wazuh Manager API    /indexer   Wazuh Indexer    /opencti   OpenCTI (graphql at /opencti/graphql)
 *   /greenbone   FAKE Greenbone bridge: scan names and findings are synthetic. POST /v1/assessments only records a demo task.
 */
const http = require("http");
const { AGENTS, publicAgent, byId, groups, summary, syscollectorOs, scaFor, syscheckFor, rootcheckFor } = require("./demo/fleet");
const ref = require("./demo/wazuh-ref");
const { alertDocs, VULNS } = require("./demo/wazuh-alerts");
const { COLLECTIONS, DETAIL } = require("./demo/cti-data");
const gb = require("./demo/greenbone-data");

const PORT = Number(process.env.DEMO_PORT || 9099);
const CREDS = {
  wazuh: { user: "demo-wazuh", pass: "demo-wazuh-pass" },
  indexer: { user: "demo-indexer", pass: "demo-indexer-pass" },
  openctiToken: "demo-opencti-token",
  greenboneToken: "demo-greenbone-bridge-token"
};
// Real Wazuh JWTs can be long (many RBAC roles). A long token here guards against any truncation of the raw token.
const WAZUH_JWT = "eyJ-demo." + "A".repeat(880) + ".sig";
const basic = (u, p) => "Basic " + Buffer.from(`${u}:${p}`).toString("base64");

/* ------------------------------------------------ helpers ------------------------------------------------ */
const getPath = (obj, path) => path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
const intParam = (v, d) => { const n = Number(v); return Number.isFinite(n) && n >= 0 ? Math.floor(n) : d; };
const page = (items, q) => { const offset = intParam(q.get("offset"), 0), limit = intParam(q.get("limit"), 500) || 500; return items.slice(offset, offset + limit); };
const wazuhItems = (items, total) => ({ data: { affected_items: items, total_affected_items: total ?? items.length, total_failed_items: 0, failed_items: [] }, message: "All selected information was returned", error: 0 });
const searchIn = (items, search, fields) => {
  if (!search) return items;
  const needle = search.toLowerCase();
  return items.filter((x) => fields.some((f) => String(getPath(x, f) ?? "").toLowerCase().includes(needle)));
};

/* ---------------------------------------------- Wazuh manager API ---------------------------------------------- */
function wazuhApi(pathname, q) {
  const parts = pathname.split("/").filter(Boolean); // after /wazuh
  const head = parts[0];
  if (pathname === "/agents/summary/status") return { data: summary(), error: 0 };
  if (head === "agents" && parts.length === 1) {
    let list = AGENTS.slice();
    const status = q.get("status");
    if (status) { const set = new Set(status.split(",")); list = list.filter((a) => set.has(a.status)); }
    const only = q.get("agents_list");
    if (only) { const set = new Set(only.split(",")); list = list.filter((a) => set.has(a.id)); }
    list = searchIn(list, q.get("search"), ["id", "name", "ip", "os.name", "version", "status"]);
    const sort = q.get("sort") || "id";
    if (sort === "-id") list.reverse();
    return wazuhItems(page(list, q).map(publicAgent), list.length);
  }
  if (pathname === "/manager/info") return wazuhItems([ref.MANAGER.info]);
  if (pathname === "/manager/status") return wazuhItems([ref.MANAGER.status]);
  if (pathname === "/manager/stats") return wazuhItems(ref.managerStats());
  if (pathname === "/cluster/status") return { data: { enabled: "yes", running: "yes" }, error: 0 };
  if (pathname === "/cluster/nodes") return wazuhItems(ref.MANAGER.nodes);
  if (head === "syscollector" && parts[2] === "os") { const a = byId.get(parts[1]); return wazuhItems(a ? [syscollectorOs(a)] : []); }
  if (head === "syscheck" || head === "rootcheck" || head === "sca") {
    const a = byId.get(parts[1]);
    if (!a) return wazuhItems([]);
    let list = head === "syscheck" ? syscheckFor(a) : head === "rootcheck" ? rootcheckFor(a) : scaFor(a);
    if (head === "syscheck" && q.get("file")) list = list.filter((x) => x.file === q.get("file"));
    return wazuhItems(page(list, q), list.length);
  }
  if (head === "rules") { const list = searchIn(ref.rulesList(), q.get("search"), ["id", "description", "groups", "filename", "mitre.id"]); return wazuhItems(page(list, q), list.length); }
  if (head === "decoders") { const list = searchIn(ref.decoders(), q.get("search"), ["name", "filename", "details.program_name"]); return wazuhItems(page(list, q), list.length); }
  if (head === "groups" && parts.length === 1) { const list = searchIn(groups(), q.get("search"), ["name"]); return wazuhItems(page(list, q), list.length); }
  if (head === "groups" && parts[2] === "agents") { const list = AGENTS.filter((a) => a.group.includes(parts[1])); return wazuhItems(page(list, q).map(publicAgent), list.length); }
  if (head === "mitre" && parts[1] === "techniques") { const list = searchIn(ref.techniques(), q.get("search"), ["external_id", "name", "description"]); return wazuhItems(page(list, q), list.length); }
  if (head === "mitre" && parts[1] === "groups") { const list = searchIn(ref.mitreGroups(), q.get("search"), ["external_id", "name", "description", "aliases"]); return wazuhItems(page(list, q), list.length); }
  return null;
}

/* ------------------------------------------------ Wazuh indexer ------------------------------------------------ */
/** Evaluates the small subset of the Elasticsearch query DSL the app uses. */
function matches(doc, query) {
  if (!query) return true;
  const [kind] = Object.keys(query);
  const arg = query[kind];
  switch (kind) {
    case "match_all": return true;
    case "range": { const [field] = Object.keys(arg); const c = arg[field]; const v = getPath(doc, field);
      if (field === "timestamp") { const t = Date.parse(v); const bound = (x) => (typeof x === "string" && x.startsWith("now") ? null : Date.parse(x)); const g = c.gte ? bound(c.gte) : null, l = c.lte ? bound(c.lte) : null; return (g === null || t >= g) && (l === null || t <= l); }
      return (c.gte === undefined || v >= c.gte) && (c.lte === undefined || v <= c.lte) && (c.gt === undefined || v > c.gt) && (c.lt === undefined || v < c.lt); }
    case "ids": return arg.values.includes(doc._id);
    case "term": { const [field] = Object.keys(arg); const want = arg[field]; return String(getPath(doc, field)) === String(want?.value ?? want); }
    case "terms": { const [field] = Object.keys(arg); return arg[field].map(String).includes(String(getPath(doc, field))); }
    case "simple_query_string": {
      const hay = `${doc.full_log || ""} ${doc.rule?.description || ""} ${doc.agent?.name || ""} ${JSON.stringify(doc.data || {})}`.toLowerCase();
      return String(arg.query).toLowerCase().split(/\s+/).filter(Boolean).every((t) => hay.includes(t));
    }
    case "bool": {
      const list = (x) => (x === undefined ? [] : Array.isArray(x) ? x : [x]);
      return list(arg.filter).every((c) => matches(doc, c)) && list(arg.must).every((c) => matches(doc, c)) && list(arg.must_not).every((c) => !matches(doc, c));
    }
    default: return true;
  }
}
const strip = ({ _min, _id, ...rest }) => rest;

/** Small generic aggregation engine for the app's "ins_" (insights) queries: terms, range and 1-hour date_histogram, with nested aggs. */
function runAggs(docs, spec) {
  const out = {};
  for (const [name, def] of Object.entries(spec || {})) {
    const sub = (group) => runAggs(group, def.aggs);
    if (def.terms) {
      const m = new Map();
      for (const d of docs) { const v = getPath(d, def.terms.field); for (const x of Array.isArray(v) ? v : v === undefined ? [] : [v]) { const k = String(x); (m.get(k) || m.set(k, []).get(k)).push(d); } }
      out[name] = { buckets: [...m.entries()].sort((a, b) => b[1].length - a[1].length).slice(0, def.terms.size || 10).map(([key, g]) => ({ key, doc_count: g.length, ...sub(g) })) };
    } else if (def.range) {
      out[name] = { buckets: def.range.ranges.map((r) => { const g = docs.filter((d) => { const v = Number(getPath(d, def.range.field)); return Number.isFinite(v) && (r.from === undefined || v >= r.from) && (r.to === undefined || v < r.to); }); return { key: r.key, from: r.from, to: r.to, doc_count: g.length, ...sub(g) }; }) };
    } else if (def.date_histogram) {
      const H = 3_600_000, now = Date.now(), end = Math.floor(now / H) * H;
      out[name] = { buckets: Array.from({ length: 24 }, (_, i) => { const start = end - (23 - i) * H; const g = docs.filter((d) => { const t = Date.parse(d.timestamp); return t >= start && t < start + H; }); return { key: start, key_as_string: new Date(start).toISOString(), doc_count: g.length, ...sub(g) }; }) };
    }
  }
  return out;
}
const insAggs = (docs, aggs) => runAggs(docs, Object.fromEntries(Object.entries(aggs || {}).filter(([k]) => k.startsWith("ins_"))));

function alertAggs(docs, aggs) {
  const out = {};
  const level = (d) => Number(d.rule.level);
  if (aggs.critical) out.critical = { doc_count: docs.filter((d) => level(d) >= 12).length };
  if (aggs.by_hour) {
    const buckets = Array.from({ length: 24 }, (_, i) => ({ key_as_string: new Date(Math.floor((Date.now() - (23 - i) * 3_600_000) / 3_600_000) * 3_600_000).toISOString(), doc_count: 0, high: { doc_count: 0 } }));
    for (const d of docs) { const h = Math.floor(d._min / 60); if (h > 23) continue; const b = buckets[23 - h]; b.doc_count++; if (level(d) >= 12) b.high.doc_count++; }
    out.by_hour = { buckets };
  }
  if (aggs.by_level) {
    const c = { info: 0, low: 0, medium: 0, high: 0 };
    for (const d of docs) c[level(d) >= 12 ? "high" : level(d) >= 7 ? "medium" : level(d) >= 4 ? "low" : "info"]++;
    out.by_level = { buckets: Object.entries(c).map(([key, doc_count]) => ({ key, doc_count })) };
  }
  if (aggs.top_src) {
    const m = new Map();
    for (const d of docs) { const ip = d.data?.srcip; if (!ip) continue; const e = m.get(ip) || { key: ip, doc_count: 0, max: 0, geo: d.GeoLocation }; e.doc_count++; e.max = Math.max(e.max, level(d)); if (!e.geo && d.GeoLocation) e.geo = d.GeoLocation; m.set(ip, e); }
    const size = aggs.top_src.terms?.size || 10;
    out.top_src = { buckets: [...m.values()].sort((a, b) => b.doc_count - a.doc_count).slice(0, size).map((e) => ({ key: e.key, doc_count: e.doc_count, max_level: { value: e.max }, geo: { hits: { hits: e.geo ? [{ _source: { GeoLocation: e.geo } }] : [] } } })) };
  }
  Object.assign(out, insAggs(docs, aggs));
  return out;
}

function indexer(url, body) {
  let parsed = {};
  try { parsed = JSON.parse(body || "{}"); } catch { /* ignore */ }
  const size = parsed.size ?? 10, from = parsed.from ?? 0;
  if (url.includes("vulnerabilities")) {
    const docs = VULNS.map((d, i) => ({ ...d, _id: `v-${i}` })).filter((d) => matches(d, parsed.query));
    const sev = new Map();
    for (const d of docs) sev.set(d.vulnerability.severity, (sev.get(d.vulnerability.severity) || 0) + 1);
    return {
      hits: { total: { value: docs.length, relation: "eq" }, hits: docs.slice(from, from + size).map((d) => ({ _id: d._id, _source: strip(d) })) },
      aggregations: {
        by_sev: { buckets: [...sev.entries()].sort((a, b) => b[1] - a[1]).map(([key, doc_count]) => ({ key, doc_count })) },
        hosts: { value: new Set(docs.map((d) => d.agent.name)).size },
        ...insAggs(docs, parsed.aggs)
      }
    };
  }
  const all = alertDocs();
  const docs = all.filter((d) => matches(d, parsed.query));
  return {
    hits: { total: { value: docs.length, relation: "eq" }, hits: docs.slice(from, from + size).map((d) => ({ _id: d._id, _source: strip(d) })) },
    ...(parsed.aggs ? { aggregations: alertAggs(docs, parsed.aggs) } : {})
  };
}

/* --------------------------------------------------- OpenCTI --------------------------------------------------- */
const LIST_FIELDS = ["stixCyberObservables", "threatActors", "vulnerabilities", "malwares", "reports", "indicators"];
const encodeCursor = (n) => Buffer.from(String(n)).toString("base64");
const decodeCursor = (c) => { try { const n = Number(Buffer.from(String(c), "base64").toString()); return Number.isFinite(n) ? n : 0; } catch { return 0; } };

function shapeNode(node, q) {
  const out = { ...node };
  delete out._i;
  const asEdges = (list, key) => ({ edges: (list || []).map((x) => ({ node: x })) });
  if (/objectMarking\s*\{\s*edges/.test(q)) out.objectMarking = asEdges(out.objectMarking);
  if (/objectLabel\s*\{\s*edges/.test(q)) out.objectLabel = asEdges(out.objectLabel);
  return out;
}

function opencti(q, vars) {
  const detail = /\b(indicator|report|threatActor|vulnerability|malware)\(\s*id:\s*\$id\s*\)/.exec(q);
  if (detail) {
    const node = COLLECTIONS[DETAIL[detail[1]]].find((x) => x.id === vars.id);
    return { data: { [detail[1]]: node ? shapeNode(node, q) : null } };
  }
  const field = LIST_FIELDS.find((f) => q.includes(`${f}(`));
  if (!field) return null;
  const firstInQuery = /first:\s*(\d+)/.exec(q);
  const first = Math.min(Number(vars.first ?? (firstInQuery ? firstInQuery[1] : 25)) || 25, 200);
  const search = String(vars.s ?? vars.search ?? "").toLowerCase();
  let list = COLLECTIONS[field];
  if (search) list = list.filter((n) => `${n.name || ""} ${n.description || ""} ${n.pattern || ""} ${n.observable_value || ""}`.toLowerCase().includes(search));
  const start = vars.after ? decodeCursor(vars.after) : 0;
  const slice = list.slice(start, start + first);
  const end = start + slice.length;
  const conn = { edges: slice.map((n) => ({ node: shapeNode(n, q) })) };
  if (q.includes("pageInfo")) conn.pageInfo = { globalCount: list.length, endCursor: end ? encodeCursor(end) : null, hasNextPage: end < list.length };
  return { data: { [field]: conn } };
}

/* -------------------------------------------------- Greenbone bridge -------------------------------------------------- */
const DEMO_TASKS = [];
// DEMO_UNREACHABLE=10.20.2.32 makes retest scans report that host as down: a finished scan with no entry and no results for it.
const DEMO_UNREACHABLE = (process.env.DEMO_UNREACHABLE || "").split(",").map((x) => x.trim()).filter(Boolean);
const ipNum = (ip) => ip.split(".").reduce((a, b) => a * 256 + Number(b), 0);
const FALLBACK = [
  ["1.3.6.1.4.1.25623.1.0.117721", "Apache HTTP Server 2.4.49 Path Traversal", "80/tcp", 9.8, "High", ["CVE-2021-41773"], "Update to Apache HTTP Server 2.4.51 or later.", true],
  ["1.3.6.1.4.1.25623.1.0.105611", "SSH Weak Encryption Algorithms Supported", "22/tcp", 5.3, "Medium", [], "Disable the weak ciphers in sshd_config.", false],
  ["1.3.6.1.4.1.25623.1.0.117274", "TLS 1.0 Protocol Detection", "443/tcp", 4.3, "Medium", ["CVE-2011-3389"], "Disable TLS 1.0 and 1.1.", true],
  ["1.3.6.1.4.1.25623.1.0.103190", "ICMP Timestamp Reply Information Disclosure", "general/icmp", 2.1, "Low", ["CVE-1999-0524"], "Filter ICMP timestamp requests.", false]
];
function demoHosts(spec) {
  const text = String(spec);
  const [base, bits] = text.split("/");
  if (bits !== undefined && bits !== "32") {
    const start = ipNum(base), end = start + 2 ** (32 - Number(bits)) - 1;
    const inRange = gb.HOSTS.filter((h) => ipNum(h.ip) >= start && ipNum(h.ip) <= end).map((h) => h.ip);
    if (inRange.length) return inRange;
    const [a, b, c] = base.split(".");
    return [`${a}.${b}.${c}.10`, `${a}.${b}.${c}.11`];
  }
  return [base];
}
function reportForTask(task) {
  const isRetest = /retest/i.test(task.targetName);
  const hosts = demoHosts(task.target).filter((h) => !(isRetest && DEMO_UNREACHABLE.includes(h))).sort();
  const id = `rep-${task.taskId}`;
  const findings = [];
  for (const ip of hosts) {
    const known = gb.hostByIp(ip);
    const list = known
      ? gb.latestHostFindings(ip).filter((f) => !(isRetest && f.quick)).map((f) => ({ oid: f.oid, name: f.name, port: f.port, severity: f.severity, threat: f.threat, cves: f.cves, solution: f.solution, description: f.description }))
      : FALLBACK.filter((f) => !(isRetest && f[7])).map(([oid, name, port, severity, threat, cves, solution]) => ({ oid, name, port, severity, threat, cves, solution, description: `${name} on ${ip}.` }));
    for (const f of list) findings.push({ reportId: id, taskName: task.targetName, host: ip, ...f, creationTime: task.createdAt, resultId: `${task.taskId}-${ip}-${f.oid}` });
  }
  return { id, status: "Done", timestamp: task.createdAt, taskName: task.targetName, scannedHosts: hosts, findings };
}

function greenbone(pathname, req, body) {
  if (pathname === "/v1/overview") {
    const posted = [...DEMO_TASKS].reverse().map((t) => ({ id: t.taskId, name: t.targetName, status: "Done", progress: "100", target: t.targetName, lastReportId: `rep-${t.taskId}` }));
    return { connected: true, version: "22.4 (demo)", message: "Connected to the demo Greenbone bridge (synthetic data).", targets: [...DEMO_TASKS.map((t) => ({ id: t.targetId, name: t.targetName, hosts: t.target, comment: "Created from PrimeSEC (demo)" })), ...gb.TARGETS], tasks: [...posted, ...gb.TASKS_BASE] };
  }
  if (pathname === "/v1/findings") {
    const { reports, rows } = gb.rows(DEMO_TASKS.map(reportForTask));
    return { findings: rows, truncated: false, reports: reports.map((r) => ({ id: r.id, status: r.status, scannedHosts: r.scannedHosts, timestamp: r.timestamp })), completedReports: reports.map((r) => r.id), source: "Demo Greenbone bridge (synthetic)", retrievedAt: new Date().toISOString() };
  }
  if (pathname === "/v1/platform") return gb.PLATFORM;
  if (pathname === "/v1/assessments" && req.method === "POST") {
    let data = {};
    try { data = JSON.parse(body); } catch { /* ignore */ }
    const id = () => Math.random().toString(16).slice(2, 10) + "-demo";
    const name = String(data.name || "assessment").replace(/[^A-Za-z0-9 ._-]/g, "").slice(0, 60);
    const task = { targetId: id(), taskId: id(), targetName: `${name} (demo) ${id().slice(0, 4)}`, target: String(data.target || ""), status: "Requested", progress: 0, createdAt: new Date().toISOString() };
    DEMO_TASKS.push(task);
    return { __status: 201, ...task, reportId: null, message: "Demo only: no scan was run." };
  }
  return null;
}

/* ------------------------------------------------------ server ------------------------------------------------------ */
function handle(req, res, body) {
  const json = (code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
  const auth = req.headers.authorization || "";
  const url = new URL(req.url || "/", "http://localhost");
  const pathname = url.pathname;
  if (process.env.DEMO_QUIET !== "true") console.log(new Date().toLocaleTimeString(), req.method, (req.url || "").slice(0, 80));

  if (pathname === "/health") return json(200, { ok: true, demo: true, agents: AGENTS.length, alerts24h: alertDocs().length, vulnerabilities: VULNS.length, indicators: COLLECTIONS.indicators.length });

  if (pathname.startsWith("/wazuh/security/user/authenticate")) {
    if (auth !== basic(CREDS.wazuh.user, CREDS.wazuh.pass)) return json(401, { title: "Unauthorized" });
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end(WAZUH_JWT);
  }
  if (pathname.startsWith("/wazuh/")) {
    if (auth !== `Bearer ${WAZUH_JWT}`) return json(401, { title: "Unauthorized" });
    const out = wazuhApi(pathname.slice("/wazuh".length), url.searchParams);
    return out ? json(200, out) : json(404, { title: "Not found" });
  }
  if (pathname.startsWith("/indexer/")) {
    if (auth !== basic(CREDS.indexer.user, CREDS.indexer.pass)) return json(401, { error: "unauthorized" });
    return json(200, indexer(pathname, body));
  }
  if (pathname.startsWith("/greenbone/")) {
    if (auth !== `Bearer ${CREDS.greenboneToken}`) return json(401, { error: "Authentication required" });
    const out = greenbone(pathname.slice("/greenbone".length), req, body);
    if (!out) return json(404, { error: "Not found" });
    const { __status, ...rest } = out;
    return json(__status || 200, rest);
  }
  if (pathname === "/opencti/graphql") {
    if (auth !== `Bearer ${CREDS.openctiToken}`) return json(401, { errors: [{ message: "unauthorized" }] });
    let q = "", vars = {};
    try { const b = JSON.parse(body); q = b.query || ""; vars = b.variables || {}; } catch { /* ignore */ }
    const out = opencti(q, vars);
    return out ? json(200, out) : json(200, { errors: [{ message: "Unsupported demo query" }] });
  }
  json(404, { error: "not found" });
}

http
  .createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => { try { handle(req, res, body); } catch (e) { console.error(e); res.writeHead(500); res.end("demo server error"); } });
  })
  .listen(PORT, "127.0.0.1", () => {
    console.log(`PrimeSEC demo integrations (SYNTHETIC data) on http://localhost:${PORT}`);
    console.log(`${AGENTS.length} agents, ${alertDocs().length} alerts/24h, ${VULNS.length} vulnerabilities, ${COLLECTIONS.indicators.length} indicators, ${gb.BASELINE_REPORTS.length} scan reports.`);
    console.log("To point the app at it (scripts\\dev-demo.ps1 does this for you), set:\n");
    console.log(`WAZUH_API_URL=http://localhost:${PORT}/wazuh\nWAZUH_API_USERNAME=${CREDS.wazuh.user}\nWAZUH_API_PASSWORD=${CREDS.wazuh.pass}`);
    console.log(`WAZUH_INDEXER_URL=http://localhost:${PORT}/indexer\nWAZUH_INDEXER_USERNAME=${CREDS.indexer.user}\nWAZUH_INDEXER_PASSWORD=${CREDS.indexer.pass}`);
    console.log(`OPENCTI_URL=http://localhost:${PORT}/opencti\nOPENCTI_API_TOKEN=${CREDS.openctiToken}`);
    console.log(`GREENBONE_BRIDGE_URL=http://localhost:${PORT}/greenbone\nGREENBONE_BRIDGE_TOKEN=${CREDS.greenboneToken}   (FAKE: no scanning happens)\n`);
  });
