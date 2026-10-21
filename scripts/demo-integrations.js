#!/usr/bin/env node
/**
 * PrimeSEC demo integrations: a local FAKE Wazuh (Manager API + Indexer) and OpenCTI (GraphQL).
 * Lets you see the dashboard's live-data mode without real platforms. Every record is
 * clearly marked "(demo)". Nothing here is real telemetry. Run with: npm run demo:integrations
 *
 * Includes hourly alert buckets, severity counts, GeoIP-enriched sources, a vulnerability index and
 * OpenCTI platform totals, so every dashboard panel can be exercised.
 *
 * Endpoints (single port, default 9099):
 *   /wazuh   Wazuh Manager API    /indexer   Wazuh Indexer    /opencti   OpenCTI (graphql at /opencti/graphql)
 *   /greenbone   FAKE Greenbone bridge: records "(demo)" tasks in memory. It scans nothing and touches no network.
 */
const http = require("http");

const PORT = Number(process.env.DEMO_PORT || 9099);
const CREDS = {
  wazuh: { user: "demo-wazuh", pass: "demo-wazuh-pass" },
  indexer: { user: "demo-indexer", pass: "demo-indexer-pass" },
  openctiToken: "demo-opencti-token",
  greenboneToken: "demo-greenbone-bridge-token"
};
const DEMO_TASKS = [];
// Real Wazuh JWTs can be long (many RBAC roles). A long token here guards against any truncation of the raw token.
const WAZUH_JWT = "eyJ-demo." + "A".repeat(880) + ".sig";

const basic = (u, p) => "Basic " + Buffer.from(`${u}:${p}`).toString("base64");
const ago = (minutes) => new Date(Date.now() - minutes * 60000).toISOString();
const edges = (nodes) => ({ edges: nodes.map((node) => ({ node })) });

const AGENTS = [
  ["000", "wazuh-manager (demo)", "active", "127.0.0.1", "Ubuntu"],
  ["001", "web-01 (demo)", "active", "10.20.0.11", "Debian"],
  ["002", "db-02 (demo)", "active", "10.20.0.12", "Ubuntu"],
  ["003", "app-05 (demo)", "active", "10.20.0.15", "Red Hat"],
  ["004", "vpn-gw (demo)", "active", "10.20.0.2", "Debian"],
  ["005", "ws-114 (demo)", "active", "10.30.4.114", "Windows"],
  ["006", "ws-207 (demo)", "disconnected", "10.30.4.207", "Windows"],
  ["007", "mail-01 (demo)", "active", "10.20.0.30", "Ubuntu"]
].map(([id, name, status, ip, os]) => ({ id, name, status, ip, version: "v4.9.0", os: { name: os } }));

const ALERTS = [
  [12, "Suspicious PowerShell execution (demo)", "ws-114 (demo)", "203.0.113.45", 6],
  [10, "Multiple failed SSH logins (demo)", "web-01 (demo)", "203.0.113.45", 14],
  [9, "Outbound beacon to rare domain (demo)", "app-05 (demo)", "198.51.100.17", 31],
  [13, "Ransomware-like file encryption activity (demo)", "ws-207 (demo)", "10.30.4.207", 52],
  [7, "New admin user created (demo)", "db-02 (demo)", "10.20.0.12", 75]
];

// Extra raw text per alert, so investigations have observables beyond the source IP.
const ALERT_LOGS = {
  0: "powershell.exe -nop -w hidden -enc SQBFAFgA... downloaded http://update-check.example/payload.bin from 203.0.113.45",
  1: "sshd[2211]: Failed password for root from 203.0.113.45 port 51820 ssh2",
  2: "dns query login-portal.example from 10.20.0.15 to 198.51.100.17",
  3: "syscheck: file C:\\Users\\a\\docs.locked changed, sha256 9f2c0000000000000000000000000000000000000000000000000000e41a",
  4: "useradd: new user 'svc-backup' created by uid=0 (no external observables)"
};

const INDICATORS = [
  ["203.0.113.45 (demo)", "[ipv4-addr:value = '203.0.113.45']", "stix", 40, 92],
  ["update-check.example (demo)", "[domain-name:value = 'update-check.example']", "stix", 95, 85],
  ["198.51.100.17 (demo)", "[ipv4-addr:value = '198.51.100.17']", "stix", 180, 64],
  ["9f2c…e41a (demo)", "[file:hashes.'SHA-256' = '9f2c0000000000000000000000000000000000000000000000000000e41a']", "stix", 300, 78],
  ["login-portal.example (demo)", "[domain-name:value = 'login-portal.example']", "stix", 520, 71],
  ["http://203.0.113.45/payload.bin (demo)", "[url:value = 'http://203.0.113.45/payload.bin']", "stix", 700, 88],
  ["evil-sig (demo)", "rule demo_sig { condition: true }", "yara", 900, 55],
  ["10.99.0.0/16 (demo)", "[ipv4-addr:value = '10.99.0.0/16']", "stix", 1300, 40]
].map(([name, pattern, pattern_type, m, score], i) => ({ id: `ind-${i}`, name, pattern, pattern_type, created_at: ago(m), x_opencti_score: score }));

// ---- alert metrics: 24 hourly buckets that add up to the demo total ----
const TOTAL_ALERTS = 1842;
const HIGH_ALERTS = 17;
const spread = (total, weights) => {
  const sum = weights.reduce((a, b) => a + b, 0);
  const out = weights.map((w) => Math.floor((total * w) / sum));
  // hand the rounding remainder out one by one, heaviest buckets first
  const order = weights.map((w, i) => i).sort((x, y) => weights[y] - weights[x]);
  for (let r = total - out.reduce((a, b) => a + b, 0), k = 0; r > 0; r--, k++) out[order[k % order.length]]++;
  return out;
};
const HOURLY = spread(TOTAL_ALERTS, Array.from({ length: 24 }, (_, i) => 30 + ((i * 41) % 55)));
const HOURLY_HIGH = spread(HIGH_ALERTS, Array.from({ length: 24 }, (_, i) => ((i * 7) % 5 === 0 ? 3 : 1)));
const hourBuckets = () =>
  HOURLY.map((count, i) => ({
    key_as_string: ago((23 - i) * 60),
    doc_count: count,
    high: { doc_count: HOURLY_HIGH[i] }
  }));
// info + low + medium + high must equal TOTAL_ALERTS
const LEVELS = [
  { key: "info", doc_count: 560 }, { key: "low", doc_count: 800 },
  { key: "medium", doc_count: 465 }, { key: "high", doc_count: HIGH_ALERTS }
];
// GeoIP-enriched alert sources. Coordinates are arbitrary demo values, not attributions.
const SOURCES = [
  ["203.0.113.45", 55.75, 37.62, "Moscow", "Russia (demo)", 412, 12],
  ["198.51.100.17", 39.9, 116.4, "Beijing", "China (demo)", 301, 10],
  ["192.0.2.88", 50.11, 8.68, "Frankfurt", "Germany (demo)", 188, 9],
  ["203.0.113.200", -23.55, -46.63, "Sao Paulo", "Brazil (demo)", 140, 7],
  ["198.51.100.99", 1.35, 103.82, "Singapore", "Singapore (demo)", 122, 13],
  ["192.0.2.140", 37.77, -122.42, "San Francisco", "United States (demo)", 96, 8],
  ["203.0.113.9", 6.52, 3.38, "Lagos", "Nigeria (demo)", 64, 6]
].map(([ip, lat, lon, city, country, doc_count, max]) => ({
  key: ip, doc_count,
  max_level: { value: max },
  geo: { hits: { hits: [{ _source: { GeoLocation: { location: { lat, lon }, city_name: city, country_name: country } } }] } }
}));

const VULNS = [
  ["db-02 (demo)", "CVE-2024-3094", "xz-utils", "Critical", 9.8], ["web-01 (demo)", "CVE-2023-44487", "nginx", "High", 7.5],
  ["app-05 (demo)", "CVE-2024-21626", "runc", "High", 8.6], ["ws-114 (demo)", "CVE-2023-4863", "libwebp", "High", 8.8],
  ["vpn-gw (demo)", "CVE-2023-38408", "openssh", "Critical", 9.8]
].sort((a, b) => b[4] - a[4]);

const REPORTS = [
  "Q4 phishing campaign against finance (demo)", "Ransomware affiliate infrastructure review (demo)", "C2 framework trends (demo)",
  "Supply-chain compromise advisory (demo)", "Credential stuffing wave, APAC (demo)", "Quarterly threat landscape (demo)"
].map((name, i) => ({ id: `rep-${i}`, name, published: ago(1440 * (i + 1)), created_at: ago(1440 * (i + 1)) }));

const ACTORS = [
  ["APT-Alpha (demo)", "Fictional state-aligned espionage group."], ["FIN-Delta (demo)", "Fictional financially motivated group."],
  ["Hacktivist-7 (demo)", "Fictional hacktivist collective."], ["APT-Bravo (demo)", "Fictional intrusion set."],
  ["FIN-Echo (demo)", "Fictional ransomware affiliate."], ["Insider-X (demo)", "Fictional insider-threat profile."]
].map(([name, description], i) => ({ id: `act-${i}`, name, description }));

function handle(req, res, body) {
  const json = (code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
  const auth = req.headers.authorization || "";
  const url = req.url || "";
  console.log(new Date().toLocaleTimeString(), req.method, url.slice(0, 70));

  if (url.startsWith("/wazuh/security/user/authenticate")) {
    if (auth !== basic(CREDS.wazuh.user, CREDS.wazuh.pass)) return json(401, { title: "Unauthorized" });
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end(WAZUH_JWT);
  }
  if (url.startsWith("/wazuh/agents")) {
    if (auth !== `Bearer ${WAZUH_JWT}`) return json(401, { title: "Unauthorized" });
    return json(200, { data: { total_affected_items: AGENTS.length, affected_items: AGENTS } });
  }
  if (url.startsWith("/indexer/")) {
    if (auth !== basic(CREDS.indexer.user, CREDS.indexer.pass)) return json(401, { error: "unauthorized" });
    if (url.includes("vulnerabilities")) {
      return json(200, {
        hits: {
          total: { value: 128 },
          hits: VULNS.map(([agent, id, pkg, severity, base]) => ({
            _source: { agent: { name: agent }, package: { name: pkg }, vulnerability: { id, severity, score: { base } } }
          }))
        },
        aggregations: {
          by_sev: { buckets: [{ key: "Medium", doc_count: 64 }, { key: "High", doc_count: 31 }, { key: "Low", doc_count: 27 }, { key: "Critical", doc_count: 6 }] },
          hosts: { value: 6 }
        }
      });
    }
    let parsed = {};
    try { parsed = JSON.parse(body); } catch { /* ignore */ }
    const wantedIds = parsed?.query?.ids?.values;
    if (Array.isArray(wantedIds)) {
      const hits = ALERTS.map(([level, description, agent, srcip, m], i) => ({
        _id: `alert-${i}`,
        _source: {
          timestamp: ago(m), rule: { level, description }, agent: { name: agent },
          data: srcip.startsWith("10.") ? {} : { srcip }, full_log: ALERT_LOGS[i]
        }
      })).filter((h) => wantedIds.includes(h._id));
      return json(200, { hits: { total: { value: hits.length }, hits } });
    }
    return json(200, {
      hits: {
        total: { value: TOTAL_ALERTS },
        hits: ALERTS.map(([level, description, agent, srcip, m], i) => ({
          _id: `alert-${i}`,
          _source: { timestamp: ago(m), rule: { level, description }, agent: { name: agent }, data: { srcip } }
        }))
      },
      aggregations: {
        critical: { doc_count: HIGH_ALERTS },
        by_hour: { buckets: hourBuckets() },
        by_level: { buckets: LEVELS },
        top_src: { buckets: SOURCES }
      }
    });
  }
  if (url.startsWith("/greenbone/")) {
    if (auth !== `Bearer ${CREDS.greenboneToken}`) return json(401, { error: "Authentication required" });
    if (url === "/greenbone/v1/overview") {
      return json(200, {
        connected: true, version: "22.4 (demo)", message: "Connected to the demo Greenbone bridge (fake).",
        targets: DEMO_TASKS.map((t) => ({ id: t.targetId, name: t.targetName, hosts: t.target, comment: "" })),
        tasks: [...DEMO_TASKS].reverse().map((t) => ({ id: t.taskId, name: t.targetName, status: t.status, progress: String(t.progress), target: t.targetName, lastReportId: "" }))
      });
    }
    if (url === "/greenbone/v1/assessments" && req.method === "POST") {
      let data = {};
      try { data = JSON.parse(body); } catch { /* ignore */ }
      const id = () => Math.random().toString(16).slice(2, 10) + "-demo";
      const name = String(data.name || "assessment").replace(/[^A-Za-z0-9 ._-]/g, "").slice(0, 60);
      const task = { targetId: id(), taskId: id(), targetName: `${name} (demo) ${id().slice(0, 4)}`, target: String(data.target || ""), status: "Requested", progress: 0 };
      DEMO_TASKS.push(task);
      return json(201, { ...task, reportId: null, message: "Demo only: no scan was run." });
    }
    return json(404, { error: "Not found" });
  }
  if (url === "/opencti/graphql") {
    if (auth !== `Bearer ${CREDS.openctiToken}`) return json(401, { errors: [{ message: "unauthorized" }] });
    let q = "";
    let vars = {};
    try { const parsedBody = JSON.parse(body); q = parsedBody.query || ""; vars = parsedBody.variables || {}; } catch { /* ignore */ }
    if (q.includes("PrimeSecIndicatorSearch")) {
      // like real OpenCTI search: loose text match over name and pattern
      const term = String(vars.s || "").toLowerCase();
      const hits = term ? INDICATORS.filter((n) => `${n.name} ${n.pattern}`.toLowerCase().includes(term)) : [];
      return json(200, { data: { indicators: edges(hits) } });
    }
    const rich = q.includes("pageInfo");
    const conn = (nodes, total) => (rich ? { pageInfo: { globalCount: total }, ...edges(nodes) } : edges(nodes));
    if (q.includes("indicators(")) return json(200, { data: { indicators: conn(rich ? INDICATORS : INDICATORS.map(({ x_opencti_score, ...n }) => n), 12480) } });
    if (q.includes("reports(")) return json(200, { data: { reports: conn(REPORTS, 3092) } });
    if (q.includes("threatActors(")) return json(200, { data: { threatActors: conn(ACTORS, 214) } });
  }
  json(404, { error: "not found" });
}

http
  .createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => handle(req, res, body));
  })
  .listen(PORT, "127.0.0.1", () => {
    console.log(`PrimeSEC demo integrations (FAKE data) on http://localhost:${PORT}`);
    console.log("Add to .env, then restart `npm run dev` if the dashboard still shows sample data:\n");
    console.log(`WAZUH_API_URL=http://localhost:${PORT}/wazuh\nWAZUH_API_USERNAME=${CREDS.wazuh.user}\nWAZUH_API_PASSWORD=${CREDS.wazuh.pass}`);
    console.log(`WAZUH_INDEXER_URL=http://localhost:${PORT}/indexer\nWAZUH_INDEXER_USERNAME=${CREDS.indexer.user}\nWAZUH_INDEXER_PASSWORD=${CREDS.indexer.pass}`);
    console.log(`OPENCTI_URL=http://localhost:${PORT}/opencti\nOPENCTI_API_TOKEN=${CREDS.openctiToken}`);
    console.log(`GREENBONE_BRIDGE_URL=http://localhost:${PORT}/greenbone\nGREENBONE_BRIDGE_TOKEN=${CREDS.greenboneToken}   (FAKE: no scanning happens)\n`);
  });
