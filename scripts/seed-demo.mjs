// Fills a SEPARATE data folder with a rich, internally consistent demo: scan history and findings, host context, inventory from five
// sources, 15 investigation cases, governed-response proposals and executions, AI-agent policies and approvals, SAP assessments,
// an audit trail and the Neo4j graph. Everything goes through the same library functions the app itself uses.
//
// Needs the demo integrations server running (npm run demo:integrations) and the demo environment (scripts\dev-demo.ps1 sets it).
// Run: node --experimental-strip-types --no-warnings scripts/seed-demo.mjs [--reset]
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
try { process.loadEnvFile(path.join(root, ".env")); } catch { /* .env is optional here: it only supplies the Neo4j password */ }

process.env.INTEGRATION_TIMEOUT_MS ||= "120000"; // the graph is written in many small transactions, but Neo4j can be slow on a cold start
const DATA_DIR = process.env.PRIMESEC_DATA_DIR || "";
const demoPort = process.env.DEMO_PORT || "9099";
if (!DATA_DIR || path.basename(DATA_DIR) === "data") {
  console.error('Refusing to run: PRIMESEC_DATA_DIR must point at a separate demo folder (for example "data-demo"), never the real "data".');
  process.exit(1);
}
const dataDir = path.isAbsolute(DATA_DIR) ? DATA_DIR : path.join(root, DATA_DIR);
if (process.argv.includes("--reset")) fs.rmSync(dataDir, { recursive: true, force: true });
if (fs.existsSync(path.join(dataDir, "cases.json"))) {
  console.log(`${DATA_DIR} is already seeded. Use --reset to rebuild it.`);
  process.exit(0);
}
fs.mkdirSync(dataDir, { recursive: true });

const health = await fetch(`http://127.0.0.1:${demoPort}/health`).then((r) => r.json()).catch(() => null);
if (!health?.ok) { console.error(`The demo integrations server is not answering on port ${demoPort}. Start it with: npm run demo:integrations`); process.exit(1); }

const lib = (f) => import(path.join(root, "lib", f).replace(/\\/g, "/").replace(/^([A-Za-z]):/, "file:///$1:"));
const [integ, findingsLib, reportsLib, assetsLib, vaptLib, inv, sync, syncSources, casesLib, respLib, respAdapters, gateLib, agentLib, sapLib, graphLib, investigate] = await Promise.all([
  "integrations.ts", "findings.ts", "reports.ts", "assets.ts", "vapt.ts", "inventory.ts", "sync.ts", "syncSources.ts", "cases.ts", "response.ts", "responseAdapters.ts", "agentgate.ts", "agentsec.ts", "sap.ts", "graph.ts", "investigate.ts"
].map(lib));

const MIN = 60_000, HOUR = 3_600_000, DAY = 86_400_000;
const T0 = Date.now();
const iso = (ms) => new Date(ms).toISOString();
const agoMin = (m) => iso(T0 - m * MIN);
const log = (...a) => console.log("•", ...a);
const step = async (name, fn) => { const t = Date.now(); try { const r = await fn(); log(`${name} (${Date.now() - t} ms)${r ? " — " + r : ""}`); } catch (e) { console.error(`✗ ${name}:`, e?.message || e); } };

// ---------- people ----------
const P = {
  admin: { name: "Rohan Iyer", email: "rohan.iyer@meridian.example", roles: ["SOC_Admin"] },
  lead: { name: "Meera Nair", email: "meera.nair@meridian.example", roles: ["SOC_Admin"] },
  a1: { name: "Aarav Mehta", email: "aarav.mehta@meridian.example", roles: ["SOC_Analyst"] },
  a2: { name: "Neha Kulkarni", email: "neha.kulkarni@meridian.example", roles: ["SOC_Analyst"] },
  a3: { name: "Daniel Okafor", email: "daniel.okafor@meridian.example", roles: ["SOC_Analyst"] },
  a4: { name: "Sofia Rossi", email: "sofia.rossi@meridian.example", roles: ["SOC_Analyst"] },
  demoAdmin: { name: "Demo Admin", email: "demo-admin@primesec.local", roles: ["SOC_Admin"] },
  demoAnalyst: { name: "Demo Analyst", email: "demo-analyst@primesec.local", roles: ["SOC_Analyst"] }
};

/* ============================================================ 1. VAPT ============================================================ */
const hostsByName = {};
await step("Greenbone findings and report history", async () => {
  const remote = await vaptLib.getBridgeFindings();
  const reports = [...remote.reports].sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));
  const order = new Map(reports.map((r, i) => [r.id, i]));
  for (let k = 0; k < reports.length; k++) {
    const upto = remote.findings.filter((f) => order.get(f.reportId) <= k).map((f) => ({ ...f, reportIndex: k - order.get(f.reportId) }));
    const now = reports[k].timestamp;
    await findingsLib.syncFindings(upto, { now });
    await reportsLib.captureSnapshots(upto, { now, completedReports: reports.slice(0, k + 1).map((r) => r.id), reports: reports.slice(0, k + 1) });
  }
  return `${(await findingsLib.readFindings()).length} findings from ${reports.length} reports`;
});

await step("host context (criticality, exposure)", async () => {
  const ctx = {
    "web-01": ["Critical", "Internet-facing"], "web-02": ["Critical", "Internet-facing"], "web-03": ["High", "Internet-facing"], "web-04": ["High", "Internet-facing"], "api-gw-01": ["Critical", "Internet-facing"],
    "app-01": ["High", "Internal"], "app-02": ["High", "Internal"], "app-04": ["Critical", "Internal"], "db-01": ["Critical", "Internal"], "db-02": ["Critical", "Internal"], "db-03": ["High", "Internal"], "db-04": ["Medium", "Internal"],
    "dc-01": ["Critical", "Internal"], "fs-01": ["High", "Internal"], "mail-01": ["High", "Internet-facing"], "vpn-gw-01": ["Critical", "Internet-facing"], "jump-01": ["High", "Internet-facing"]
  };
  const ips = Object.fromEntries((await fetch(`http://127.0.0.1:${demoPort}/wazuh/security/user/authenticate?raw=true`, { method: "POST", headers: { Authorization: "Basic " + Buffer.from("demo-wazuh:demo-wazuh-pass").toString("base64") } }).then((r) => r.text()).then(async (tok) => (await (await fetch(`http://127.0.0.1:${demoPort}/wazuh/agents?limit=500`, { headers: { Authorization: `Bearer ${tok}` } })).json()).data.affected_items.map((a) => [a.name, a.registerIP]))));
  for (const [name, [criticality, exposure]] of Object.entries(ctx)) { hostsByName[name] = ips[name]; await assetsLib.updateAsset(ips[name], { criticality, exposure }, P.a1); }
  return `${Object.keys(ctx).length} hosts`;
});

const FIND = await findingsLib.readFindings();
const byName = (host, re) => FIND.find((f) => f.host === hostsByName[host] && re.test(f.name));
await step("analyst work on findings (owners, status, retests)", async () => {
  const set = async (f, patch, who = P.a1) => { if (f) await findingsLib.updateFinding(f.id, patch, who); };
  await set(byName("web-02", /Apache HTTP Server 2.4.49/), { remediationStatus: "In Progress", owner: "web-platform@meridian.example", exploitEvidence: "Exploited in the wild", remediationNotes: "Patch 2.4.58 staged in the change window on Saturday. WAF virtual patch is active in the meantime." });
  await set(byName("web-03", /Web Shell/), { remediationStatus: "In Progress", owner: "ir-team@meridian.example", exploitEvidence: "Exploited in the wild", remediationNotes: "Host isolated from the DMZ. Rebuild from a known-good image; credentials rotated. See the web shell case." }, P.admin);
  await set(byName("web-03", /PHP-CGI/), { remediationStatus: "Open", owner: "web-platform@meridian.example", exploitEvidence: "Public exploit" });
  await set(byName("app-04", /Log4Shell/), { remediationStatus: "In Progress", owner: "app-platform@meridian.example", exploitEvidence: "Exploited in the wild", remediationNotes: "Log4j upgraded to 2.17.2 on 3 of 4 nodes; node 4 pending a restart." });
  await set(byName("app-04", /End of Life/), { remediationStatus: "Open", owner: "infra@meridian.example", remediationNotes: "OS upgrade scheduled for Q1 with the application migration." });
  await set(byName("app-02", /Spring4Shell/), { remediationStatus: "In Progress", owner: "app-platform@meridian.example", exploitEvidence: "Exploited in the wild" });
  await set(byName("app-02", /Docker Remote API/), { remediationStatus: "Open", owner: "platform-security@meridian.example", remediationNotes: "Listener bound to 0.0.0.0 by a legacy compose file. Change request raised." });
  await set(byName("app-01", /Jenkins/), { remediationStatus: "In Progress", owner: "devops@meridian.example", exploitEvidence: "Public exploit" });
  await set(byName("db-02", /Default Credentials/), { remediationStatus: "In Progress", owner: "database-team@meridian.example", exploitEvidence: "Public exploit", remediationNotes: "Account rotated; network ACL review pending." });
  await set(byName("db-03", /Unsupported Version/), { remediationStatus: "Open", owner: "database-team@meridian.example", remediationNotes: "Migration to SQL Server 2022 is on the roadmap; compensating controls documented." });
  await set(byName("db-03", /SMBv1/), { remediationStatus: "In Progress", owner: "windows-team@meridian.example", exploitEvidence: "Public exploit" });
  await set(byName("fs-01", /SMBv1/), { remediationStatus: "In Progress", owner: "windows-team@meridian.example", exploitEvidence: "Public exploit", remediationNotes: "SMBv1 disabled via GPO; reboot pending." });
  await set(byName("fs-01", /PrintNightmare/), { remediationStatus: "Open", owner: "windows-team@meridian.example", exploitEvidence: "Exploited in the wild" });
  await set(byName("dc-01", /Zerologon/), { remediationStatus: "Open", owner: "identity-team@meridian.example", exploitEvidence: "Public exploit", remediationNotes: "Enforcement mode is the missing step. Emergency change raised." });
  await set(byName("db-01", /trust/), { remediationStatus: "In Progress", owner: "database-team@meridian.example" });
  await set(byName("vpn-gw-01", /OpenVPN/), { remediationStatus: "In Progress", owner: "network-team@meridian.example" });
  await set(byName("mail-01", /Dovecot/), { remediationStatus: "Open", owner: "messaging-team@meridian.example" });
  // fixed along the way: resolved or closed with evidence
  for (const f of FIND.filter((x) => x.notInLatestSync && x.threat !== "Log")) {
    const r = FIND.indexOf(f) % 3;
    if (r === 0) await set(f, { remediationStatus: "Resolved", owner: "infra@meridian.example", remediationNotes: "Fixed in the weekly patch cycle; no longer reported by the latest scan." });
    else if (r === 1) { await findingsLib.markRetestRequested(f.id, "demo-retest-" + f.id.slice(0, 6), P.a2); }
  }
  for (const f of FIND.filter((x) => x.notInLatestSync && x.threat !== "Log" && FIND.indexOf(x) % 3 === 2).slice(0, 4)) await set(f, { remediationStatus: "Closed", owner: "infra@meridian.example", remediationNotes: "Verified fixed by the retest scan on the next weekly run." }, P.admin);
  for (const [host, re] of [["web-01", /TLS/], ["web-02", /TLS/]]) { const f = byName(host, re); if (f) await findingsLib.markRetestRequested(f.id, "demo-retest-" + f.id.slice(0, 6), P.a1); }
  return "done";
});

await step("approved scan scopes", async () => {
  const exp = (days) => iso(Date.now() + days * DAY);
  const scopes = [
    { name: "Internal infrastructure: Q4 weekly assessment", authorizationReference: "CHG-2026-1184 / SOW-MRD-0042", targets: ["172.16.10.0/24", "10.20.1.0/24", "10.20.2.0/24", "10.20.3.0/24"], expiresAt: exp(60) },
    { name: "Remote access and mail", authorizationReference: "CHG-2026-1190 (network team sign-off)", targets: ["10.20.0.0/24", "10.20.4.0/24"], expiresAt: exp(45) },
    { name: "Cloud workloads (AWS ap-south-1, Azure Central India)", authorizationReference: "CLOUD-SEC-2026-077 (cloud owner approval)", targets: ["10.40.1.0/24", "10.40.2.0/24"], expiresAt: exp(30) },
    { name: "External perimeter: PCI ASV quarterly", authorizationReference: "PCI-ASV-2026-Q4 / SOW-MRD-0051", targets: ["203.0.113.0/24"], expiresAt: exp(14), acknowledgePublic: true },
    { name: "Legacy lab range (decommissioned)", authorizationReference: "CHG-2026-0911 lab retirement", targets: ["10.99.1.0/24"], expiresAt: exp(20) }
  ];
  const made = [];
  for (const s of scopes) made.push(await vaptLib.createScope(s, P.admin));
  await vaptLib.revokeScope(made[4].id, P.lead);
  return `${made.length} scopes (1 revoked)`;
});

/* ======================================================== 2. INVENTORY ======================================================== */
const ROLE = {
  manager: ["server", "management", "Security Operations", 4, false], web: ["server", "production", "Digital Channels", 5, true], waf: ["network-device", "production", "Digital Channels", 5, true], app: ["server", "production", "Core Applications", 4, false],
  apigw: ["server", "production", "Digital Channels", 5, true], "db-pg": ["database", "production", "Core Applications", 5, false], "db-my": ["database", "production", "Core Applications", 5, false], "db-ms": ["database", "production", "Finance Systems", 4, false],
  "db-ora": ["database", "production", "Finance Systems", 3, false], cache: ["server", "production", "Core Applications", 3, false], dc: ["server", "production", "Corporate IT", 5, false], adfs: ["server", "production", "Corporate IT", 5, true],
  fs: ["server", "production", "Corporate IT", 4, false], mail: ["server", "production", "Corporate IT", 4, true], vpn: ["network-device", "production", "Corporate IT", 5, true], jump: ["server", "production", "Corporate IT", 4, true],
  backup: ["server", "production", "Corporate IT", 4, false], "cloud-web": ["cloud-instance", "production", "Digital Channels", 5, true], "cloud-api": ["cloud-instance", "production", "Digital Channels", 5, false],
  "cloud-db": ["cloud-instance", "production", "Digital Channels", 5, false], "cloud-win": ["cloud-instance", "production", "Finance Systems", 4, false], "cloud-analytics": ["cloud-instance", "production", "Data and Analytics", 3, false],
  k8s: ["kubernetes-node", "production", "Platform Engineering", 4, false], "ws-win": ["endpoint", "corporate", "Corporate IT", 2, false], "ws-mac": ["endpoint", "corporate", "Engineering", 2, false], "ws-lin": ["endpoint", "corporate", "Engineering", 2, false]
};
const roleOf = (a) => {
  const n = a.name;
  if (n === "wazuh-manager") return "manager";
  if (/^web-/.test(n)) return "web"; if (/^waf/.test(n)) return "waf"; if (/^app-/.test(n)) return "app"; if (/^api-gw/.test(n)) return "apigw";
  if (n === "db-01") return "db-pg"; if (n === "db-02") return "db-my"; if (n === "db-03") return "db-ms"; if (n === "db-04") return "db-ora"; if (/^cache/.test(n)) return "cache";
  if (/^dc-/.test(n)) return "dc"; if (/^adfs/.test(n)) return "adfs"; if (/^fs-/.test(n)) return "fs"; if (/^mail-/.test(n)) return "mail"; if (/^vpn-/.test(n)) return "vpn"; if (/^jump/.test(n)) return "jump"; if (/^bk-/.test(n)) return "backup";
  if (/^aws-prod-web/.test(n)) return "cloud-web"; if (/^aws-prod-api/.test(n)) return "cloud-api"; if (/^aws-prod-db/.test(n)) return "cloud-db"; if (/^azure/.test(n)) return "cloud-win"; if (/^gcp/.test(n)) return "cloud-analytics"; if (/^k8s/.test(n)) return "k8s";
  if (/^ws-/.test(n)) return a.os && /mac/i.test(a.os) ? "ws-mac" : a.os && /ubuntu|debian/i.test(a.os) ? "ws-lin" : "ws-win";
  return "web";
};

let agentRows = [];
await step("inventory: Wazuh agents + vulnerabilities (5 runs of history, 1 failed)", async () => {
  const { items } = await integ.listWazuhAgents();
  agentRows = items;
  const vulnBody = await integ.wazuhIndexerSearch("wazuh-states-vulnerabilities-*", { size: 1000, track_total_hits: true, query: { match_all: {} } });
  const vulnsByAgent = new Map();
  for (const h of vulnBody.hits.hits) {
    const s = h._source, id = s.agent.id;
    const sev = String(s.vulnerability.severity).toLowerCase();
    const row = { cve: s.vulnerability.id, key: s.vulnerability.id, title: `${s.vulnerability.id} · ${s.package.name}`, severity: sev, cvss: s.vulnerability.score.base, status: "open" };
    vulnsByAgent.set(id, [...(vulnsByAgent.get(id) ?? []), row]);
  }
  const build = () => items.map((a) => {
    const base = sync.wazuhAgentToAsset(a);
    const [type, env, bu, crit, inet] = ROLE[roleOf(a)];
    const vulns = (vulnsByAgent.get(a.id) ?? []).map((v, i) => ({ ...v, status: i % 11 === 7 ? "closed" : "open" }));
    return { ...base, assetType: type, environment: env, businessUnit: bu, criticality: crit, internetFacing: inet, vulnerabilities: vulns, tags: [...new Set([...(a.groups ?? []), roleOf(a)])] };
  });
  const runs = [[-96, false], [-72, false], [-48, false], [-30, true], [-24, false], [-2, false]];
  for (const [h, fail] of runs) {
    await sync.runAssetSync("wazuh", "scheduled sync", async () => { if (fail) throw new Error("Could not reach the upstream platform. Check its URL, TLS certificate, credentials and network access."); return { items: build(), note: "Demo data: records came from the demo integrations server, not a real platform." }; }, T0 + h * HOUR);
  }
  return `${items.length} agents`;
});

await step("inventory: Greenbone hosts (from the imported findings)", async () => {
  const findings = await findingsLib.readFindings();
  const hosts = await assetsLib.readAssets();
  const ctx = new Map(hosts.map((h) => [assetsLib.hostKey(h.host), { criticality: h.criticality, exposure: h.exposure }]));
  const agentByIp = new Map(agentRows.filter((a) => a.ip).map((a) => [a.ip, a]));
  const items = () => sync.findingsToAssets(findings, ctx).map((it) => { const a = agentByIp.get(it.primaryIp); return a ? { ...it, name: a.name, hostname: a.name, identifiers: { agent_id: a.id } } : it; });
  for (const h of [-26, 0]) await sync.runAssetSync("greenbone", h === 0 ? "demo seed" : "scheduled sync", async () => ({ items: items(), note: "Built from findings already imported in the VAPT workspace; this does not call Greenbone." }), T0 + h * HOUR);
});

await step("inventory: cloud, network, business applications and retired hosts", async () => {
  const batches = [
    // cloud accounts: same machines Wazuh sees, reported by the cloud API (so the Duplicates tab has real candidates)
    { at: -20, items: [
      { source: "aws", sourceAssetId: "i-0a1b2c3d4e5f60001", assetType: "cloud-instance", name: "aws-prod-web-01", hostname: "aws-prod-web-01", primaryIp: "10.40.1.11", operatingSystem: "Amazon Linux 2023", environment: "production", businessUnit: "Digital Channels", criticality: 5, internetFacing: true, tags: ["aws", "ap-south-1", "ec2"], identifiers: { cloud_instance_id: "i-0a1b2c3d4e5f60001" } },
      { source: "aws", sourceAssetId: "i-0a1b2c3d4e5f60002", assetType: "cloud-instance", name: "aws-prod-api-01", hostname: "aws-prod-api-01", primaryIp: "10.40.1.21", operatingSystem: "Amazon Linux 2023", environment: "production", businessUnit: "Digital Channels", criticality: 5, internetFacing: false, tags: ["aws", "ap-south-1", "ec2"], identifiers: { cloud_instance_id: "i-0a1b2c3d4e5f60002" } },
      { source: "aws", sourceAssetId: "i-0a1b2c3d4e5f60003", assetType: "cloud-instance", name: "aws-prod-db-01", hostname: "aws-prod-db-01", primaryIp: "10.40.1.31", operatingSystem: "Amazon Linux 2023", environment: "production", businessUnit: "Digital Channels", criticality: 5, tags: ["aws", "ap-south-1", "ec2"], identifiers: { cloud_instance_id: "i-0a1b2c3d4e5f60003" } },
      { source: "aws", sourceAssetId: "arn:aws:s3:::meridian-prod-backups", assetType: "storage-bucket", name: "meridian-prod-backups", environment: "production", businessUnit: "Corporate IT", criticality: 5, internetFacing: true, tags: ["aws", "s3", "backups", "public-policy-detected"], identifiers: { cmdb_id: "S3-BKP-001" }, vulnerabilities: [{ key: "S3-PUBLIC-POLICY", title: "S3 bucket policy allows public access", severity: "critical", cvss: 9.1, status: "open" }] },
      { source: "aws", sourceAssetId: "arn:aws:rds:ap-south-1:db:meridian-prod-pg", assetType: "database", name: "meridian-prod-pg (RDS)", environment: "production", businessUnit: "Core Applications", criticality: 5, tags: ["aws", "rds", "postgresql"], identifiers: { cloud_instance_id: "db-RDS-PROD-PG" }, vulnerabilities: [{ cve: "CVE-2023-5868", key: "CVE-2023-5868", title: "PostgreSQL < 15.5 memory disclosure", severity: "medium", cvss: 4.3, status: "open" }] },
      { source: "aws", sourceAssetId: "alb-prod-public", assetType: "load-balancer", name: "alb-prod-public", primaryIp: "203.0.113.20", environment: "production", businessUnit: "Digital Channels", criticality: 5, internetFacing: true, tags: ["aws", "alb"], identifiers: { cloud_instance_id: "alb-prod-public" } }
    ] },
    { at: -18, items: [
      { source: "azure", sourceAssetId: "vm-azure-app-01", assetType: "cloud-instance", name: "azure-app-01", hostname: "azure-app-01", primaryIp: "10.40.2.11", operatingSystem: "Windows Server 2022", environment: "production", businessUnit: "Finance Systems", criticality: 4, tags: ["azure", "centralindia"], identifiers: { cloud_instance_id: "vm-azure-app-01" } },
      { source: "azure", sourceAssetId: "sql-mrd-fin-prod", assetType: "database", name: "mrd-fin-prod (Azure SQL)", environment: "production", businessUnit: "Finance Systems", criticality: 5, tags: ["azure", "sql"], identifiers: { cloud_instance_id: "sql-mrd-fin-prod" } },
      { source: "gcp", sourceAssetId: "gce-analytics-01", assetType: "cloud-instance", name: "gcp-analytics-01", hostname: "gcp-analytics-01", primaryIp: "10.40.3.11", operatingSystem: "Debian 12", environment: "production", businessUnit: "Data and Analytics", criticality: 3, tags: ["gcp", "asia-south1"], identifiers: { cloud_instance_id: "gce-analytics-01" } },
      { source: "gcp", sourceAssetId: "bq-analytics-warehouse", assetType: "database", name: "BigQuery analytics warehouse", environment: "production", businessUnit: "Data and Analytics", criticality: 4, tags: ["gcp", "bigquery", "pii"], identifiers: { cmdb_id: "DWH-BQ-01" } }
    ] },
    { at: -16, items: [
      { source: "cmdb", sourceAssetId: "NET-FW-EDGE-01", assetType: "network-device", name: "fw-edge-01", hostname: "fw-edge-01", primaryIp: "203.0.113.1", operatingSystem: "PAN-OS 10.2.7", environment: "production", businessUnit: "Corporate IT", criticality: 5, internetFacing: true, tags: ["firewall", "edge"], identifiers: { cmdb_id: "NET-FW-EDGE-01" }, vulnerabilities: [{ cve: "CVE-2024-3400", key: "CVE-2024-3400", title: "PAN-OS GlobalProtect command injection", severity: "critical", cvss: 10, status: "open" }] },
      { source: "cmdb", sourceAssetId: "NET-FW-EDGE-02", assetType: "network-device", name: "fw-edge-02", hostname: "fw-edge-02", primaryIp: "203.0.113.2", operatingSystem: "PAN-OS 11.0.4", environment: "production", businessUnit: "Corporate IT", criticality: 5, internetFacing: true, tags: ["firewall", "edge"], identifiers: { cmdb_id: "NET-FW-EDGE-02" } },
      { source: "cmdb", sourceAssetId: "NET-SW-CORE-01", assetType: "network-device", name: "sw-core-01", primaryIp: "10.20.0.250", operatingSystem: "Cisco IOS XE 17.9", environment: "production", businessUnit: "Corporate IT", criticality: 5, tags: ["switch", "core"], identifiers: { cmdb_id: "NET-SW-CORE-01" }, vulnerabilities: [{ cve: "CVE-2023-20198", key: "CVE-2023-20198", title: "Cisco IOS XE web UI privilege escalation", severity: "critical", cvss: 10, status: "closed" }] },
      { source: "cmdb", sourceAssetId: "NET-LB-F5-01", assetType: "load-balancer", name: "lb-f5-01", primaryIp: "172.16.10.2", operatingSystem: "F5 BIG-IP 16.1", environment: "production", businessUnit: "Digital Channels", criticality: 5, internetFacing: true, tags: ["load-balancer", "f5"], identifiers: { cmdb_id: "NET-LB-F5-01" } },
      { source: "cmdb", sourceAssetId: "APP-PORTAL", assetType: "application", name: "Customer Portal", environment: "production", businessUnit: "Digital Channels", criticality: 5, internetFacing: true, tags: ["application", "tier-1", "pci"], identifiers: { cmdb_id: "APP-PORTAL" } },
      { source: "cmdb", sourceAssetId: "APP-PAYMENTS", assetType: "application", name: "Payments Gateway", environment: "production", businessUnit: "Finance Systems", criticality: 5, tags: ["application", "tier-1", "pci"], identifiers: { cmdb_id: "APP-PAYMENTS" } },
      { source: "cmdb", sourceAssetId: "APP-CORE-API", assetType: "application", name: "Core Banking API", environment: "production", businessUnit: "Core Applications", criticality: 5, tags: ["application", "tier-1"], identifiers: { cmdb_id: "APP-CORE-API" } },
      { source: "cmdb", sourceAssetId: "APP-DWH", assetType: "application", name: "Data Warehouse and Reporting", environment: "production", businessUnit: "Data and Analytics", criticality: 3, tags: ["application", "tier-2", "pii"], identifiers: { cmdb_id: "APP-DWH" } },
      { source: "cmdb", sourceAssetId: "APP-HRP", assetType: "application", name: "HR and Payroll", environment: "production", businessUnit: "Corporate IT", criticality: 4, tags: ["application", "tier-2", "pii"], identifiers: { cmdb_id: "APP-HRP" } },
      { source: "cmdb", sourceAssetId: "APP-EMAIL", assetType: "application", name: "Email and Collaboration", environment: "production", businessUnit: "Corporate IT", criticality: 4, tags: ["application", "tier-2"], identifiers: { cmdb_id: "APP-EMAIL" } }
    ] },
    // retired machines still reported by an old source: they trigger the "stale source" warning
    { at: -24 * 12, items: [
      { source: "wazuh", sourceAssetId: "031-old", assetType: "endpoint", name: "ws-mum-088 (retired)", hostname: "ws-mum-088", primaryIp: "10.30.1.88", operatingSystem: "Microsoft Windows 10 Pro", environment: "corporate", businessUnit: "Corporate IT", criticality: 2, tags: ["workstations", "decommissioned"], identifiers: { agent_id: "031-old" } },
      { source: "wazuh", sourceAssetId: "044-old", assetType: "endpoint", name: "ws-lon-009 (retired)", hostname: "ws-lon-009", primaryIp: "10.30.2.9", operatingSystem: "Microsoft Windows 10 Pro", environment: "corporate", businessUnit: "Corporate IT", criticality: 2, tags: ["workstations", "decommissioned"], identifiers: { agent_id: "044-old" } }
    ] }
  ];
  for (const b of batches) await inv.ingestAssets(inv.validateBatch(b.items), iso(T0 + b.at * HOUR));
  return `${batches.reduce((n, b) => n + b.items.length, 0)} assets from aws, azure, gcp, cmdb`;
});

await step("inventory: OpenCTI snapshot", async () => {
  for (const [entity, pages] of [["indicators", 2], ["vulnerabilities", 1], ["reports", 1], ["threat_actors", 1], ["malwares", 1]]) for (let i = 0; i < pages; i++) await syncSources.syncOpenCti(entity, 200, "demo seed");
});

const assetsNow = (await inv.readInventory()).assets;
const assetByName = (n) => assetsNow.find((a) => a.name === n || a.hostname === n);
const assetId = (n) => assetByName(n)?.id;

/* ========================================================== 3. CASES ========================================================== */
const caseIds = {};
const INCIDENTS = [
  { key: "A", sev: "critical", prio: 88, agent: "038", q: "payload.bin", owner: P.demoAnalyst.email, start: 300, status: ["triaged", "investigating"], title: "Phishing to credential theft on a finance workstation (ws-mum-114)",
    description: "An Invoice_Q4.xlsm macro launched encoded PowerShell on ws-mum-114, which downloaded a payload from a known Cobalt Strike server, dumped LSASS and then moved to fs-01 and dc-01 with a service account. Scope and containment under way.",
    evidence: [["timeline", "Wazuh", "Attack timeline: phishing mail to PsExec on fs-01", { steps: ["15:05 mail-01 delivers Invoice_Q4.xlsm to priya.n", "15:28 user opens link to secure-m365-login.example", "15:32 WINWORD.EXE spawns encoded PowerShell (download from 203.0.113.45)", "15:39 Defender real-time protection disabled", "15:44 LSASS dump via comsvcs.dll, Mimikatz sekurlsa::logonpasswords", "15:59 PsExec service installed on fs-01 as CORP\\svc_backup", "16:18 svc_backup2 created and added to Administrators on fs-01", "16:40 beaconing to 203.0.113.45:443 every 60 s"] }], ["ioc", "OpenCTI", "Indicators observed in the intrusion", { ip: ["203.0.113.45"], domains: ["update-check.example", "secure-m365-login.example"], sha256: ["9f2c4b7a…c2f7e41 (dropper)", "e6a1f3d8…c3d60e5f (Mimikatz)"], url: ["http://203.0.113.45/payload.bin"] }], ["host", "Analyst", "Host triage: ws-mum-114", { user: "priya.n (Finance)", osBuild: "Windows 11 23H2", edr: "Defender (disabled at 15:39)", netIsolation: "not yet isolated: waiting for IR lead approval" }], ["note", "Analyst", "Credential exposure assessment", { exposedAccounts: ["priya.n", "svc_backup"], action: "Reset both; rotate krbtgt twice if dc-01 compromise is confirmed" }]],
    notes: [["investigating", "Scope confirmed: fs-01 and dc-02 touched. Credential reset in progress."]] },
  { key: "B", sev: "critical", prio: 95, agent: "043", q: "lckd", owner: P.lead.email, start: 12, status: ["triaged", "investigating", "contained"], title: "Ransomware-like encryption on ws-lon-044 and the finance share",
    description: "Shadow copies were deleted and 1,842 files renamed to .lckd within four minutes on ws-lon-044; the activity then spread to \\\\fs-01\\finance over SMB. The host was disconnected from the network by the on-site team.",
    evidence: [["timeline", "Wazuh", "Encryption timeline", { steps: ["07:51 vssadmin delete shadows /all /quiet (m.rossi session)", "07:54 mass rename to .lckd on the local profile", "07:56 612 files renamed on \\\\fs-01\\finance via SMB", "08:02 host unplugged by the London desk"] }], ["ioc", "OpenCTI", "Ransomware payload", { sha256: ["3b8e5d1a…a613"], family: "LockBit 3.0 (low confidence)", note: ".lckd extension and README_RESTORE.txt match intel" }], ["note", "Analyst", "Recovery plan", { steps: ["Restore \\\\fs-01\\finance from last night's snapshot", "Rebuild ws-lon-044", "Reset m.rossi and all sessions on the host"], rto: "4 hours" }]],
    notes: [["contained", "Host isolated at the switch port; fs-01 share set read-only; snapshot restore scheduled."]] },
  { key: "C", sev: "high", prio: 82, agent: "003", q: "sha256 shell.php added", owner: P.a2.email, start: 175, status: ["triaged", "investigating"], title: "Web shell planted on web-03 after SQL injection",
    description: "sqlmap-style SQL injection from 198.51.100.17 was followed by a file upload and a PHP web shell in /uploads. web-03 now beacons to 192.0.2.141. The host is in the DMZ and serves the public site.",
    evidence: [["timeline", "Wazuh", "Web shell timeline", { steps: ["13:01 SQL injection burst from 198.51.100.17", "13:14 POST /uploads/upload.php returns 200", "13:17 /var/www/html/uploads/shell.php created (sha256 c41d7e0a…)", "13:20 rootcheck flags the backdoor", "13:30 beacon to 192.0.2.141:8443", "13:39 crontab replaced with a curl | sh job"] }], ["ioc", "OpenCTI", "Indicators", { ip: ["198.51.100.17", "192.0.2.141"], sha256: ["c41d7e0a…c0e29"] }], ["host", "Analyst", "Greenbone cross-check", { findings: ["PHP-CGI argument injection (CVE-2024-4577)", "Web shell in /uploads"], note: "The PHP-CGI finding explains the initial foothold." }]],
    notes: [["investigating", "Memory and disk images taken. Waiting for WAF rule to block 198.51.100.17 before reimaging."]] },
  { key: "D", sev: "high", prio: 74, agent: "009", q: "jndi", owner: P.a3.email, start: 100, status: ["triaged"], title: "Log4Shell exploitation attempts against app-04",
    description: "Four JNDI lookup attempts in request headers reached app-04 from two sources, one of them the Cobalt Strike server. Greenbone still reports CVE-2021-44228 on this host.",
    evidence: [["ioc", "OpenCTI", "Sources", { ip: ["198.51.100.18", "203.0.113.45"], callback: "ldap://203.0.113.45:1389/a" }], ["note", "Analyst", "Status of the fix", { detail: "3 of 4 nodes patched to 2.17.2. Node 4 pending restart; mitigation: log4j2.formatMsgNoLookups on all nodes." }]], notes: [] },
  { key: "E", sev: "high", prio: 72, agent: "025", q: "Lagos", owner: P.a4.email, start: 62, status: ["triaged", "investigating"], title: "VPN password spray followed by impossible-travel login (a.kumar)",
    description: "Eight failed VPN logins from a Lagos address across eight accounts, then an MFA-fatigue approval and a VPN login for a.kumar twelve minutes after a login from Mumbai.",
    evidence: [["ioc", "OpenCTI", "Source", { ip: ["203.0.113.9"], profile: "password spraying, score 74" }], ["note", "Analyst", "User contact", { detail: "a.kumar confirms he did not approve the MFA prompt. Session killed, password reset, device re-registered." }]], notes: [["investigating", "Session terminated. Checking mailbox rules and OAuth grants for a.kumar."]] },
  { key: "F", sev: "high", prio: 76, agent: "031", q: "PutBucketPolicy", owner: null, start: 22, status: [], title: "Root account used to make the backup bucket public (aws-prod-db-01 account)",
    description: "CloudTrail shows PutBucketPolicy by the root user from 192.0.2.150, opening meridian-prod-backups to the internet.", evidence: [["ioc", "OpenCTI", "Source", { ip: ["192.0.2.150"], note: "Same address as the db-02 data transfer" }]], notes: [] },
  { key: "G", sev: "medium", prio: 52, agent: "035", q: "privileged", owner: P.a1.email, start: 45, status: ["triaged"], title: "Privileged container started in the prod namespace (k8s-node-02)",
    description: "A pod with privileged: true and hostPID was created by a CI service account. Needs confirmation that the deployment is legitimate.", evidence: [["note", "Analyst", "Initial check", { detail: "No matching change ticket. CI pipeline owner contacted." }]], notes: [] },
  { key: "H", sev: "critical", prio: 90, agent: "015", q: "4.8", owner: P.lead.email, start: 40, status: ["triaged", "investigating"], title: "Possible database exfiltration from db-02 (4.8 GB to 192.0.2.150)",
    description: "mysqldump was started by the web-server account and 4.8 GB left db-02 to an external address 29 minutes later. db-02 holds customer records.",
    evidence: [["timeline", "Wazuh", "Sequence", { steps: ["07:20 mysqldump --all-databases by www-data", "07:49 4.8 GB to 192.0.2.150:443 over 14 minutes"] }], ["host", "Analyst", "Impact", { data: "Customer PII (approx. 1.2 M rows)", regulatory: "Possible breach notification duties: legal informed" }]], notes: [["investigating", "Egress to 192.0.2.150 blocked at the firewall. Legal and DPO notified."]] },
  { key: "I", sev: "medium", prio: 45, agent: "019", q: "RC4", owner: P.a2.email, start: 200, status: ["triaged", "investigating", "resolved"], title: "Kerberoasting alert on dc-01 (svc_backup)",
    description: "A service ticket for MSSQLSvc/db-03 was requested with RC4 by svc_backup. Part of the ws-mum-114 intrusion chain.", evidence: [["note", "Analyst", "Assessment", { detail: "Linked to case A; svc_backup already reset. Covered by the account-reset action there." }]], notes: [["resolved", "Covered by the credential reset in the phishing case. RC4 for service tickets disabled by GPO on 19 Nov."]] },
  { key: "J", sev: "low", prio: 30, agent: "010", q: "xk3jq9vbt2", owner: P.a3.email, start: 70, status: ["triaged", "investigating", "resolved"], title: "DNS queries to a generated domain from app-05",
    description: "212 NXDOMAIN lookups in ten minutes for xk3jq9vbt2.example.", evidence: [["note", "Analyst", "Root cause", { detail: "A misconfigured health-check library resolved random names to test the resolver. No malware found; the build was rolled back." }]], notes: [["resolved", "False positive: library bug, not a DGA. Library pinned to the previous version. Detection threshold tuned."]] }
];

const alertCache = new Map();
async function findAlert(agentId, query) {
  const body = await integ.wazuhIndexerSearch("wazuh-alerts-4.x-*", { size: 1, sort: [{ timestamp: { order: "desc" } }], query: { bool: { filter: [{ term: { "agent.id": agentId } }, { range: { "rule.level": { gte: 7 } } }], must: [{ simple_query_string: { query } }] } } });
  return body.hits.hits[0]?._id ?? null;
}

await step("cases from investigated alerts", async () => {
  let made = 0;
  for (const inc of INCIDENTS) {
    const alertId = await findAlert(inc.agent, inc.q);
    if (!alertId) { console.warn(`  no alert found for case ${inc.key}`); continue; }
    const result = await investigate.investigateAlert(alertId);
    alertCache.set(inc.key, { alertId, result });
    const { case: c } = await casesLib.openCaseFromAlert({ alert: { ...result.alert, timestamp: result.alert.timestamp }, searched: result.searched, openCtiConnected: result.openCti.connected, matches: result.correlation.matches.map((m) => ({ indicatorName: m.indicatorName, matchedValue: m.matchedValue, observableType: m.observableType, score: m.score })), vulnerabilities: result.vulnerabilities, techniques: result.techniques }, inc.owner ? P.a1 : P.a2);
    caseIds[inc.key] = c.id;
    made++;
  }
  return `${made} cases`;
});

// manual cases (not tied to an alert)
await step("manual cases", async () => {
  const f = (host, re) => byName(host, re)?.id;
  const manual = [
    { key: "K", input: { title: "USB mass-storage device on a finance workstation (ws-mum-118)", description: "A USB drive was mounted on ws-mum-118 outside working hours.", severity: "low", priorityScore: 30 }, owner: P.a4.email, status: ["triaged", "investigating", "closed"], note: "Confirmed with the user and the line manager: a signed-off firmware update for a hardware token. No action needed." , start: 1500 },
    { key: "L", input: { title: "Distributed SSH brute-force wave on the edge hosts", description: "Hundreds of failed SSH logins from 14 countries across jump-01, vpn-gw-01, web-01 and mail-01. Blocked automatically by active response.", severity: "low", priorityScore: 25 }, owner: P.a1.email, status: ["triaged", "investigating", "resolved"], note: "No successful logins. Source addresses blocked for 10 minutes by active response and added to the edge firewall deny list.", start: 1300 },
    { key: "M", input: { title: "Remediate Log4Shell on app-04 (CVE-2021-44228)", description: "Greenbone and Wazuh both report CVE-2021-44228 on app-04. Exploitation attempts were seen (see the Log4Shell case).", severity: "high", priorityScore: 78, links: { findingId: f("app-04", /Log4Shell/), assetId: assetId("app-04") } }, owner: P.demoAnalyst.email, status: ["triaged", "investigating"], start: 240 },
    { key: "N", input: { title: "Emergency patching: Zerologon enforcement on dc-01", description: "Greenbone reports CVE-2020-1472 on dc-01. Enforcement mode is not yet on.", severity: "critical", priorityScore: 92, links: { findingId: f("dc-01", /Zerologon/), assetId: assetId("dc-01") } }, owner: null, status: [], start: 100 },
    { key: "O", input: { title: "Review stale and never-connected Wazuh agents", description: "Three agents are disconnected, two never connected and one is pending registration. Confirm each is decommissioned or fix the enrolment.", severity: "low", priorityScore: 20, links: { assetId: assetId("ws-mum-207") } }, owner: P.demoAdmin.email, status: [], start: 2800 }
  ];
  for (const m of manual) {
    const c = await casesLib.createCase(m.input, P.a1);
    caseIds[m.key] = c.id;
    if (m.owner) await casesLib.assignCase(c.id, m.owner, P.lead);
    for (const s of m.status) await casesLib.transitionCase(c.id, s, ["resolved", "closed"].includes(s) ? m.note : "", P.a1);
  }
  return `${manual.length} cases`;
});

await step("case work: owners, evidence, status changes", async () => {
  for (const inc of INCIDENTS) {
    const id = caseIds[inc.key];
    if (!id) continue;
    if (inc.owner) await casesLib.assignCase(id, inc.owner, P.lead);
    for (const [type, source, title, content] of inc.evidence) await casesLib.addEvidence(id, { type, source, title, content }, inc.owner === P.demoAnalyst.email ? P.demoAnalyst : P.a1);
    let i = 0;
    for (const s of inc.status) {
      const note = inc.notes.find((n) => n[0] === s)?.[1] ?? "";
      await casesLib.transitionCase(id, s, note, inc.owner === P.lead.email ? P.lead : P.a1);
      if (i++ === 0 && s === "triaged") await casesLib.noteEvent(id, "investigation_plan_generated", P.a1, { steps: 6 });
    }
  }
  const second = [["K", "ioc"]];
  return "done";
});

/* ======================================================== 4. RESPONSE ======================================================== */
const respCfg = { enabled: true, allowedActions: new Set(["watch_asset", "isolate_endpoint", "block_ip", "disable_user", "quarantine_file", "run_scan"]), maxTargetLength: 300, approvalMaxAgeMinutes: 60, dualControl: true };
respAdapters.ensureAdapters();
await step("governed response proposals and executions", async () => {
  const prop = (actionType, target, rationale, links, actor) => respLib.createProposal({ actionType, target, rationale, links }, actor, respCfg);
  const out = {};
  out.iso = await prop("isolate_endpoint", "ws-lon-044", "Active ransomware encryption on ws-lon-044 and spread to the finance share over SMB. Containment before restore.", { alertId: alertCache.get("B")?.alertId, caseId: caseIds.B }, P.a3);
  await respLib.reviewProposal(out.iso.id, "approve", "Approved: confirmed encryption in progress. Run through the EDR console; this platform has no isolation adapter.", P.lead, respCfg);
  out.block = await prop("block_ip", "203.0.113.45", "Known Cobalt Strike server (OpenCTI score 92) contacted by ws-mum-114 and used in Log4Shell callbacks.", { caseId: caseIds.A }, P.demoAnalyst);
  out.user = await prop("disable_user", "svc_backup2", "Account created by the intruder and added to Administrators on fs-01.", { caseId: caseIds.A }, P.a1);
  out.rej = await prop("isolate_endpoint", "web-03", "Web shell present on a public web server.", { caseId: caseIds.C }, P.a2);
  await respLib.reviewProposal(out.rej.id, "reject", "Rejected for now: the host serves the public site. Use the WAF block first, reimage in the maintenance window.", P.admin, respCfg);
  out.scan = await prop("run_scan", "10.20.3.50", "Retest fs-01 after SMBv1 was disabled by GPO.", {}, P.a4);
  out.cancel = await prop("quarantine_file", "/var/www/html/uploads/shell.php", "Quarantine the web shell.", { caseId: caseIds.C }, P.a2);
  await respLib.cancelProposal(out.cancel.id, P.a2);
  // watch_asset is the one action that really executes (inside PrimeSEC only)
  for (const [name, finish] of [["ws-mum-114", "verified"], ["web-03", "rolled_back"], ["db-02", "executed"]]) {
    const id = assetId(name);
    if (!id) continue;
    const p = await prop("watch_asset", id, `Tag ${name} for extra attention while its case is open.`, { assetId: id, caseId: name === "db-02" ? caseIds.H : name === "web-03" ? caseIds.C : caseIds.A }, P.a1);
    await respLib.reviewProposal(p.id, "approve", "Approved. Low risk: only tags the asset inside PrimeSEC.", P.lead, respCfg);
    const ex = await respLib.executeProposal(p.id, `demo-${name}`, P.admin, undefined, respCfg);
    if (finish !== "executed") await respLib.verifyExecution(ex.execution.id);
    if (finish === "rolled_back") await respLib.rollbackExecution(ex.execution.id);
  }
  return `${Object.keys(out).length + 3} proposals`;
});

/* ===================================================== 5. AI AGENT SECURITY ===================================================== */
const agentAudit = { agents: [], calls: [], decisions: [] };
await step("AI agent registry, policies, gateway decisions, approvals", async () => {
  const reg = async (x) => agentLib.registerAgent(x, "rohan.iyer@meridian.example");
  const ag = {};
  ag.copilot = await reg({ name: "SOC Copilot", framework: "LangChain", model: "claude-sonnet", environment: "production", owner: "Security Operations", tools: ["alert.read", "case.comment", "intel.lookup", "asset.lookup"], dataClasses: ["internal"], privileges: "moderate", criticality: "high", notes: "Summarises alerts and drafts case notes. Read-only toward every platform." });
  ag.codebot = await reg({ name: "Code Review Bot", framework: "CrewAI", model: "claude-opus", environment: "production", owner: "Platform Engineering", tools: ["repo.read", "pull_request.comment", "ci.status"], dataClasses: ["source-code"], privileges: "low", criticality: "medium" });
  ag.hr = await reg({ name: "HR Onboarding Assistant", framework: "n8n", model: "gpt-4o", environment: "production", owner: "People Operations", tools: ["employee.read", "ticket.create", "email.draft"], dataClasses: ["personal", "confidential"], privileges: "moderate", criticality: "high" });
  ag.analyst = await reg({ name: "Data Analyst Agent", framework: "AutoGen", model: "claude-sonnet", environment: "staging", owner: "Data and Analytics", tools: ["warehouse.query", "report.publish"], dataClasses: ["customer-data", "financial"], privileges: "moderate", criticality: "high" });
  ag.chat = await reg({ name: "Customer Chat Assistant", framework: "Semantic Kernel", model: "claude-haiku", environment: "production", owner: "Digital Channels", tools: ["faq.search", "order.status", "ticket.create"], dataClasses: ["customer-data"], privileges: "low", criticality: "high" });
  ag.mcp = await reg({ name: "IT Helpdesk MCP Client", framework: "MCP client", model: "claude-sonnet", environment: "production", owner: "Corporate IT", tools: ["user.password_reset", "device.lookup", "ticket.read"], dataClasses: ["internal", "credential"], privileges: "high", criticality: "critical", notes: "Can reset passwords: every call goes through the gateway." });
  ag.old = await reg({ name: "Legacy Invoice Bot", framework: "Custom", model: "not reported", environment: "production", owner: "Finance Systems", tools: ["invoice.read", "payment.approve", "email.send"], dataClasses: ["financial"], privileges: "high", criticality: "critical" });
  await agentLib.setAgentStatus(ag.old.id, "suspended");
  await agentLib.createPolicy({ name: "Second review for sensitive actions in production", description: "Sensitive actions by production agents are also queued for a security reviewer.", condition: "sensitive_action", action: "review", severity: "medium" });
  await agentLib.createPolicy({ name: "Escalate calls from unknown agents", description: "A request from an agent that is not in the registry is held for review and counted.", condition: "unknown_agent", action: "review", severity: "high" });
  agentAudit.agents = Object.values(ag);
  const calls = [
    [ag.copilot, "alert.read", { dataClass: "internal" }, P.a1], [ag.copilot, "intel.lookup", { dataClass: "internal" }, P.a1], [ag.copilot, "case.comment", { dataClass: "internal" }, P.a2], [ag.codebot, "repo.read", { dataClass: "source-code" }, P.a3],
    [ag.chat, "faq.search", {}, P.a1], [ag.chat, "order.status", { dataClass: "customer-data" }, P.a1], [ag.hr, "employee.read", { dataClass: "personal" }, P.a2],
    [ag.mcp, "user.password_reset", { dataClass: "credential", sensitive: true }, P.a1], [ag.mcp, "user.password_reset", { dataClass: "credential", sensitive: true, target: "t.nguyen" }, P.a2],
    [ag.analyst, "warehouse.query", { dataClass: "customer-data" }, P.a3], [ag.analyst, "report.publish", { dataClass: "financial", target: "external-partner-portal", external: true, sensitive: true }, P.a3],
    [ag.hr, "email.send", { dataClass: "personal", external: true }, P.a2], [ag.chat, "order.refund", { dataClass: "financial", sensitive: true }, P.a1], [{ id: "agent-unknown-77f3" }, "db.dump", { dataClass: "confidential" }, P.a4], [ag.old, "payment.approve", { dataClass: "financial", sensitive: true }, P.a4]
  ];
  for (const [a, tool, extra, actor] of calls) agentAudit.calls.push({ r: await gateLib.authorize({ agentId: a.id, tool, ...extra }, actor), actor, extra });
  const state = await agentLib.readState();
  const pending = state.approvals.filter((a) => a.status === "pending");
  if (pending[0]) { await gateLib.decideApproval(pending[0].id, "approve", "Verified with the requester: a routine password reset for a locked-out user.", P.lead); agentAudit.decisions.push({ a: pending[0], decision: "approved" }); }
  if (pending[1]) { await gateLib.decideApproval(pending[1].id, "reject", "No ticket for this reset and the user is on leave.", P.lead); agentAudit.decisions.push({ a: pending[1], decision: "rejected" }); }
  return `${Object.keys(ag).length} agents`;
});

/* ================================================== 6. SAP ASSESSMENTS ================================================== */
await step("SAP gateway assessments", async () => {
  const systems = [
    { assetId: "SAP-PRD-S4H-01", saprouttab: 'P * * *\nS * * *', gatewayProfile: "snc/enable = 0\nsnc/permit_insecure_start = 1\ngw/acl_mode = 0", reginfo: "P TP=* HOST=*", secinfo: "P TP=* HOST=*" },
    { assetId: "SAP-QAS-S4H-01", saprouttab: 'P 10.20.0.0 10.20.1.21 3299\nKP "p:CN=router1.meridian.example, O=Meridian" * sapdp00', gatewayProfile: "snc/enable = 1\nsnc/permit_insecure_start = 0\ngw/acl_mode = 1", reginfo: "P TP=* HOST=local", secinfo: "P USER=* HOST=local TP=*" },
    { assetId: "SAP-BW-PRD-01", saprouttab: 'P * * 3200\nKP "p:CN=bw-router, O=Meridian" * sapdp00', gatewayProfile: "snc/enable = 1\nsnc/permit_insecure_start = 1\ngw/acl_mode = 1", reginfo: "P TP=* HOST=*", secinfo: "D USER=* HOST=* TP=*" },
    { assetId: "SAP-PO-01", saprouttab: 'KP "p:CN=po-router, O=Meridian" 10.20.1.0 10.20.1.30 3300', gatewayProfile: "snc/enable = 1\nsnc/permit_insecure_start = 0\ngw/acl_mode = 1", reginfo: "P TP=gwrd HOST=10.20.1.30", secinfo: "P USER=po_admin HOST=10.20.1.30 TP=gwrd" }
  ];
  for (const s of systems) await sapLib.assess(s, { explain: false, createdBy: P.a1.email });
  return `${systems.length} assessments`;
});

/* ===================================================== 7. DASHBOARD HISTORY ===================================================== */
await step("audit trail", async () => {
  const lines = [];
  const ev = (minAgo, actor, body) => lines.push({ eventId: `audit_${(T0 - minAgo * MIN).toString(36)}_${Math.random().toString(36).slice(2, 8)}`, timestamp: agoMin(minAgo), actor: { name: actor.name, email: actor.email, roles: actor.roles }, ...body });
  // investigations behind each case, newest alerts last so the dashboard list reads as a log
  for (const inc of INCIDENTS) {
    const hit = alertCache.get(inc.key);
    if (!hit) continue;
    const r = hit.result;
    ev(Math.max(2, inc.start - 4), inc.owner === P.demoAnalyst.email ? P.demoAnalyst : P.a1, {
      action: "alert_investigation_created",
      alert: { id: r.alert.id, level: r.alert.level, description: r.alert.description, agent: r.alert.agent, timestamp: r.alert.timestamp, sourceIp: r.alert.sourceIp },
      openCti: { connected: r.openCti.connected, searched: r.searched },
      correlation: { matchCount: r.correlation.matches.length, matchedIndicators: r.correlation.matches.slice(0, 5).map((m) => ({ id: m.indicatorId ?? m.indicatorName, name: m.indicatorName, matchedValue: m.matchedValue })) }
    });
  }
  agentAudit.agents.forEach((a, i) => ev(60 * 24 * (13 - i), P.admin, { action: "agent_registered", agent: { id: a.id, name: a.name, framework: a.framework, environment: a.environment, toolCount: a.tools.length } }));
  agentAudit.calls.forEach(({ r, actor, extra }, i) => ev(31 + i * 53, actor, { action: "agent_policy_evaluated", agentId: r.agent?.id ?? "unknown", tool: r.tool, decision: r.decision, dataClass: extra.dataClass ?? "internal", external: Boolean(extra.external), policyRevision: r.policyRevision, reasonPolicies: (r.reasons ?? []).map((x) => x.policyId) }));
  agentAudit.calls.forEach(({ r, actor }, i) => ev(30 + i * 53, actor, { action: "agent_gateway_decision", requestId: r.requestId, agentId: r.agent?.id ?? "unknown", tool: r.tool, decision: r.decision, status: r.status, approvalId: r.approvalId ?? null, authorizedByApproval: Boolean(r.authorizedByApproval), policyRevision: r.policyRevision }));
  agentAudit.decisions.forEach(({ a, decision }, i) => ev(20 + i * 11, P.lead, { action: "agent_approval_decided", approvalId: a.id, agentId: a.agentId, tool: a.tool, decision, requestedBy: a.requestedBy?.email ?? null }));
  const scopes = await vaptLib.readScopes();
  scopes.forEach((s, i) => { ev(60 * 24 * (6 - i), P.admin, { action: "vapt_scope_approved", scope: { id: s.id, name: s.name, targets: s.targets, authorizationReference: s.authorizationReference, expiresAt: s.expiresAt, includesPublicRanges: s.includesPublicRanges } }); if (s.status === "Revoked") ev(60 * 30, P.lead, { action: "vapt_scope_revoked", scope: { id: s.id, name: s.name, targets: s.targets, authorizationReference: s.authorizationReference, expiresAt: s.expiresAt, includesPublicRanges: s.includesPublicRanges } }); });
  for (const [d, task] of [[21, "w1"], [14, "w2"], [7, "w3"], [1, "w4"]]) ev(60 * 24 * d - 240, P.a1, { action: "vapt_findings_synchronized", imported: d === 21 ? 82 : 17, updated: d === 21 ? 0 : 60, missing: d === 21 ? 0 : 6, total: 147, truncated: false });
  ev(60 * 5, P.a2, { action: "vapt_assessment_requested", target: "172.16.10.12", reason: undefined });
  ev(60 * 5 - 1, P.a2, { action: "vapt_assessment_started", target: "172.16.10.12", assessment: { taskId: "demo-retest-1", targetId: "demo-target-1", targetName: "Retest web-02 Apache fix (demo)", status: "Requested" } });
  ev(60 * 9, P.a3, { action: "vapt_assessment_denied", target: "198.51.100.40", reason: "The target is outside every approved scope." });
  ev(26 * 60, P.a1, { action: "inventory_ingested", origin: "sync", sources: ["wazuh"], accepted: agentRows.length, created: 0, updated: agentRows.length });
  ev(18 * 60, P.admin, { action: "graph_write", operation: "project", summary: { nodes: 220, relationships: 780, linked: 780, skipped: 0 } });
  ev(8 * 60, P.demoAdmin, { action: "platform_launch", platform: "wazuh", outcome: "opened" });
  ev(3 * 60, P.demoAdmin, { action: "platform_launch", platform: "opencti", outcome: "opened" });
  lines.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  fs.appendFileSync(path.join(dataDir, "audit-events.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  return `${lines.length} events`;
});

/* ====================================================== 8. TIMELINE REWRITE ====================================================== */
// The functions above stamp "now". Spread the records over realistic windows so timelines, ages and "last updated" columns read naturally.
await step("re-time cases, findings, response, agents, SAP", async () => {
  const readJson = (n) => JSON.parse(fs.readFileSync(path.join(dataDir, n), "utf8"));
  const writeJson = (n, v) => fs.writeFileSync(path.join(dataDir, n), JSON.stringify(v));
  const seeded = (s) => { let x = [...s].reduce((h, c) => (Math.imul(h, 31) + c.charCodeAt(0)) | 0, 17); return () => { x = (Math.imul(x, 1103515245) + 12345) & 0x7fffffff; return x / 0x7fffffff; }; };
  // cases
  const cases = readJson("cases.json");
  const startByKey = Object.fromEntries([...INCIDENTS.map((i) => [i.key, i.start]), ["K", 1500], ["L", 1300], ["M", 240], ["N", 100], ["O", 2800]]);
  const keyById = Object.fromEntries(Object.entries(caseIds).map(([k, v]) => [v, k]));
  for (const c of cases.cases) {
    const key = keyById[c.id];
    const inc = INCIDENTS.find((i) => i.key === key);
    if (inc) { c.title = inc.title; c.description = inc.description; c.severity = inc.sev; c.priorityScore = inc.prio; }
    const start = T0 - (startByKey[key] ?? 600) * MIN;
    const closed = ["resolved", "closed"].includes(c.status);
    const jitter = 0.45 + 0.55 * ((([...c.id].reduce((h, ch) => h + ch.charCodeAt(0), 0)) % 17) / 16);
    const span = Math.round(Math.min(closed ? 6 * HOUR : 90 * MIN, Math.max(20 * MIN, T0 - start - 2 * MIN)) * jitter);
    const n = c.events.length + c.evidence.length;
    const items = [...c.events.map((e) => ({ e, kind: "event" })), ...c.evidence.map((e) => ({ e, kind: "evidence" }))];
    c.createdAt = iso(start);
    c.events.sort((a, b) => a.at.localeCompare(b.at));
    c.events.forEach((e, i) => { e.at = iso(start + Math.round((span * i) / Math.max(1, c.events.length - 1 || 1))); });
    c.evidence.forEach((e, i) => { e.createdAt = iso(start + Math.round(span * 0.25) + i * 7 * MIN); });
    c.updatedAt = c.events.length ? c.events[c.events.length - 1].at : c.createdAt;
    if (closed) c.closedAt = c.updatedAt;
    if (c.snapshot) c.snapshot.capturedAt = iso(start);
  }
  writeJson("cases.json", cases);
  // response
  const resp = readJson("response.json");
  resp.proposals.forEach((p, i) => { const t = T0 - (35 + i * 17) * MIN; p.proposedAt = iso(t); if (p.reviewedAt) p.reviewedAt = iso(t + 6 * MIN); });
  const proposalTime = new Map(resp.proposals.map((p) => [p.id, Date.parse(p.proposedAt)]));
  resp.executions.forEach((x) => { const t = (proposalTime.get(x.proposalId) ?? T0) + 12 * MIN; x.createdAt = iso(t); x.updatedAt = iso(t + 4 * MIN); });
  writeJson("response.json", resp);
  // findings: analyst updates happened over the last days
  const fs2 = readJson("vapt-findings.json");
  const r = seeded("findings");
  for (const f of fs2) if (f.updatedAt) { f.updatedAt = iso(T0 - Math.floor(r() * 5 * DAY) - HOUR); if (f.retestRequestedAt) f.retestRequestedAt = iso(Date.parse(f.updatedAt)); }
  writeJson("vapt-findings.json", fs2);
  // scopes
  const sc = readJson("vapt-scopes.json");
  sc.forEach((s, i) => { s.createdAt = iso(T0 - (6 - i) * DAY); if (s.revokedAt) s.revokedAt = iso(T0 - 30 * HOUR); });
  writeJson("vapt-scopes.json", sc);
  // AI-agent security
  const st = readJson("agentsec-state.json");
  const r2 = seeded("agents");
  st.agents.forEach((a, i) => { if (!a.seeded) a.createdAt = iso(T0 - (14 - i) * DAY); });
  st.findings.forEach((f) => { const t = T0 - Math.floor(r2() * 20 * HOUR) - 5 * MIN; f.lastSeenAt = iso(t); f.firstSeenAt = iso(t - Math.floor(r2() * 8) * HOUR); });
  st.approvals.forEach((a) => { const t = T0 - Math.floor(r2() * 90) * MIN - MIN; a.createdAt = iso(t); a.expiresAt = iso(t + 30 * MIN); if (a.decidedAt) a.decidedAt = iso(t + 7 * MIN); if (a.approvedUntil) a.approvedUntil = iso(t + 17 * MIN); });
  writeJson("agentsec-state.json", st);
  // SAP
  const sap = readJson("sap-assessments.json");
  (Array.isArray(sap) ? sap : sap.items ?? []).forEach((a, i) => { a.createdAt = iso(T0 - (i * 2 + 1) * DAY); });
  writeJson("sap-assessments.json", sap);
});

/* =========================================================== 9. GRAPH =========================================================== */
await step("Neo4j graph (namespace " + (process.env.NEO4J_NAMESPACE || "primesec") + ")", async () => {
  const graph = new graphLib.GraphClient();
  if (!graph.configured) return "skipped: NEO4J_* is not configured";
  if (!(await graph.health().catch((e) => { console.warn('  neo4j health:', e.message); return false; }))) return "skipped: Neo4j is not reachable";
  await graph.ensureSchema();
  await graph.run([{ statement: "MATCH (n {tenant_id:$ns}) DETACH DELETE n", parameters: { ns: process.env.NEO4J_NAMESPACE || "primesec" } }]);
  const store = await inv.readInventory();
  const batch = graphLib.projectInventory(store);
  const id = (n) => assetsNow.find((a) => a.name === n || a.hostname === n || a.name === `${n} (RDS)`)?.id;
  const nodes = [], rels = [];
  const node = (type, nid, properties) => nodes.push({ type, id: nid, properties: { origin: "demo", ...properties } });
  const rel = (sourceType, sourceId, type, targetType, targetId, properties) => { if (sourceId && targetId) rels.push({ sourceType, sourceId, type, targetType, targetId, properties: { origin: "demo", ...properties } }); };
  // business applications and the hosts that support them
  const apps = { Portal: ["Customer Portal", ["web-01", "web-02", "web-03", "api-gw-01", "app-01", "app-02", "db-01", "aws-prod-web-01"]], Payments: ["Payments Gateway", ["app-04", "db-03", "azure-app-01", "api-gw-02"]], Core: ["Core Banking API", ["app-05", "app-06", "db-02", "db-04", "aws-prod-api-01", "aws-prod-db-01"]], Dwh: ["Data Warehouse and Reporting", ["gcp-analytics-01", "db-04"]], Hr: ["HR and Payroll", ["fs-01", "db-03"]], Mail: ["Email and Collaboration", ["mail-01", "mail-02", "adfs-01", "dc-01", "dc-02"]] };
  for (const [k, [name, hosts]] of Object.entries(apps)) { node("BusinessApplication", `app-${k}`, { name }); for (const h of hosts) rel("Asset", id(h), "SUPPORTS_APPLICATION", "BusinessApplication", `app-${k}`); }
  // software
  const sw = { nginx: ["nginx 1.18", ["web-01", "web-02", "web-04", "aws-prod-web-01"]], apache: ["Apache httpd 2.4.49", ["web-02", "web-03"]], php: ["PHP 8.1 (CGI)", ["web-03"]], log4j: ["Apache Log4j 2.14", ["app-04", "app-02"]], jenkins: ["Jenkins 2.426", ["app-01"]], pg: ["PostgreSQL 15.4", ["db-01"]], mysql: ["MySQL 8.0.35", ["db-02"]], mssql: ["SQL Server 2012", ["db-03"]], openssh: ["OpenSSH 9.6", ["jump-01", "vpn-gw-01", "web-01"]], openvpn: ["OpenVPN 2.6.8", ["vpn-gw-01", "vpn-gw-02"]], docker: ["Docker Engine 24", ["app-02", "k8s-node-01", "k8s-node-02", "k8s-node-03"]] };
  for (const [k, [name, hosts]] of Object.entries(sw)) { node("Software", `sw-${k}`, { name }); for (const h of hosts) rel("Asset", id(h), "RUNS_SOFTWARE", "Software", `sw-${k}`); }
  // identities
  const idents = { "priya.n": ["Priya N (Finance)", ["ws-mum-114", "fs-01"]], "a.kumar": ["A. Kumar (Engineering)", ["vpn-gw-01", "ws-mum-101"]], svc_backup: ["svc_backup (service account)", ["fs-01", "dc-01", "bk-01"]], svc_backup2: ["svc_backup2 (created by intruder)", ["fs-01", "dc-02"]], "m.rossi": ["M. Rossi (Finance, London)", ["ws-lon-044"]], svc_sql: ["svc_sql (service account)", ["db-03"]], "ci-deploy": ["ci-deploy (IAM)", ["aws-prod-api-01", "k8s-node-02"]] };
  for (const [k, [name, hosts]] of Object.entries(idents)) { node("Identity", `id-${k}`, { name }); for (const h of hosts) rel("Asset", id(h), "HAS_IDENTITY", "Identity", `id-${k}`); }
  // network paths (what talks to what)
  const paths = [["web-01", "app-01"], ["web-02", "app-02"], ["web-03", "app-01"], ["web-03", "db-01"], ["web-04", "app-05"], ["api-gw-01", "app-04"], ["api-gw-02", "app-05"], ["app-01", "db-01"], ["app-02", "db-02"], ["app-04", "db-03"], ["app-05", "db-04"], ["vpn-gw-01", "jump-01"], ["jump-01", "dc-01"], ["jump-01", "app-01"], ["ws-mum-114", "fs-01"], ["ws-mum-114", "dc-01"], ["fs-01", "dc-01"], ["fs-01", "dc-02"], ["ws-lon-044", "fs-01"], ["mail-01", "adfs-01"], ["adfs-01", "dc-01"], ["bk-01", "fs-01"], ["bk-01", "db-01"], ["aws-prod-web-01", "aws-prod-api-01"], ["aws-prod-api-01", "aws-prod-db-01"], ["k8s-node-01", "aws-prod-api-01"], ["gcp-analytics-01", "db-04"]];
  for (const [a, b] of paths) rel("Asset", id(a), "CONNECTED_TO", "Asset", id(b), { protocol: "tcp" });
  // the threat picture: alerts, indicators, actors, techniques
  const IOCS = { "203.0.113.45": "Cobalt Strike server (203.0.113.45)", "192.0.2.141": "C2 address (192.0.2.141)", "192.0.2.150": "Exfiltration server (192.0.2.150)", "203.0.113.9": "Password-spray source (203.0.113.9)", "198.51.100.17": "SQL injection source (198.51.100.17)", "198.51.100.18": "Log4Shell scanner (198.51.100.18)", "secure-m365-login.example": "Phishing domain", "9f2c4b7a…": "Dropper hash (Invoice_Q4.xlsm)", "3b8e5d1a…": "Ransomware payload (.lckd)" };
  Object.entries(IOCS).forEach(([k, name]) => node("Indicator", `ioc-${k}`, { name }));
  const actors = { apt29: ["APT29", "Espionage; Cobalt Strike, phishing"], lockbit: ["LockBit", "Ransomware-as-a-service"], fin7: ["FIN7", "Financially motivated; phishing, web exploitation"], scattered: ["Scattered Spider", "Help-desk social engineering, MFA fatigue"] };
  Object.entries(actors).forEach(([k, [name, d]]) => node("ThreatActor", `ta-${k}`, { name, description: d }));
  const techs = { T1566: "Phishing", "T1059.001": "PowerShell", "T1003.001": "LSASS Memory", "T1021.002": "SMB / Admin Shares", T1486: "Data Encrypted for Impact", T1190: "Exploit Public-Facing Application", "T1505.003": "Web Shell", T1048: "Exfiltration Over Alternative Protocol", "T1078": "Valid Accounts", T1621: "MFA Request Generation", T1611: "Escape to Host" };
  Object.entries(techs).forEach(([k, name]) => node("Technique", `tech-${k}`, { name }));
  for (const [k, ids] of Object.entries({ apt29: ["203.0.113.45", "secure-m365-login.example"], lockbit: ["3b8e5d1a…"], fin7: ["9f2c4b7a…", "192.0.2.141"], scattered: ["203.0.113.9"] })) for (const i of ids) rel("Indicator", `ioc-${i}`, "ATTRIBUTED_TO", "ThreatActor", `ta-${k}`, { confidence: "assessed" });
  for (const [k, ts] of Object.entries({ apt29: ["T1566", "T1059.001", "T1003.001", "T1078"], lockbit: ["T1486", "T1021.002"], fin7: ["T1190", "T1505.003", "T1566"], scattered: ["T1621", "T1078"] })) for (const t of ts) rel("ThreatActor", `ta-${k}`, "USES_TECHNIQUE", "Technique", `tech-${t}`);
  for (const [actor, cve] of [["lockbit", "CVE-2021-34527"], ["fin7", "CVE-2024-4577"], ["apt29", "CVE-2021-44228"], ["lockbit", "CVE-2017-0144"]]) rel("ThreatActor", `ta-${actor}`, "EXPLOITS", "Vulnerability", cve);
  // alerts from the planted incidents, linked to assets and indicators
  const alertSpecs = [
    ["A", "ws-mum-114", ["203.0.113.45", "secure-m365-login.example", "9f2c4b7a…"], ["T1059.001", "T1566"]], ["B", "ws-lon-044", ["3b8e5d1a…"], ["T1486"]], ["C", "web-03", ["198.51.100.17", "192.0.2.141"], ["T1505.003", "T1190"]],
    ["D", "app-04", ["198.51.100.18", "203.0.113.45"], ["T1190"]], ["E", "vpn-gw-01", ["203.0.113.9"], ["T1078", "T1621"]], ["F", "aws-prod-db-01", ["192.0.2.150"], ["T1078"]], ["G", "k8s-node-02", [], ["T1611"]], ["H", "db-02", ["192.0.2.150"], ["T1048"]], ["I", "dc-01", [], ["T1003.001"]], ["J", "app-05", [], []]
  ];
  for (const [k, host, iocs, ts] of alertSpecs) {
    const hit = alertCache.get(k);
    if (!hit) continue;
    const aid = hit.alertId;
    node("Alert", aid, { name: hit.result.alert.description.slice(0, 80), level: hit.result.alert.level, agent: hit.result.alert.agent, timestamp: hit.result.alert.timestamp });
    rel("Asset", id(host), "GENERATED_ALERT", "Alert", aid, {});
    for (const i of iocs) rel("Alert", aid, "MATCHES_INDICATOR", "Indicator", `ioc-${i}`, {});
    for (const t of ts) rel("Alert", aid, "USES_TECHNIQUE", "Technique", `tech-${t}`, {});
  }
  const all = { nodes: [...batch.nodes, ...nodes], relationships: [...batch.relationships, ...rels] };
  let linked = 0, skipped = 0;
  const chunks = [];
  for (let i = 0; i < all.nodes.length; i += 150) chunks.push({ nodes: all.nodes.slice(i, i + 150), relationships: [] });
  for (let i = 0; i < all.relationships.length; i += 200) chunks.push({ nodes: [], relationships: all.relationships.slice(i, i + 200) });
  for (const chunk of chunks) { const r = await graph.upsert(chunk); linked += r.linked; skipped += r.skipped; }
  return `${all.nodes.length} nodes, ${all.relationships.length} relationships (${skipped} skipped)`;
});

console.log("\nDemo data ready in", DATA_DIR);
