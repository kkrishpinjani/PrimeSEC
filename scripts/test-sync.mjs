// Tests for continuous synchronisation: run history, watermarks, overlap guard, mapping, marking policy, failure handling.
// Run: npm run test:sync (Node 22.6+; TypeScript is type-stripped).
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const root = process.cwd();
const work = mkdtempSync(path.join(tmpdir(), "primesec-sync-"));
process.chdir(work);
const url = (f) => path.join(root, "lib", f).replace(/\\/g, "/").replace(/^([A-Za-z]):/, "file:///$1:");
const S = await import(url("sync.ts"));
const I = await import(url("inventory.ts"));

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };

const agent = (id, over = {}) => ({ id, name: `host-${id}`, status: "active", ip: `10.0.0.${Number(id) + 1}`, version: "Wazuh v4.9", os: "Ubuntu 22.04", groups: ["default"], ...over });

// ---- Wazuh mapping ----
const m = S.wazuhAgentToAsset(agent("004"));
ok("agent id becomes a durable identifier", m.identifiers.agent_id === "004" && m.primaryIp === "10.0.0.5" && m.assetType === "endpoint");
ok("agent 000 is the manager server", S.wazuhAgentToAsset(agent("000")).assetType === "server");
ok("a null ip stays null", S.wazuhAgentToAsset(agent("5", { ip: null })).primaryIp === null);

// ---- asset sync: success ----
const r1 = await S.runAssetSync("wazuh", "admin@x", async () => ({ items: [agent("001"), agent("002")].map(S.wazuhAgentToAsset) }));
ok("run completes with counts", r1.run.status === "completed" && r1.run.recordsSeen === 2 && r1.run.recordsIngested === 2 && r1.ingest.created === 2);
ok("run records who started it", r1.run.triggeredBy === "admin@x");
const r2 = await S.runAssetSync("wazuh", "admin@x", async () => ({ items: [agent("001"), agent("003")].map(S.wazuhAgentToAsset) }));
ok("a second run updates one asset and creates one", r2.ingest.created === 1 && r2.ingest.updated === 1);
ok("inventory holds three assets, not four", (await I.readInventory()).assets.length === 3);
const wm = await S.listWatermarks();
ok("a watermark is stored per source and stream", wm.length === 1 && wm[0].source === "wazuh" && wm[0].stream === "assets" && wm[0].cursor.records === 2);
const runs = await S.listRuns();
ok("history is newest first", runs.length === 2 && runs[0].id === r2.run.id);
ok("history filters by source", (await S.listRuns({ source: "greenbone" })).length === 0);

// ---- asset sync: failures ----
const f1 = await S.runAssetSync("wazuh", "a", async () => { throw Object.assign(new Error("Wazuh API request failed (500) at https://wazuh.internal:55000/agents?token=abc"), {}); });
ok("a failing fetch is recorded as failed", f1.run.status === "failed" && f1.ingest === null);
ok("the stored error has no URL", !/https?:/.test(f1.run.error) && f1.run.error.includes("[url]"), f1.run.error);
ok("a failure does not move the watermark", (await S.listWatermarks())[0].cursor.records === 2);
const f2 = await S.runAssetSync("wazuh", "a", async () => ({ items: [agent("010").name, { source: "wazuh" }] }));
ok("invalid records fail the whole run and ingest nothing", f2.run.status === "failed" && (await I.readInventory()).assets.length === 3, f2.run.error);
const f3 = await S.runAssetSync("wazuh", "a", async () => { throw Object.assign(new Error("Wazuh API URL or credentials are not configured."), { code: "NOT_CONFIGURED" }); });
ok("a not-configured platform says so", f3.run.status === "failed" && f3.run.error.includes("not configured"));
const empty = await S.runAssetSync("wazuh", "a", async () => ({ items: [] }));
ok("an empty but successful read completes with zero", empty.run.status === "completed" && empty.run.recordsSeen === 0);

// ---- overlap guard ----
let release;
const gate = new Promise((r) => { release = r; });
const slow = S.runAssetSync("greenbone", "a", async () => { await gate; return { items: [] }; });
await new Promise((r) => setTimeout(r, 50));
let blocked = null;
try { await S.runAssetSync("greenbone", "b", async () => ({ items: [] })); } catch (e) { blocked = e; }
ok("a second run of the same source is refused while one is live", blocked?.code === "CONFLICT", blocked?.message);
const other = await S.runAssetSync("wazuh", "c", async () => ({ items: [] }));
ok("a different source is not blocked", other.run.status === "completed");
release();
await slow;
const after = await S.runAssetSync("greenbone", "b", async () => ({ items: [] }));
ok("the source is free again after the run finishes", after.run.status === "completed");

// ---- stale runs ----
await S.runAssetSync("greenbone", "x", async () => ({ items: [] }), Date.now() - 3600_000).catch(() => {});
let staleGate;
const g2 = new Promise((r) => { staleGate = r; });
const orphan = S.runAssetSync("greenbone", "orphan", async () => { await g2; return { items: [] }; }, Date.now() - 3600_000);
await new Promise((r) => setTimeout(r, 50));
const recovered = await S.runAssetSync("greenbone", "next", async () => ({ items: [] }));
ok("a run older than the stale limit no longer blocks a new one", recovered.run.status === "completed");
ok("the stale run is marked interrupted", (await S.listRuns({ source: "greenbone" })).some((r) => r.status === "failed" && /Interrupted/.test(r.error ?? "")));
staleGate();
await orphan;

// ---- Greenbone findings -> assets ----
const F = (over) => ({ id: "f1", host: "10.1.1.1", port: "443/tcp", name: "Weak TLS", oid: "1.3.6.1", cves: ["CVE-2024-0001"], severityScore: 7.5, severity: "High", remediationStatus: "Open", threat: "High", ...over });
const hosts = new Map([["10.1.1.1", { criticality: "Critical", exposure: "Internet-facing" }]]);
const gb = S.findingsToAssets([F(), F({ id: "f2", name: "Old", oid: "9", cves: [], severityScore: 4, severity: "Medium", remediationStatus: "Resolved" }), F({ id: "f3", host: "App01", oid: "7", cves: [] })], hosts);
ok("one asset per host", gb.length === 2);
const g1 = gb.find((a) => a.sourceAssetId === "10.1.1.1");
ok("host settings carry over (Critical = 5, internet-facing)", g1.criticality === 5 && g1.internetFacing === true && g1.primaryIp === "10.1.1.1" && g1.hostname === null);
ok("resolved findings are closed, others open", g1.vulnerabilities.find((v) => v.title === "Old").status === "closed" && g1.vulnerabilities.find((v) => v.title === "Weak TLS").status === "open");
ok("an unknown host has unknown criticality and is a hostname", gb.find((a) => a.sourceAssetId === "app01").criticality === null && gb.find((a) => a.sourceAssetId === "app01").hostname === "App01");
ok("the vulnerability key prefers the CVE, then the NVT oid", g1.vulnerabilities[0].key === "CVE-2024-0001" && g1.vulnerabilities[1].key === "9");
const gbRun = await S.runAssetSync("greenbone", "a", async () => ({ items: gb }));
ok("mapped findings pass inventory validation and ingest", gbRun.run.status === "completed" && gbRun.ingest.created === 2, gbRun.run.error);

// ---- OpenCTI: markings ----
ok("no allow-list means no restriction", S.allowedMarkings("") === null && S.allowedMarkings(undefined) === null);
const allow = S.allowedMarkings("TLP:CLEAR, tlp:green");
const rec = (id, markings) => ({ id, name: `Name ${id}`, markings, fields: { pattern: "[ipv4-addr:value = '1.2.3.4']" } });
const now = "2026-01-01T00:00:00Z";
ok("an allowed marking keeps content", !S.toIntelObject("indicators", rec("a", ["TLP:CLEAR"]), allow, now).restricted && S.toIntelObject("indicators", rec("a", ["TLP:GREEN"]), allow, now).payload.pattern.startsWith("["));
const red = S.toIntelObject("indicators", rec("b", ["TLP:RED"]), allow, now);
ok("a disallowed marking drops name and content", red.restricted && red.name === "" && red.payload === null && red.markings[0] === "TLP:RED");
ok("one disallowed marking among allowed ones restricts", S.toIntelObject("indicators", rec("c", ["TLP:CLEAR", "TLP:RED"]), allow, now).restricted);
ok("an unmarked object is restricted when a list is set", S.toIntelObject("indicators", rec("d", []), allow, now).restricted);
ok("an unmarked object is kept when no list is set", !S.toIntelObject("indicators", rec("d", []), null, now).restricted);

// ---- OpenCTI: paging and watermark ----
const pages = [
  { items: [rec("1", ["TLP:CLEAR"]), rec("2", ["TLP:RED"])], endCursor: "c2", hasNextPage: true },
  { items: [rec("3", ["TLP:CLEAR"])], endCursor: "c3", hasNextPage: false },
  { items: [rec("1", ["TLP:CLEAR"])], endCursor: "c1", hasNextPage: false }
];
const seen = [];
const fetcher = (after) => { seen.push(after); return Promise.resolve(pages[seen.length - 1]); };
const o1 = await S.runOpenCtiSync("indicators", "a", fetcher, allow);
ok("first page starts from the top", seen[0] === null && o1.run.recordsSeen === 2);
ok("a restricted object is mentioned in the run note", /1 object/.test(o1.run.note ?? ""), o1.run.note);
const o2 = await S.runOpenCtiSync("indicators", "a", fetcher, allow);
ok("the next run resumes from the stored cursor", seen[1] === "c2", String(seen[1]));
const o3 = await S.runOpenCtiSync("indicators", "a", fetcher, allow);
ok("after the last page, the stream starts over", seen[2] === null);
const intel = await S.listIntel({ entityType: "indicators" });
ok("objects are stored once each (upsert by entity + id)", intel.length === 3 && new Set(intel.map((o) => o.externalId)).size === 3);
ok("the restricted object holds no content in storage", intel.find((o) => o.externalId === "2").payload === null);
const bad = await S.runOpenCtiSync("indicators", "a", async () => { throw new Error("OpenCTI GraphQL request failed (401)."); }, allow);
ok("an OpenCTI failure is recorded and keeps the cursor", bad.run.status === "failed" && (await S.listWatermarks()).find((w) => w.stream === "indicators").cursor.endCursor === "c1");

// ---- bounds ----
for (let i = 0; i < 230; i++) await S.runAssetSync("wazuh", "a", async () => ({ items: [] }));
ok("run history is capped", (await S.readSync()).runs.length === 200);

console.log(`sync: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
