// Tests for the optional sync scheduler: configuration, one pass over the sources, overlap and failure isolation, paging, status.
// Uses the real sync engine (lib/sync.ts) with fake fetchers. Run: npm run test:scheduler (Node 22.6+).
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const root = process.cwd();
process.chdir(mkdtempSync(path.join(tmpdir(), "primesec-sched-")));
const url = (f) => path.join(root, "lib", f).replace(/\\/g, "/").replace(/^([A-Za-z]):/, "file:///$1:");
const Sch = await import(url("syncScheduler.ts"));
const S = await import(url("sync.ts"));
const I = await import(url("inventory.ts"));

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };

// ---- configuration ----
ok("off by default and when empty or invalid", [undefined, "", "abc", "0", "4", "1441", "-5", "NaN"].every((v) => Sch.schedulerConfig({ SYNC_SCHEDULE_MINUTES: v }) === null));
const cfg = Sch.schedulerConfig({ SYNC_SCHEDULE_MINUTES: "15" });
ok("a valid interval turns it on with defaults", cfg.intervalMs === 15 * 60_000 && cfg.sources.join() === "wazuh,greenbone,opencti" && cfg.openctiEntities.join() === "vulnerabilities,indicators" && cfg.openctiMaxPages === 5);
ok("the bounds are accepted", Sch.schedulerConfig({ SYNC_SCHEDULE_MINUTES: "5" }).intervalMs === 300_000 && Sch.schedulerConfig({ SYNC_SCHEDULE_MINUTES: "1440" }).intervalMs === 86_400_000);
ok("sources can be limited, and unknown names are ignored", Sch.schedulerConfig({ SYNC_SCHEDULE_MINUTES: "10", SYNC_SCHEDULE_SOURCES: " WAZUH , bogus" }).sources.join() === "wazuh");
ok("only unknown sources means off, not a crash", Sch.schedulerConfig({ SYNC_SCHEDULE_MINUTES: "10", SYNC_SCHEDULE_SOURCES: "bogus" }) === null);
ok("OpenCTI entities are checked against the supported list, with a safe fallback", Sch.schedulerConfig({ SYNC_SCHEDULE_MINUTES: "10", SYNC_SCHEDULE_OPENCTI_ENTITIES: "users, indicators" }).openctiEntities.join() === "indicators" && Sch.schedulerConfig({ SYNC_SCHEDULE_MINUTES: "10", SYNC_SCHEDULE_OPENCTI_ENTITIES: "users" }).openctiEntities.join() === "vulnerabilities");
ok("the page limit is bounded", Sch.schedulerConfig({ SYNC_SCHEDULE_MINUTES: "10", SYNC_SCHEDULE_OPENCTI_MAX_PAGES: "999" }).openctiMaxPages === 5 && Sch.schedulerConfig({ SYNC_SCHEDULE_MINUTES: "10", SYNC_SCHEDULE_OPENCTI_MAX_PAGES: "3" }).openctiMaxPages === 3);

// ---- a pass over the sources, using the real engine ----
const agent = (id) => ({ source: "wazuh", sourceAssetId: id, identifiers: { agent_id: id }, name: "host-" + id });
const calls = [];
const audited = [];
let wazuhBehaviour = "ok";
let pages = [
  { items: [{ id: "1", name: "a", markings: ["TLP:CLEAR"], fields: {} }], endCursor: "c1", hasNextPage: true },
  { items: [{ id: "2", name: "b", markings: ["TLP:CLEAR"], fields: {} }], endCursor: "c2", hasNextPage: true },
  { items: [{ id: "3", name: "c", markings: ["TLP:CLEAR"], fields: {} }], endCursor: "c3", hasNextPage: false }
];
let pageIx = 0;
const runners = {
  wazuh: (by) => { calls.push(["wazuh", by]); return S.runAssetSync("wazuh", by, async () => { if (wazuhBehaviour === "fail") throw new Error("Wazuh API request failed (500)."); return { items: [agent("1"), agent("2")] }; }); },
  greenbone: (by) => { calls.push(["greenbone", by]); return S.runAssetSync("greenbone", by, async () => ({ items: [{ source: "greenbone", sourceAssetId: "10.0.0.5", primaryIp: "10.0.0.5", name: "10.0.0.5" }] })); },
  opencti: (entity, by) => { calls.push(["opencti", entity, by]); return S.runOpenCtiSync(entity, by, async () => pages[Math.min(pageIx++, pages.length - 1)], null); },
  audit: async (o) => { audited.push(o.run); }
};
const full = Sch.schedulerConfig({ SYNC_SCHEDULE_MINUTES: "15", SYNC_SCHEDULE_OPENCTI_ENTITIES: "vulnerabilities" });
const r1 = await Sch.tick(full, runners);
ok("one pass runs wazuh, greenbone and every OpenCTI page of the stream", r1.map((r) => `${r.source}/${r.stream}`).join() === "wazuh/assets,greenbone/assets,opencti/vulnerabilities,opencti/vulnerabilities,opencti/vulnerabilities" && r1.every((r) => r.status === "completed"), JSON.stringify(r1));
ok("paging stops at the end of the stream (3 pages) and resumed from the stored cursor", pageIx === 3);
ok("every run names the scheduler as the actor", calls.every((c) => c.at(-1) === "scheduler") && audited.every((a) => a.triggeredBy === "scheduler"));
ok("every run was audited", audited.length === 5);
ok("the inventory was really updated by the scheduled runs", (await I.readInventory()).assets.length === 3);
ok("the sync history shows the scheduled runs", (await S.listRuns()).filter((r) => r.triggeredBy === "scheduler").length === 5);

// ---- limits and isolation ----
pageIx = 0; pages = pages.map((p) => ({ ...p, hasNextPage: true }));
const limited = await Sch.tick({ ...full, openctiMaxPages: 2, sources: ["opencti"] }, runners);
ok("the page limit caps one pass even if the stream has more", limited.length === 2 && limited.every((r) => r.source === "opencti"));
wazuhBehaviour = "fail";
const iso = await Sch.tick({ ...full, sources: ["wazuh", "greenbone"] }, runners);
ok("a failing source is reported as failed and the next source still runs", iso[0].status === "failed" && /500/.test(iso[0].note) && iso[1].status === "completed");

// ---- overlap with a manual run ----
let release;
const gate = new Promise((r) => { release = r; });
const manual = S.runAssetSync("greenbone", "admin@x", async () => { await gate; return { items: [] }; });
await new Promise((r) => setTimeout(r, 40));
const skipped = await Sch.tick({ ...full, sources: ["greenbone"] }, { ...runners, greenbone: (by) => S.runAssetSync("greenbone", by, async () => ({ items: [] })) });
ok("a source already syncing by hand is skipped, not failed", skipped[0].status === "skipped" && skipped[0].note === "already running");
release(); await manual;

// ---- a broken runner can never escape ----
const nothrow = await Sch.tick({ ...full, sources: ["wazuh"] }, { ...runners, wazuh: async () => { throw new Error("boom"); } });
ok("a runner that throws is reported, not propagated", nothrow[0].status === "failed" && nothrow[0].note === "could not start");
const badAudit = await Sch.tick({ ...full, sources: ["greenbone"] }, { ...runners, audit: async () => { throw new Error("disk full"); } });
ok("an audit failure does not fail the sync", badAudit[0].status === "completed");

// ---- starting and status ----
ok("not configured: start does nothing", Sch.startSyncScheduler({}, runners) === false && Sch.schedulerStatus().enabled === false);
const logs = [];
ok("configured: start reports on and exposes its status", Sch.startSyncScheduler({ SYNC_SCHEDULE_MINUTES: "30" }, runners, (m) => logs.push(m)) === true);
const st = Sch.schedulerStatus();
ok("status shows the interval, sources and a next run about a minute away", st.enabled && st.intervalMinutes === 30 && st.sources.length === 3 && st.lastTickAt === null && Math.abs(Date.parse(st.nextTickAt) - Date.now() - Sch.FIRST_RUN_DELAY_MS) < 5000 && /every 30 min/.test(logs[0]));
ok("starting twice (a dev reload) does not start a second timer", Sch.startSyncScheduler({ SYNC_SCHEDULE_MINUTES: "30" }, runners, (m) => logs.push(m)) === true && logs.length === 1);
Sch.stopSyncSchedulerForTests();
ok("stopping clears the status", Sch.schedulerStatus().enabled === false);

console.log(`scheduler: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
