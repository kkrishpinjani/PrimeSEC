// Tests for the unified asset inventory: identity matching, normalisation, exposure score, validation, storage.
// Run: npm run test:inventory (Node 22.6+; TypeScript is type-stripped).
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const root = process.cwd();
const work = mkdtempSync(path.join(tmpdir(), "primesec-inv-"));
process.chdir(work);
const I = await import(path.join(root, "lib", "inventory.ts").replace(/\\/g, "/").replace(/^([A-Za-z]):/, "file:///$1:"));

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const bad = (name, fn) => { try { fn(); fail++; console.log("FAIL (no error):", name); } catch (e) { (e.code === "INVALID") ? pass++ : (fail++, console.log("FAIL (wrong error):", name, e.message)); } };
const V = (o) => I.validateAssetInput(o);

// ---- identity ----
ok("durable id wins over source id", I.canonicalKey({ source: "wazuh", sourceAssetId: "x", identifiers: { agent_id: "007" } }) === "agent_id:007");
ok("cloud instance id outranks agent id", I.canonicalKey({ source: "wazuh", sourceAssetId: "x", identifiers: { agent_id: "007", cloud_instance_id: "i-abc" } }) === "cloud_instance_id:i-abc");
ok("no durable id falls back to source + source id", I.canonicalKey({ source: "Wazuh", sourceAssetId: "A 1", identifiers: {} }) === "source:wazuh:a1");
ok("an ip identifier is NOT a merge key", I.canonicalKey({ source: "x", sourceAssetId: "1", identifiers: { ip: "10.0.0.1" } }) === "source:x:1");

// ---- ingest: upsert, isolation of IP-only matches ----
const a = V({ source: "wazuh", sourceAssetId: "007", name: "web-01", criticality: 5, internetFacing: true, identifiers: { agent_id: "007" }, vulnerabilities: [{ cve: "CVE-2025-1234", severity: "critical", cvss: 9.8 }] });
const r1 = await I.ingestAssets([a]);
const r2 = await I.ingestAssets([a]);
ok("first ingest creates, second updates", r1.created === 1 && r2.created === 0 && r2.updated === 1);
ok("same durable id gives the same asset", r1.assets[0].id === r2.assets[0].id);
const s1 = await I.readInventory();
ok("re-ingest does not duplicate the vulnerability", s1.vulns.length === 1 && s1.assets.length === 1);
ok("critical, internet-facing, CVSS 9.8 is high or critical", ["high", "critical"].includes(r2.assets[0].riskLevel), r2.assets[0].riskLevel);
const x = await I.ingestAssets([V({ source: "wazuh", sourceAssetId: "a", primaryIp: "10.0.0.1" }), V({ source: "openvas", sourceAssetId: "b", primaryIp: "10.0.0.1" })]);
ok("two sources with the same IP stay separate assets", x.created === 2);

// ---- fields merge sensibly ----
await I.ingestAssets([V({ source: "cmdb", sourceAssetId: "c1", identifiers: { agent_id: "007" }, hostname: "web-01.corp", environment: "prod", tags: ["pci"] })]);
const d = (await I.listAssets({ q: "web-01" })).items[0];
ok("a second source on the same agent id merges into the asset", d.environment === "prod" && d.hostname === "web-01.corp" && Object.keys(d.sources).sort().join() === "cmdb,wazuh", JSON.stringify(d.sources));
ok("a source that does not know criticality does not change it", d.criticality === 5);
await I.ingestAssets([V({ source: "cmdb", sourceAssetId: "c1", identifiers: { agent_id: "007" }, criticality: 2 })]);
ok("another source's lower criticality does not lower the highest claim", (await I.listAssets({ q: "web-01" })).items[0].criticality === 5);
await I.ingestAssets([V({ source: "wazuh", sourceAssetId: "007", identifiers: { agent_id: "007" }, criticality: 1 })]);
ok("the same source lowering its own claim does take effect (max is now cmdb's 2)", (await I.listAssets({ q: "web-01" })).items[0].criticality === 2);
await I.ingestAssets([V({ source: "wazuh", sourceAssetId: "007", identifiers: { agent_id: "007" }, criticality: 5, internetFacing: true })]);
const unk = await I.ingestAssets([V({ source: "wazuh", sourceAssetId: "z9" })]);
ok("criticality stays unknown (null) when no source says", unk.assets[0].criticality === null);

// ---- exposure score ----
const E = I.exposure;
ok("score formula matches the package", E({ criticality: 5, internetFacing: true }, [{ status: "open", severity: "critical", cvss: 9.8 }]).score === 97.8);
ok("closed and false-positive vulnerabilities are ignored", E({ criticality: 1, internetFacing: false }, [{ status: "closed", severity: "critical", cvss: 10 }, { status: "false_positive", severity: "high", cvss: null }]).score === 5);
ok("severity words stand in for a missing CVSS", E({ criticality: 1, internetFacing: false }, [{ status: "open", severity: "high", cvss: null }]).score === 7.5 * 6 + 2 + 5);
ok("unknown criticality is scored as medium (3)", E({ criticality: null, internetFacing: false }, []).score === 15);
ok("score is capped at 100", E({ criticality: 5, internetFacing: true }, Array.from({ length: 20 }, () => ({ status: "open", severity: "critical", cvss: 10 }))).score === 100);
ok("bands", E({ criticality: 5, internetFacing: true }, [{ status: "open", severity: "critical", cvss: 10 }]).level === "critical" && E({ criticality: 1, internetFacing: false }, []).level === "low");

// ---- vulnerabilities: dedupe by key, status updates ----
await I.ingestAssets([V({ source: "openvas", sourceAssetId: "h", identifiers: { openvas_host_id: "h1" }, vulnerabilities: [{ cve: "cve-2024-1", severity: "high" }, { cve: "CVE-2024-1", severity: "high", status: "fixed" }] })]);
const st = await I.readInventory();
const host = st.assets.find((q) => q.canonicalKey === "openvas_host_id:h1");
const hv = st.vulns.filter((v) => v.assetId === host.id);
ok("CVE keys are case-insensitive and de-duplicated", hv.length === 1 && hv[0].key === "CVE-2024-1" && hv[0].status === "fixed");
ok("a fixed vulnerability leaves zero open", (await I.assetDetail(host.id)).openVulnerabilities === 0);

// ---- validation ----
bad("unknown field rejected", () => V({ source: "wazuh", sourceAssetId: "1", tenant_id: "x" }));
bad("missing source id", () => V({ source: "wazuh" }));
bad("short source", () => V({ source: "w", sourceAssetId: "1" }));
bad("criticality out of range", () => V({ source: "wazuh", sourceAssetId: "1", criticality: 6 }));
bad("criticality not an integer", () => V({ source: "wazuh", sourceAssetId: "1", criticality: 2.5 }));
bad("cvss out of range", () => V({ source: "wazuh", sourceAssetId: "1", vulnerabilities: [{ cve: "CVE-1", cvss: 11 }] }));
bad("vulnerability with nothing to identify it", () => V({ source: "wazuh", sourceAssetId: "1", vulnerabilities: [{ severity: "high" }] }));
bad("overlong text", () => V({ source: "wazuh", sourceAssetId: "1", name: "x".repeat(301) }));
bad("empty batch", () => I.validateBatch([]));
bad("oversized batch", () => I.validateBatch(Array.from({ length: 1001 }, () => ({ source: "ab", sourceAssetId: "1" }))));
bad("one bad item rejects the whole batch", () => I.validateBatch([{ source: "ab", sourceAssetId: "1" }, { source: "ab" }]));
ok("__proto__ key in identifiers does not pollute", (() => { try { V(JSON.parse('{"source":"ab","sourceAssetId":"1","identifiers":{"__proto__":"x"}}')); } catch { /* fine */ } return ({}).x === undefined; })());

// ---- queries ----
const top = await I.topExposure(5);
ok("top exposure is sorted by score descending", top.every((t, i) => i === 0 || top[i - 1].riskScore >= t.riskScore));
const sum = await I.inventorySummary();
ok("summary counts add up", sum.totalAssets === Object.values(sum.byRisk).reduce((p, c) => p + c, 0) && sum.criticalityUnknown >= 1);
ok("filter by risk level", (await I.listAssets({ riskLevel: "critical" })).items.every((q) => q.riskLevel === "critical"));
ok("paging", (await I.listAssets({ limit: 1, offset: 1 })).items.length === 1);
try { await I.assetDetail("nope"); ok("missing asset", false); } catch (e) { ok("missing asset is NOT_FOUND", e.code === "NOT_FOUND"); }

// ---- observation cap ----
for (let i = 0; i < 30; i++) await I.ingestAssets([V({ source: "wazuh", sourceAssetId: "007", identifiers: { agent_id: "007" } })]);
const capped = await I.assetDetail(r1.assets[0].id);
ok("observations are capped per asset", capped.observations.length === 20, String(capped.observations.length));

// ================= reconciliation: analyst-approved merge =================
const codeOf = async (fn) => { try { await fn(); return null; } catch (e) { return e.code ?? `UNEXPECTED:${e.message}`; } };
const NOTE = "Same machine: the scanner address belongs to the agent's second network card.";

// suggestions
const cands = await I.mergeCandidates();
const ipPair = cands.find((c) => c.reasons.includes("Same IP 10.0.0.1"));
ok("two assets from different sources sharing an IP are suggested, with the reason", ipPair && ipPair.strength === "medium" && new Set([ipPair.a.name, ipPair.b.name]).size === 2, JSON.stringify(cands.map((c) => c.reasons)));
await I.ingestAssets([V({ source: "wazuh", sourceAssetId: "dup-1", primaryIp: "10.7.7.7" }), V({ source: "wazuh", sourceAssetId: "dup-2", primaryIp: "10.7.7.7" })]);
ok("two assets from the SAME source with one IP are not suggested (that source says they differ)", !(await I.mergeCandidates()).some((c) => c.reasons.includes("Same IP 10.7.7.7")));
await I.ingestAssets([V({ source: "cmdb", sourceAssetId: "h1", hostname: "Web-77.corp.example" }), V({ source: "openvas", sourceAssetId: "h2", hostname: "web-77.corp.example" }), V({ source: "cmdb", sourceAssetId: "h3", hostname: "app-1.corp" }), V({ source: "openvas", sourceAssetId: "h4", hostname: "app-1.other.example" })]);
const hostLeads = (await I.mergeCandidates()).filter((c) => c.reasons.some((r) => /host name/.test(r)));
ok("the same host name (ignoring case) is a medium lead; only the short name matching is weak", hostLeads.find((c) => c.reasons[0].startsWith("Same host name web-77"))?.strength === "medium" && hostLeads.find((c) => c.reasons[0].startsWith("Same short host name app-1"))?.strength === "weak");
ok("the strongest leads sort first", (await I.mergeCandidates()).every((c, i, all) => i === 0 || ["strong", "medium", "weak"].indexOf(all[i - 1].strength) <= ["strong", "medium", "weak"].indexOf(c.strength)));

// dismiss
const before = (await I.mergeCandidates()).length;
await I.dismissPair(ipPair.a.id, ipPair.b.id);
ok("a dismissed pair stops being suggested (in either order)", (await I.mergeCandidates()).length === before - 1 && !(await I.mergeCandidates()).some((c) => c.reasons.includes("Same IP 10.0.0.1")));
ok("dismissing needs two different, existing assets", await codeOf(() => I.dismissPair("x", "x")) === "INVALID" && await codeOf(() => I.dismissPair("nope1", "nope2")) === "NOT_FOUND");

// merge
const W = (await I.ingestAssets([V({ source: "wazuh", sourceAssetId: "mg-w", identifiers: { agent_id: "mg-w" }, name: "lab-host", hostname: "lab-host", primaryIp: "10.5.5.5", criticality: 2, tags: ["lab"], vulnerabilities: [{ cve: "CVE-2025-555", severity: "high", cvss: 7 }] })])).assets[0];
const O = (await I.ingestAssets([V({ source: "openvas", sourceAssetId: "mg-o", identifiers: { openvas_host_id: "mg-o" }, name: "10.5.6.6", primaryIp: "10.5.6.6", criticality: 4, internetFacing: true, environment: "prod", vulnerabilities: [{ cve: "CVE-2025-555", severity: "high", cvss: 7.5 }, { cve: "CVE-2025-666", severity: "critical", cvss: 9.8 }] })])).assets[0];
const oldRisk = W.riskScore;
ok("merge needs a written reason", await codeOf(() => I.mergeAssets(W.id, O.id, "short", "alice@x")) === "INVALID" && await codeOf(() => I.mergeAssets(W.id, O.id, undefined, "alice@x")) === "INVALID");
ok("merge needs two different, existing assets", await codeOf(() => I.mergeAssets(W.id, W.id, NOTE, "a")) === "INVALID" && await codeOf(() => I.mergeAssets(W.id, "nope", NOTE, "a")) === "NOT_FOUND" && await codeOf(() => I.mergeAssets("nope", O.id, NOTE, "a")) === "NOT_FOUND");
const dup2 = (await I.listAssets({ q: "dup-" })).items;
ok("merging two assets reported by the same source is refused", await codeOf(() => I.mergeAssets(dup2[0].id, dup2[1].id, NOTE, "a")) === "CONFLICT");
const merged = await I.mergeAssets(W.id, O.id, NOTE, "alice@x", "2026-11-04T00:00:00.000Z");
ok("the survivor keeps its name and gains the other source, identifiers and attributes", merged.name === "lab-host" && Object.keys(merged.sources).sort().join() === "openvas,wazuh" && merged.identifiers.agent_id === "mg-w" && merged.identifiers.openvas_host_id === "mg-o" && merged.environment === "prod" && merged.tags.includes("lab"));
ok("on conflict the survivor wins (its IP stays)", merged.primaryIp === "10.5.5.5");
ok("criticality is the highest claim and internet exposure is combined", merged.criticality === 4 && merged.internetFacing === true);
const after = await I.assetDetail(W.id);
ok("a vulnerability both had is kept once, with the newer record", after.vulnerabilities.filter((v) => v.key === "CVE-2025-555").length === 1 && after.vulnerabilities.find((v) => v.key === "CVE-2025-555").cvss === 7.5);
ok("the other asset's vulnerabilities moved across", after.vulnerabilities.some((v) => v.key === "CVE-2025-666") && after.openVulnerabilities === 2);
ok("the exposure score was recomputed from the combined data", merged.riskScore > oldRisk, `${oldRisk} -> ${merged.riskScore}`);
ok("observations moved to the survivor", after.observations.some((o) => o.source === "openvas"));
ok("the absorbed asset is gone", await codeOf(() => I.assetDetail(O.id)) === "NOT_FOUND");
ok("the merge, who did it, when and why stay on the asset", merged.mergedFrom.length === 1 && merged.mergedFrom[0].by === "alice@x" && merged.mergedFrom[0].note === NOTE && merged.mergedFrom[0].name === "10.5.6.6" && merged.mergedFrom[0].at === "2026-11-04T00:00:00.000Z");

// the old identity now resolves to the survivor
const total = (await I.readInventory()).assets.length;
const again = await I.ingestAssets([V({ source: "openvas", sourceAssetId: "mg-o", identifiers: { openvas_host_id: "mg-o" }, vulnerabilities: [{ cve: "CVE-2025-666", severity: "critical", cvss: 9.8, status: "fixed" }] })]);
ok("a later report of the merged-away identity lands on the survivor instead of recreating it", again.created === 0 && again.assets[0].id === W.id && (await I.readInventory()).assets.length === total);
ok("...and updates the survivor's data", (await I.assetDetail(W.id)).vulnerabilities.find((v) => v.key === "CVE-2025-666").status === "fixed");

// names: the source that created an asset owns its name
ok("after a merge, a later sync from the merged-away source does NOT rename the survivor", (await I.assetDetail(W.id)).name === "lab-host");
const nm = (await I.ingestAssets([V({ source: "wazuh", sourceAssetId: "nm-1", identifiers: { agent_id: "nm-1" }, name: "first-name" })])).assets[0];
await I.ingestAssets([V({ source: "openvas", sourceAssetId: "nm-o", identifiers: { agent_id: "nm-1" }, name: "scanner-name" })]);
ok("a second source reporting the same asset does not rename it", (await I.assetDetail(nm.id)).name === "first-name");
await I.ingestAssets([V({ source: "wazuh", sourceAssetId: "nm-1", identifiers: { agent_id: "nm-1" }, name: "renamed-by-owner" })]);
ok("the source that owns the name can change it", (await I.assetDetail(nm.id)).name === "renamed-by-owner");

// ---- staleness: flagged, never acted on ----
const DAY = 86_400_000, T0 = Date.parse("2026-11-04T00:00:00Z");
ok("a source silent for the limit or longer is stale; a recent one is not", JSON.stringify(I.staleSourcesOf({ sources: { wazuh: "2026-10-20T00:00:00Z", openvas: "2026-11-02T00:00:00Z" } }, T0, 7)) === JSON.stringify([{ source: "wazuh", days: 15 }]));
ok("exactly at the limit counts as stale; one day short does not", I.staleSourcesOf({ sources: { a: new Date(T0 - 7 * DAY).toISOString() } }, T0, 7).length === 1 && I.staleSourcesOf({ sources: { a: new Date(T0 - 6.5 * DAY).toISOString() } }, T0, 7).length === 0);
ok("the limit comes from INVENTORY_STALE_DAYS, bounded, with a default of 7", I.staleDays({}) === 7 && I.staleDays({ INVENTORY_STALE_DAYS: "30" }) === 30 && I.staleDays({ INVENTORY_STALE_DAYS: "0" }) === 7 && I.staleDays({ INVENTORY_STALE_DAYS: "9999" }) === 7 && I.staleDays({ INVENTORY_STALE_DAYS: "abc" }) === 7);
ok("an unparseable timestamp is ignored, not flagged or thrown", I.staleSourcesOf({ sources: { a: "not a date" } }, T0, 7).length === 0);
ok("list rows carry their stale sources", (await I.listAssets({ limit: 500 }, Date.now() + 30 * DAY)).items.every((r) => r.staleSources.length === Object.keys(r.sources).length) && (await I.listAssets({ limit: 500 })).items.every((r) => r.staleSources.length === 0));
ok("the summary counts assets with a stale source", (await I.inventorySummary()).staleAssets === 0);

const t1 = "2026-11-01T00:00:00.000Z", t2 = "2026-11-02T00:00:00.000Z";
const sid = { source: "openvas", sourceAssetId: "st-1", identifiers: { openvas_host_id: "st-1" } };
const st1 = (await I.ingestAssets([V({ ...sid, vulnerabilities: [{ cve: "CVE-2025-A1", severity: "high" }, { cve: "CVE-2025-B2", severity: "high" }, { cve: "CVE-2025-C3", severity: "low", status: "closed" }] })], t1)).assets[0];
await I.ingestAssets([V({ ...sid, vulnerabilities: [{ cve: "CVE-2025-A1", severity: "high" }] })], t2);
const sd = await I.assetDetail(st1.id);
const flag = (k) => sd.vulnerabilities.find((v) => v.key === k).notInLatestSync;
ok("a finding the source stopped reporting is flagged 'not in latest sync'", flag("CVE-2025-B2") === true);
ok("a finding still reported is not flagged", flag("CVE-2025-A1") === false);
ok("a finding already closed is not flagged", flag("CVE-2025-C3") === false);
ok("flagging does NOT close anything: the status is unchanged and it still counts as open", sd.vulnerabilities.find((v) => v.key === "CVE-2025-B2").status === "open" && sd.openVulnerabilities === 2);
await I.ingestAssets([V({ source: "wazuh", sourceAssetId: "st-w", identifiers: { openvas_host_id: "st-1" } })], "2026-11-03T00:00:00.000Z");
ok("another source reporting the asset does not flag the first source's findings", (await I.assetDetail(st1.id)).vulnerabilities.find((v) => v.key === "CVE-2025-A1").notInLatestSync === false);
ok("the detail carries the asset's stale sources too", Array.isArray((await I.assetDetail(st1.id, Date.now() + 60 * DAY)).staleSources) && (await I.assetDetail(st1.id, Date.now() + 60 * DAY)).staleSources.length === 2);

// chains: merging the survivor into another keeps every alias working
const X = (await I.ingestAssets([V({ source: "cmdb", sourceAssetId: "mg-x", identifiers: { cmdb_id: "mg-x" }, name: "cmdb record" })])).assets[0];
const chained = await I.mergeAssets(X.id, W.id, NOTE, "bob@x");
const viaOldest = await I.ingestAssets([V({ source: "openvas", sourceAssetId: "mg-o", identifiers: { openvas_host_id: "mg-o" } })]);
ok("after merging again, an old identity still resolves to the final asset", viaOldest.assets[0].id === X.id && chained.mergedFrom.length === 2);
ok("dismissed pairs involving a merged-away asset are cleaned up", !(await I.readInventory()).dismissed.some((k) => k.split("|").includes(W.id)));
ok("a merged-away asset is never suggested again", !(await I.mergeCandidates()).some((c) => c.a.id === W.id || c.b.id === W.id));

console.log(`inventory: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
