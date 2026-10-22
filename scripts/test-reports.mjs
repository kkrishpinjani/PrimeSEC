// Tests for report snapshots and the baseline/retest comparison.
// Run: npm run test:reports (Node 22.6+; TypeScript is type-stripped).
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const original = process.cwd();
const work = mkdtempSync(path.join(tmpdir(), "primesec-reports-"));
process.chdir(work);
const R = await import("../lib/reports.ts");

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const rejects = async (name, fn, code) => {
  try { await fn(); fail++; console.log("FAIL (no error):", name); }
  catch (e) { (e.code === code) ? pass++ : (fail++, console.log("FAIL (wrong error):", name, "->", e.code, e.message)); }
};
const reset = async () => { const { rmSync: rm } = await import("node:fs"); rm(path.join(work, "data"), { recursive: true, force: true }); };

const raw = (reportId, host, oid, over = {}) => ({ reportId, host, oid, port: "80/tcp", name: `vuln ${oid}`, cves: [], severity: 7, threat: "High", taskName: "t", ...over });
const meta = (id, status = "Done", hosts = null) => ({ id, status, scannedHosts: hosts, timestamp: "2026-10-20T10:00:00Z" });
const snap = async (id) => (await R.readSnapshots()).find((s) => s.reportId === id);

// ---------------- capture ----------------
await reset();
let r = await R.captureSnapshots([raw("rep1", "10.0.0.5", "A"), raw("rep1", "10.0.0.5", "B"), raw("rep2", "10.0.0.5", "A")], { reports: [meta("rep1", "Done", ["10.0.0.5"]), meta("rep2", "Running", ["10.0.0.5"])], completedReports: ["rep1"] });
ok("one snapshot per report", r.captured === 2 && (await R.readSnapshots()).length === 2);
let s1 = await snap("rep1"), s2 = await snap("rep2");
ok("a Done report is complete, with the source recorded", s1.complete === true && /Done/.test(s1.completenessSource) && s1.status === "Done");
ok("a Running report is not complete", s2.complete === false && s2.status === "Running");
ok("scanned hosts and findings are stored", JSON.stringify(s1.scannedHosts) === '["10.0.0.5"]' && s1.findings.length === 2);
ok("findings carry the stable finding id", s1.findings.every((f) => /^vuln_[0-9a-f]{16}$/.test(f.id)));

await reset();
await R.captureSnapshots([raw("", "10.0.0.5", "A"), { host: "h" }], {});
ok("a result without a report id creates no snapshot", (await R.readSnapshots()).length === 0);

await reset();
await R.captureSnapshots([], { reports: [meta("clean", "Done", ["10.0.0.9"])], completedReports: ["clean"] });
const clean = await snap("clean");
ok("a CLEAN scan (finished, zero results) still gets a snapshot (the original could not represent this)", !!clean && clean.findings.length === 0 && clean.complete === true && clean.scannedHosts.includes("10.0.0.9"));

await reset();
await R.captureSnapshots([raw("repT", "10.0.0.5", "A")], { reports: [meta("repT", "Done", ["10.0.0.5"])], completedReports: ["repT"], truncated: true });
ok("a TRUNCATED import never marks a report complete, even if Greenbone says Done", (await snap("repT")).complete === false && /capped/i.test((await snap("repT")).completenessSource));
await reset();
await R.captureSnapshots([raw("repN", "10.0.0.5", "A")], {});
ok("no metadata at all -> not complete, scannedHosts null", (s => s.complete === false && s.scannedHosts === null && /No completeness metadata/.test(s.completenessSource))(await snap("repN")));
await R.captureSnapshots([raw("repN", "10.0.0.5", "A")], { reports: [meta("repN", "Done", null)], completedReports: ["repN"] });
ok("complete but without a host list -> scannedHosts stays null", (await snap("repN")).scannedHosts === null && (await snap("repN")).complete === true);

// frozen once complete
await reset();
await R.captureSnapshots([raw("rf", "10.0.0.5", "A")], { reports: [meta("rf", "Done", ["10.0.0.5"])], completedReports: ["rf"] });
const firstAt = (await snap("rf")).capturedAt;
await R.captureSnapshots([], { reports: [meta("rf", "Running", [])], completedReports: [] });
const frozen = await snap("rf");
ok("a finished report is frozen: a later partial read cannot weaken or empty it", frozen.complete === true && frozen.findings.length === 1);
await R.captureSnapshots([raw("rf", "10.0.0.5", "A")], { reports: [meta("rf", "Done", ["10.0.0.5"])], completedReports: ["rf"] });
ok("re-capturing keeps the original capture time", (await snap("rf")).capturedAt === firstAt);

// a running report that later finishes is updated
await reset();
await R.captureSnapshots([raw("rr", "10.0.0.5", "A")], { reports: [meta("rr", "Running", ["10.0.0.5"])], completedReports: [] });
await R.captureSnapshots([raw("rr", "10.0.0.5", "A"), raw("rr", "10.0.0.5", "B")], { reports: [meta("rr", "Done", ["10.0.0.5"])], completedReports: ["rr"] });
ok("a running report is updated when it finishes", (await snap("rr")).complete === true && (await snap("rr")).findings.length === 2);

// cap
await reset();
const many = Array.from({ length: 230 }, (_, i) => raw(`R${i}`, "10.0.0.5", "A", { }));
await R.captureSnapshots(many, { now: "2026-10-01T00:00:00Z" });
ok("snapshots are capped at 200, oldest dropped", (await R.readSnapshots()).length === 200);

// ---------------- comparison rules ----------------
const mk = (id, over = {}) => ({ reportId: id, capturedAt: "2026-10-20T10:00:00Z", reportTime: null, status: "Done", complete: true, completenessSource: "Greenbone reports this scan as Done", scannedHosts: ["10.0.0.5", "10.0.0.6"], taskName: "t", findings: [], ...over });
const f = (host, oid, over = {}) => ({ id: `vuln_${host}_${oid}`, host, port: "80/tcp", oid, name: `vuln ${oid}`, cves: [], severityScore: 7, severity: "High", ...over });
const cmp = (b, t) => R.compareSnapshots(mk("base", b), mk("retest", t));
let c;

c = cmp({ findings: [f("10.0.0.5", "A")] }, { findings: [f("10.0.0.5", "A")] });
ok("same finding in both -> STILL_PRESENT", c.results[0].outcome === "STILL_PRESENT" && c.results[0].reason === "present-in-retest");

c = cmp({ findings: [f("10.0.0.5", "A")] }, { findings: [] });
ok("absent from a Done report that scanned the host -> FIXED", c.results[0].outcome === "FIXED" && c.results[0].reason === "complete-and-host-scanned");

c = cmp({ findings: [f("10.0.0.5", "A")] }, { findings: [], complete: false, status: "Running", completenessSource: 'Greenbone reports status "Running"' });
ok("absent from a report NOT confirmed complete -> INCONCLUSIVE, never FIXED", c.results[0].outcome === "INCONCLUSIVE" && c.results[0].reason === "report-not-complete");

c = cmp({ findings: [f("10.0.0.5", "A"), f("10.0.0.99", "A")] }, { findings: [], scannedHosts: ["10.0.0.5"] });
ok("a Done report that never scanned the host (it was down) -> INCONCLUSIVE, not FIXED (the original bridge could not tell)", c.results.find((x) => x.finding.host === "10.0.0.99").outcome === "INCONCLUSIVE" && c.results.find((x) => x.finding.host === "10.0.0.99").reason === "host-not-confirmed-scanned");
ok("...while the host that WAS scanned in the same report is FIXED", c.results.find((x) => x.finding.host === "10.0.0.5").outcome === "FIXED");
ok("the explanation says why", /down or unreachable/i.test(c.results.find((x) => x.finding.host === "10.0.0.99").explanation));

c = cmp({ findings: [f("10.0.0.5", "A")] }, { findings: [], scannedHosts: null });
ok("a complete report with no host list -> INCONCLUSIVE (cannot rule out a down host)", c.results[0].outcome === "INCONCLUSIVE" && /does not say which hosts/.test(c.results[0].explanation));

c = cmp({ findings: [f("10.0.0.5", "A")] }, { findings: [], complete: false, completenessSource: "Import was capped: results may be missing, so the report cannot be called complete" });
ok("a capped import -> INCONCLUSIVE with the capped reason", c.results[0].reason === "import-truncated");

c = cmp({ findings: [f("10.0.0.5", "A")] }, { findings: [], scannedHosts: ["10.0.0.5".toUpperCase()] });
ok("host comparison ignores case and spaces", c.results[0].outcome === "FIXED");
c = cmp({ findings: [f("HOST.Example", "A")] }, { findings: [], scannedHosts: [" host.example "] });
ok("hostnames match case-insensitively", c.results[0].outcome === "FIXED");

// identity is host + port + NVT (the stable id), not the CVE list or the name
const base = f("10.0.0.5", "A", { cves: ["CVE-1"], name: "Old name" });
const renamed = { ...base, name: "Renamed by a feed update", cves: ["CVE-1", "CVE-2"] };
c = cmp({ findings: [base] }, { findings: [renamed] });
ok("a renamed NVT with an extra CVE is still the SAME finding (comparing by CVE list would have called it fixed)", c.results[0].outcome === "STILL_PRESENT");

c = cmp({ findings: [f("10.0.0.5", "A")] }, { findings: [f("10.0.0.5", "B")] });
ok("a different vulnerability on the same host is not the same finding", c.results[0].outcome === "FIXED" && c.newInRetest.length === 1);

// new findings and severity
c = cmp({ findings: [f("10.0.0.5", "A")] }, { findings: [f("10.0.0.5", "A", { severityScore: 9.1 }), f("10.0.0.5", "N")] });
ok("a finding only in the retest is reported as NEW", c.newInRetest.length === 1 && c.summary.new === 1);
ok("a still-present finding reports its severity in the retest", c.results[0].retestSeverityScore === 9.1);

// summary + never auto-closing
c = cmp({ findings: [f("10.0.0.5", "A"), f("10.0.0.5", "B"), f("10.0.0.5", "C")] }, { findings: [f("10.0.0.5", "B")] });
ok("summary counts add up", c.summary.fixed === 2 && c.summary.stillPresent === 1 && c.summary.inconclusive === 0 && c.results.length === 3);
ok("the comparison result has no field that closes or changes anything", !("close" in c) && !JSON.stringify(c).includes("remediationStatus"));

// empty and edge cases
c = cmp({ findings: [] }, { findings: [f("10.0.0.5", "A")] });
ok("empty baseline: nothing to compare, everything in the retest is NEW", c.results.length === 0 && c.summary.new === 1);
c = cmp({ findings: [f("10.0.0.5", "A")] }, { findings: [] });
ok("results never mutate their inputs", (() => { const b = mk("b", { findings: [f("10.0.0.5", "A")] }); const t = mk("t", { findings: [] }); const before = JSON.stringify([b, t]); R.compareSnapshots(b, t); return JSON.stringify([b, t]) === before; })());

// warnings
c = R.compareSnapshots(mk("b", { reportTime: "2026-10-21T00:00:00Z" }), mk("t", { reportTime: "2026-10-20T00:00:00Z" }));
ok("warns when the retest is OLDER than the baseline", c.warnings.some((w) => /older/i.test(w)));
c = R.compareSnapshots(mk("b", { complete: false }), mk("t"));
ok("warns when the baseline is not confirmed complete", c.warnings.some((w) => /baseline/i.test(w)));
c = R.compareSnapshots(mk("b"), mk("t", { reportTime: "2026-10-25T00:00:00Z" }));
ok("no warning for a normal baseline -> retest order", c.warnings.length === 0);

// ---------------- compareReports (storage) ----------------
await reset();
await R.captureSnapshots([raw("rb", "10.0.0.5", "A"), raw("rb", "10.0.0.5", "B"), raw("rt", "10.0.0.5", "B")], { reports: [meta("rb", "Done", ["10.0.0.5"]), meta("rt", "Done", ["10.0.0.5"])], completedReports: ["rb", "rt"] });
c = await R.compareReports("rb", "rt");
ok("compareReports end to end: A fixed, B still present", c.summary.fixed === 1 && c.summary.stillPresent === 1);
await rejects("same report twice", () => R.compareReports("rb", "rb"), "INVALID");
await rejects("missing id", () => R.compareReports("", "rt"), "INVALID");
await rejects("non-string ids", () => R.compareReports({ a: 1 }, undefined), "INVALID");
await rejects("unknown report", () => R.compareReports("rb", "nope"), "NOT_FOUND");
await Promise.all(Array.from({ length: 25 }, (_, i) => R.captureSnapshots([raw(`C${i}`, "10.0.0.5", "A")], { reports: [meta(`C${i}`, "Done", ["10.0.0.5"])], completedReports: [`C${i}`] })));
ok("25 concurrent captures: none lost", (await R.readSnapshots()).filter((s) => s.reportId.startsWith("C")).length === 25);

process.chdir(original);
rmSync(work, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
