// Tests for findings normalisation, sync/merge, remediation updates and the close rule.
// Run: npm run test:findings (Node 22.6+; TypeScript is type-stripped).
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const original = process.cwd();
const work = mkdtempSync(path.join(tmpdir(), "primesec-findings-"));
process.chdir(work); // lib/findings.ts stores ./data/vapt-findings.json relative to the working directory
const F = await import("../lib/findings.ts");

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const rejects = async (name, fn, code) => {
  try { await fn(); fail++; console.log("FAIL (no error):", name); }
  catch (e) { (e.code === code) ? pass++ : (fail++, console.log("FAIL (wrong error):", name, "->", e.code, e.message)); }
};

const raw = (over = {}) => ({ host: "10.0.0.5", port: "443/tcp", name: "TLS 1.0 enabled", oid: "1.3.6.1.4.1.25623.1.0.1", cves: ["CVE-2011-3389"], severity: "4.3", threat: "Medium", description: "d", solution: "s", reportId: "r1", resultId: "x1", creationTime: "2026-10-01T00:00:00Z", ...over });
const analyst = { email: "a@x", roles: ["SOC_Analyst"] };
const admin = { email: "admin@x", roles: ["SOC_Admin"] };
const reset = async () => { const { rmSync: rm } = await import("node:fs"); rm(path.join(work, "data"), { recursive: true, force: true }); };

// ---------------- ids ----------------
const id = (h, p, o, n) => F.findingId(h, p, o, n);
ok("id format is vuln_ + 16 hex", /^vuln_[0-9a-f]{16}$/.test(id("10.0.0.5", "443/tcp", "1.2.3", "n")));
ok("same host/port/oid -> same id even if the NVT is renamed", id("10.0.0.5", "443/tcp", "1.2.3", "Old name") === id("10.0.0.5", "443/tcp", "1.2.3", "New name"));
ok("host is case-insensitive", id("HOST.example", "80/tcp", "1.2.3", "") === id("host.example", "80/tcp", "1.2.3", ""));
ok("different port -> different id", id("10.0.0.5", "443/tcp", "1.2.3", "") !== id("10.0.0.5", "80/tcp", "1.2.3", ""));
ok("different host -> different id", id("10.0.0.5", "443/tcp", "1.2.3", "") !== id("10.0.0.6", "443/tcp", "1.2.3", ""));
ok("no oid falls back to the name", id("h", "p", "", "A") !== id("h", "p", "", "B"));
const many = new Set(); for (let i = 0; i < 100000; i++) many.add(id("10.0." + (i % 250) + "." + (i % 200), String(i % 65535) + "/tcp", "1.3.6.1." + i, ""));
ok("100,000 distinct findings, zero id collisions (the original 32-bit hash would collide)", many.size === 100000, String(many.size));

// ---------------- normalisation ----------------
const sev = (score, threat = "High") => F.normalizeFinding(raw({ severity: score, threat })).severity;
ok("9.8 Critical", sev(9.8) === "Critical"); ok("9.0 Critical", sev(9.0) === "Critical");
ok("8.9 High", sev(8.9) === "High"); ok("7.0 High", sev(7.0) === "High");
ok("6.9 Medium", sev(6.9) === "Medium"); ok("4.0 Medium", sev(4.0) === "Medium");
ok("3.9 Low", sev(3.9) === "Low"); ok("0.1 Low", sev(0.1) === "Low");
ok("0 Info", sev(0) === "Info"); ok("threat Log is always Info", sev(9.8, "Log") === "Info");
ok("severity above 10 is clamped", F.normalizeFinding(raw({ severity: 99 })).severityScore === 10);
ok("negative/NaN severity -> 0", F.normalizeFinding(raw({ severity: "oops" })).severityScore === 0 && F.normalizeFinding(raw({ severity: -5 })).severityScore === 0);
ok("cves are de-duplicated and sorted", JSON.stringify(F.normalizeFinding(raw({ cves: ["CVE-2", "CVE-1", "CVE-2", " ", ""] })).cves) === '["CVE-1","CVE-2"]');
ok("non-array cves tolerated", F.normalizeFinding(raw({ cves: "CVE-1" })).cves.length === 0);
ok("description is capped", F.normalizeFinding(raw({ description: "x".repeat(50000) })).description.length === 6000);
ok("empty input does not throw", F.normalizeFinding({}).name === "Unnamed vulnerability result");
ok("starts Open, unowned, no retest", (f => f.remediationStatus === "Open" && f.owner === "" && f.retestTaskId === null)(F.normalizeFinding(raw())));

// ---------------- sync ----------------
await reset();
let r = await F.syncFindings([raw(), raw({ host: "10.0.0.6", name: "SSH weak", oid: "2.2", port: "22/tcp", severity: 5.3 })]);
ok("first sync imports 2", r.imported === 2 && r.findings.length === 2);
r = await F.syncFindings([raw(), raw({ host: "10.0.0.6", name: "SSH weak", oid: "2.2", port: "22/tcp", severity: 5.3 })]);
ok("repeated sync creates no duplicates", r.imported === 0 && r.updated === 2 && r.findings.length === 2);

const target = r.findings.find((f) => f.host === "10.0.0.5");
await F.updateFinding(target.id, { remediationStatus: "In Progress", owner: "alice", remediationNotes: "patching Friday" }, analyst);
r = await F.syncFindings([raw(), raw({ host: "10.0.0.6", name: "SSH weak", oid: "2.2", port: "22/tcp", severity: 5.3 })]);
let after = r.findings.find((f) => f.id === target.id);
ok("remediation status, owner and notes survive a later sync", after.remediationStatus === "In Progress" && after.owner === "alice" && after.remediationNotes === "patching Friday");
ok("firstImportedAt is preserved across syncs", after.firstImportedAt === target.firstImportedAt);

r = await F.syncFindings([raw({ name: "TLS 1.0 enabled (renamed by a feed update)", severity: 6.1 }), raw({ host: "10.0.0.6", name: "SSH weak", oid: "2.2", port: "22/tcp", severity: 5.3 })]);
after = r.findings.find((f) => f.id === target.id);
ok("a renamed NVT keeps the same finding and its remediation", !!after && after.owner === "alice" && after.name.includes("renamed") && r.findings.length === 2);
ok("scanner evidence is refreshed (new severity)", after.severityScore === 6.1);

r = await F.syncFindings([raw({ severity: 4.3 }), raw({ severity: 8.8 }), raw({ severity: 6 })]);
ok("the same result repeated across reports collapses to one finding, highest severity wins", r.findings.filter((f) => f.id === target.id).length === 1 && r.findings.find((f) => f.id === target.id).severityScore === 8.8);

// absence handling
ok("a finding missing from a COMPLETE import is flagged, not closed", (() => { const gone = r.findings.find((f) => f.host === "10.0.0.6"); return gone.notInLatestSync === true && gone.remediationStatus === "Open"; })());
ok("missing count reported", r.missing === 1, String(r.missing));
r = await F.syncFindings([raw({ severity: 8.8 }), raw({ host: "10.0.0.6", name: "SSH weak", oid: "2.2", port: "22/tcp", severity: 5.3 })]);
ok("a finding that reappears is un-flagged", r.findings.every((f) => f.notInLatestSync === false));
r = await F.syncFindings([raw({ severity: 8.8 })], { truncated: true });
ok("a TRUNCATED import never flags anything missing", r.findings.every((f) => f.notInLatestSync === false) && r.missing === 0 && r.truncated === true);
r = await F.syncFindings([]);
ok("an empty complete import flags everything but closes nothing", r.findings.every((f) => f.notInLatestSync) && r.findings.every((f) => f.remediationStatus !== "Closed"));

await reset();
r = await F.syncFindings([raw({ severity: 3, host: "10.0.0.9", oid: "9" }), raw({ severity: 9.8, oid: "1" }), raw({ severity: 5, host: "10.0.0.7", oid: "7" })]);
ok("sorted by severity, highest first", r.findings.map((f) => f.severityScore).join() === "9.8,5,3", r.findings.map((f) => f.severityScore).join());

// ---------------- per-host "latest report wins" (retest verification) ----------------
await reset();
const apache = (idx, over = {}) => raw({ host: "10.5.0.10", name: "Apache path traversal", oid: "A1", severity: 9.8, threat: "High", reportIndex: idx, ...over });
const ssh = (idx, over = {}) => raw({ host: "10.5.0.10", name: "SSH weak ciphers", oid: "S1", port: "22/tcp", severity: 5.3, reportIndex: idx, ...over });
const other = (idx) => raw({ host: "10.5.0.99", name: "Other host vuln", oid: "O1", severity: 7, reportIndex: idx });
// older scan (index 1) found Apache + SSH on .10; newest scan (index 0) of .10 found only SSH: Apache is fixed
r = await F.syncFindings([ssh(0), apache(1), ssh(1)]);
const ap = r.findings.find((f) => f.oid === "A1"), ss = r.findings.find((f) => f.oid === "S1");
ok("a finding only in an OLDER report of its host is flagged (a retest no longer finds it)", ap.notInLatestSync === true);
ok("a finding in the host's LATEST report is current", ss.notInLatestSync === false);
ok("the flagged finding is kept (history), never dropped or closed", !!ap && ap.remediationStatus === "Open");
ok("the flag is counted once", r.missing === 1, String(r.missing));
r = await F.syncFindings([ssh(0), apache(1), ssh(1)]);
ok("re-syncing the same data does not re-count the flag", r.missing === 0);

// a different host's report must not hide or flag this host's findings
r = await F.syncFindings([other(0), ssh(1), apache(1)]);
ok("another host having a newer report does not make this host's findings stale", r.findings.find((f) => f.oid === "A1").notInLatestSync === false && r.findings.find((f) => f.oid === "S1").notInLatestSync === false);
ok("the other host's own finding is current", r.findings.find((f) => f.oid === "O1").notInLatestSync === false);

// regression: if the vuln comes back in the newest report it is current again
r = await F.syncFindings([apache(0), ssh(0), apache(1)]);
ok("a finding that reappears in the latest report is current again", r.findings.find((f) => f.oid === "A1").notInLatestSync === false);

// a current sighting wins over an older one even with a lower severity
r = await F.syncFindings([apache(0, { severity: 5 }), apache(1, { severity: 9.8 })]);
ok("the current report's evidence wins over an older report's, even if its severity is lower", r.findings.find((f) => f.oid === "A1").severityScore === 5);

// remediation state survives the flag flipping back and forth
await F.updateFinding(r.findings.find((f) => f.oid === "A1").id, { remediationStatus: "In Progress", owner: "carol" }, analyst);
r = await F.syncFindings([ssh(0), apache(1)]);
ok("remediation data survives being flagged", (f => f.notInLatestSync && f.owner === "carol" && f.remediationStatus === "In Progress")(r.findings.find((f) => f.oid === "A1")));
r = await F.syncFindings([apache(0), ssh(0)]);
ok("...and un-flagged", (f => !f.notInLatestSync && f.owner === "carol")(r.findings.find((f) => f.oid === "A1")));
ok("garbage reportIndex is treated as current", (await F.syncFindings([raw({ oid: "G1", reportIndex: "abc" })])).findings.find((f) => f.oid === "G1").notInLatestSync === false);

// ---------------- updates ----------------
await reset();
r = await F.syncFindings([raw()]);
const fid = r.findings[0].id;
let u = await F.updateFinding(fid, { owner: "bob", remediationNotes: "ticket 42" }, analyst);
u = await F.updateFinding(fid, { remediationStatus: "Resolved" }, analyst);
ok("a status-only patch does NOT erase owner or notes (data-loss bug in the original)", u.owner === "bob" && u.remediationNotes === "ticket 42" && u.remediationStatus === "Resolved");
u = await F.updateFinding(fid, { owner: "" }, analyst);
ok("an explicit empty owner does clear it", u.owner === "" && u.remediationNotes === "ticket 42");
await rejects("invalid status rejected", () => F.updateFinding(fid, { remediationStatus: "Fixed-ish" }, analyst), "INVALID");
await rejects("lower-case status rejected", () => F.updateFinding(fid, { remediationStatus: "closed" }, analyst), "INVALID");
await rejects("non-string status rejected", () => F.updateFinding(fid, { remediationStatus: { $ne: 1 } }, analyst), "INVALID");
await rejects("unknown id", () => F.updateFinding("vuln_doesnotexist", { owner: "x" }, analyst), "NOT_FOUND");
u = await F.updateFinding(fid, { owner: "o".repeat(500), remediationNotes: "n".repeat(9000) }, analyst);
ok("owner and notes are length-capped", u.owner.length === 120 && u.remediationNotes.length === 2000);
ok("updatedBy and updatedAt are recorded", u.updatedBy === "a@x" && !!u.updatedAt);

// close rule
await F.updateFinding(fid, { remediationStatus: "Open", remediationNotes: "" }, analyst);
await rejects("analyst cannot close without a retest", () => F.updateFinding(fid, { remediationStatus: "Closed" }, analyst), "FORBIDDEN");
await rejects("admin cannot close without a justification", () => F.updateFinding(fid, { remediationStatus: "Closed" }, admin), "FORBIDDEN");
await rejects("admin with a too-short justification cannot close", () => F.updateFinding(fid, { remediationStatus: "Closed", remediationNotes: "ok" }, admin), "FORBIDDEN");
await rejects("an analyst's long note does not unlock closing", () => F.updateFinding(fid, { remediationStatus: "Closed", remediationNotes: "this is fixed, trust me, it is fine now" }, analyst), "FORBIDDEN");
u = await F.updateFinding(fid, { remediationStatus: "Closed", remediationNotes: "Asset decommissioned, CHG-1234" }, admin);
ok("admin with a written justification can close", u.remediationStatus === "Closed");
await F.updateFinding(fid, { remediationStatus: "Open" }, analyst);
const m = await F.markRetestRequested(fid, "task-1", analyst);
ok("retest request records task id, time and Retest Required", m.retestTaskId === "task-1" && !!m.retestRequestedAt && m.remediationStatus === "Retest Required");
u = await F.updateFinding(fid, { remediationStatus: "Closed" }, analyst);
ok("after a retest was requested an analyst can close", u.remediationStatus === "Closed");
r = await F.syncFindings([raw()]);
ok("retest metadata survives a later sync", r.findings[0].retestTaskId === "task-1");

// optimistic concurrency
const cur = (await F.getFinding(fid));
await rejects("stale expectedUpdatedAt -> CONFLICT", () => F.updateFinding(fid, { owner: "z", expectedUpdatedAt: "2000-01-01T00:00:00.000Z" }, analyst), "CONFLICT");
u = await F.updateFinding(fid, { owner: "z", expectedUpdatedAt: cur.updatedAt }, analyst);
ok("matching expectedUpdatedAt succeeds", u.owner === "z");
ok("a conflict did not change the finding", (await F.getFinding(fid)).owner === "z");
await F.syncFindings([raw({ host: "10.9.9.9", oid: "77", name: "never edited" })]);
const fresh = (await F.readFindings()).find((f) => f.host === "10.9.9.9");
u = await F.updateFinding(fresh.id, { owner: "q", expectedUpdatedAt: null }, analyst);
ok("expectedUpdatedAt null works for a never-edited finding", u.owner === "q");

// concurrency: 40 simultaneous edits to different findings must all land
await reset();
const bulk = Array.from({ length: 40 }, (_, i) => raw({ host: `10.1.0.${i + 1}`, oid: `9.${i}`, name: `vuln ${i}` }));
r = await F.syncFindings(bulk);
await Promise.all(r.findings.map((f, i) => F.updateFinding(f.id, { owner: `owner-${i}` }, analyst)));
const all = await F.readFindings();
ok("40 concurrent edits: none lost", all.length === 40 && all.every((f) => f.owner.startsWith("owner-")), String(all.filter((f) => f.owner).length));
await Promise.all([F.syncFindings(bulk), ...all.map((f) => F.updateFinding(f.id, { remediationNotes: "n" }, analyst))]);
ok("a sync racing with edits loses no remediation data", (await F.readFindings()).every((f) => f.owner.startsWith("owner-") && f.remediationNotes === "n"));

process.chdir(original); // Windows cannot delete the directory the process is in
rmSync(work, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
