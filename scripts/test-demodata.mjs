// Tests for the sample data seed, "delete all" and single-finding delete.
// Run: npm run test:demodata (Node 22.6+; TypeScript is type-stripped).
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const work = mkdtempSync(path.join(tmpdir(), "primesec-demo-"));
process.chdir(work);
const D = await import("../lib/demoData.ts");
const F = await import("../lib/findings.ts");
const A = await import("../lib/assets.ts");
const R = await import("../lib/reports.ts");

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };

const res = await D.seedDemoData();
ok("seed reports 12 findings, 2 reports, 3 hosts", res.findings === 12 && res.reports === 2 && res.hosts === 3, JSON.stringify(res));
const findings = await F.readFindings();
ok("12 findings stored", findings.length === 12);
ok("everything is labelled sample", findings.every((f) => f.name.includes("(sample)") && f.oid.startsWith("sample-nvt-")));
ok("Apache and TLS 1.0 are flagged not in latest scan", findings.filter((f) => f.notInLatestSync).map((f) => f.oid).sort().join() === "sample-nvt-apache,sample-nvt-tls10");
ok("retest requested on the fixed ones", findings.filter((f) => f.remediationStatus === "Retest Required").length === 2);
ok("exploit evidence recorded", findings.find((f) => f.oid.endsWith("apache")).exploitEvidence === "Exploited in the wild");
ok("host context stored", (await A.readAssets()).length === 3);

const snaps = await R.readSnapshots();
ok("two complete snapshots", snaps.length === 2 && snaps.every((s) => s.complete));
const cmp = await R.compareReports(D.BASELINE_REPORT, D.RETEST_REPORT);
ok("comparison: 2 fixed (Apache, TLS 1.0)", cmp.summary.fixed === 2, JSON.stringify(cmp.summary));
ok("comparison: 2 still present", cmp.summary.stillPresent === 2, JSON.stringify(cmp.summary));
ok("comparison: 8 inconclusive (hosts not rescanned)", cmp.summary.inconclusive === 8, JSON.stringify(cmp.summary));
ok("comparison: 0 new", cmp.summary.new === 0);
ok("no warnings (right order)", cmp.warnings.length === 0, cmp.warnings.join("|"));

try { await D.seedDemoData(); ok("seeding twice is refused", false); } catch { ok("seeding twice is refused", true); }
ok("failed second seed changed nothing", (await F.readFindings()).length === 12);

// delete one
const target = findings.find((f) => f.oid.endsWith("telnet"));
const removed = await F.deleteFinding(target.id);
ok("deleteFinding returns the removed finding", removed.id === target.id);
ok("one fewer finding", (await F.readFindings()).length === 11);
try { await F.deleteFinding(target.id); ok("deleting again is NOT_FOUND", false); } catch (e) { ok("deleting again is NOT_FOUND", e.code === "NOT_FOUND"); }

// delete all
const cleared = await D.clearAllFindingData();
ok("clear reports counts", cleared.findings === 11 && cleared.assets === 3 && cleared.reports === 2, JSON.stringify(cleared));
ok("stores are empty", (await F.readFindings()).length === 0 && (await A.readAssets()).length === 0 && (await R.readSnapshots()).length === 0);
const again = await D.clearAllFindingData();
ok("clearing an empty store is harmless", again.findings === 0);
await D.seedDemoData();
ok("can seed again after clearing", (await F.readFindings()).length === 12);

console.log(`${pass} passed, ${fail} failed`);
process.chdir(tmpdir());
process.exit(fail ? 1 : 0);
