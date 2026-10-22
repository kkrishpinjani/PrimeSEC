// Tests for the risk model and the per-host asset store.
// Run: npm run test:risk (Node 22.6+; TypeScript is type-stripped).
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const original = process.cwd();
const work = mkdtempSync(path.join(tmpdir(), "primesec-risk-"));
process.chdir(work);
const R = await import("../lib/risk.ts");
const A = await import("../lib/assets.ts");

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const rejects = async (name, fn, code) => {
  try { await fn(); fail++; console.log("FAIL (no error):", name); }
  catch (e) { (e.code === code) ? pass++ : (fail++, console.log("FAIL (wrong error):", name, "->", e.code, e.message)); }
};
const actor = { email: "a@x" };
const full = { criticality: "Critical", exposure: "Internet-facing" };

// ---------------- weights and structure ----------------
ok("weights add up to 1", Math.abs(Object.values(R.WEIGHTS).reduce((a, b) => a + b, 0) - 1) < 1e-9);
ok("five factors", R.FACTORS.length === 5);

// ---------------- scoring: everything known ----------------
let s = R.scoreRisk({ severityScore: 9.8, exploitEvidence: "Exploited in the wild", asset: full, detectionEvidence: 100 });
ok("all factors known, worst case -> 99 Critical", s.score === 99 && s.band === "Critical", String(s.score));
ok("all known: confidence 100, range collapses to the score, not provisional", s.confidence === 100 && s.scoreMin === s.score && s.scoreMax === s.score && s.provisional === false);
s = R.scoreRisk({ severityScore: 0.1, exploitEvidence: "None known", asset: { criticality: "Low", exposure: "Internal" }, detectionEvidence: 0 });
ok("all known, best case -> Low", s.band === "Low" && s.score < 35, String(s.score));

// ---------------- unknown is not zero ----------------
s = R.scoreRisk({ severityScore: 9.8 });
ok("severity only: renormalised to the severity itself (98)", s.score === 98 && s.band === "Critical");
ok("severity only: confidence 30 and provisional", s.confidence === 30 && s.provisional === true);
ok("severity only: the range is visible and wide (29..99)", s.scoreMin === 29 && s.scoreMax === 99, `${s.scoreMin}..${s.scoreMax}`);
ok("unknown factors are listed as unknown, with no contribution", s.factors.filter((f) => !f.known).length === 4 && s.factors.every((f) => f.known || (f.value === null && f.contribution === null)));
ok("every factor names its source", s.factors.every((f) => f.source.length > 5));
ok("known contributions add up to the score (within rounding)", (() => { const t = R.scoreRisk({ severityScore: 7, asset: full }); return Math.abs(t.factors.reduce((a, f) => a + (f.contribution ?? 0), 0) - t.score) <= 1; })());

// severity 0 is KNOWN (an informational Log result), not missing: the original treated it as unknown
s = R.scoreRisk({ severityScore: 0 });
ok("severity 0.0 is a known low score, not 'unrated'", s.score === 0 && s.band === "Low" && s.confidence === 30);
const logOnCritical = R.scoreRisk({ severityScore: 0, asset: full });
ok("an informational finding on a critical, exposed asset does NOT rank as Critical (the original renormalised it to the top)", logOnCritical.score < 80, String(logOnCritical.score));
ok("the cap is applied and explained", logOnCritical.score <= R.INFO_CAP && /capped/i.test(logOnCritical.note ?? ""), String(logOnCritical.note));
ok("even with exploit evidence and full context an informational finding stays at or below the cap", R.scoreRisk({ severityScore: 0, exploitEvidence: "Exploited in the wild", asset: full, detectionEvidence: 100 }).score <= R.INFO_CAP);
ok("the range of a capped finding never exceeds the cap either", (r => r.scoreMax <= R.INFO_CAP && r.scoreMin <= r.score)(R.scoreRisk({ severityScore: 0, asset: full })));
ok("a real LOW severity (2.1) on a critical exposed host is NOT capped (context may legitimately raise it)", R.scoreRisk({ severityScore: 2.1, asset: full }).score > 50 && R.scoreRisk({ severityScore: 2.1, asset: full }).note === null);
ok("an informational finding with no context is simply 0, no note", (r => r.score === 0 && r.note === null)(R.scoreRisk({ severityScore: 0 })));
ok("ranking: an informational finding on the most important host sits below a real low-severity finding elsewhere", (() => { const F = (o) => ({ id: "x", host: "h", port: "80", name: "n", severityScore: 5, remediationStatus: "Open", exploitEvidence: "Unknown", ...o }); const ranked = R.rankFindings([F({ id: "info", host: "crown", severityScore: 0 }), F({ id: "low", host: "other", severityScore: 2.1 })], new Map([["crown", { host: "crown", criticality: "Critical", exposure: "Internet-facing", updatedAt: null, updatedBy: null }]])); return ranked[0].id === "low"; })());
ok("...whereas the original rule would have given it 100", (() => { const orig = (100 * 0.2 + 100 * 0.15) / 0.35; return Math.round(orig) === 100; })());
ok("a non-numeric severity is unknown, with no other data -> Unrated", (s = R.scoreRisk({ severityScore: NaN })).score === null && s.band === "Unrated" && s.confidence === 0 && s.scoreMin === null);
ok("severity above 10 is clamped", R.scoreRisk({ severityScore: 99 }).score === 100);
ok("negative severity is clamped to 0", R.scoreRisk({ severityScore: -5 }).score === 0);

// ---------------- context moves the score the right way ----------------
const base = { severityScore: 8 };
const sc = (extra) => R.scoreRisk({ ...base, ...extra }).score;
ok("exposure: internet-facing outranks internal", sc({ asset: { criticality: "Medium", exposure: "Internet-facing" } }) > sc({ asset: { criticality: "Medium", exposure: "Internal" } }));
ok("criticality: critical outranks low", sc({ asset: { criticality: "Critical", exposure: "Internal" } }) > sc({ asset: { criticality: "Low", exposure: "Internal" } }));
ok("exploit evidence: in the wild > public > none known", sc({ exploitEvidence: "Exploited in the wild" }) > sc({ exploitEvidence: "Public exploit" }) && sc({ exploitEvidence: "Public exploit" }) > sc({ exploitEvidence: "None known" }));
ok("'None known' is a known low value, different from Unknown", R.scoreRisk({ ...base, exploitEvidence: "None known" }).confidence === 55 && R.scoreRisk({ ...base, exploitEvidence: "Unknown" }).confidence === 30);
ok("unrecognised enum values are treated as unknown, never as a number", R.scoreRisk({ ...base, exploitEvidence: "bogus", asset: { criticality: "bogus", exposure: "bogus" } }).confidence === 30);

// ---------------- monotonic: raising any known input never lowers the score ----------------
const rnd = (n) => Math.floor(Math.random() * n);
const pick = (xs) => xs[rnd(xs.length)];
let monotone = true;
for (let i = 0; i < 3000 && monotone; i++) {
  const a = { severityScore: rnd(101) / 10, exploitEvidence: pick(["Unknown", "None known", "Public exploit", "Exploited in the wild"]), asset: { criticality: pick(["Unknown", "Low", "Medium", "High", "Critical"]), exposure: pick(["Unknown", "Internal", "Internet-facing"]) } };
  const sA = R.scoreRisk(a);
  const b = { ...a, severityScore: Math.min(10, a.severityScore + 1) };
  const sB = R.scoreRisk(b);
  if (sB.score < sA.score) monotone = false;
  if (sA.scoreMin > sA.score || sA.scoreMax < sA.score) monotone = false; // the range always brackets the score
  if (sA.confidence < 30 || sA.confidence > 100) monotone = false;
}
ok("3000 random inputs: higher severity never lowers the score, and the range always brackets the score", monotone);

// ---------------- bands ----------------
const band = (n) => R.bandOf(n);
ok("band boundaries", band(80) === "Critical" && band(79) === "High" && band(60) === "High" && band(59) === "Medium" && band(35) === "Medium" && band(34) === "Low" && band(0) === "Low" && band(null) === "Unrated");

// ---------------- ranking ----------------
const F = (over) => ({ id: "x", host: "10.0.0.1", port: "80/tcp", name: "n", severityScore: 5, remediationStatus: "Open", exploitEvidence: "Unknown", notInLatestSync: false, ...over });
const assets = new Map([["10.0.0.9", { host: "10.0.0.9", criticality: "Critical", exposure: "Internet-facing", updatedAt: "t", updatedBy: "u" }]]);
let ranked = R.rankFindings([F({ id: "a", severityScore: 5 }), F({ id: "b", severityScore: 9 }), F({ id: "c", severityScore: 7 })], new Map());
ok("ranked by score, highest first", ranked.map((f) => f.id).join() === "b,c,a");
ranked = R.rankFindings([F({ id: "low", severityScore: 9, host: "10.0.0.2" }), F({ id: "ctx", severityScore: 9, host: "10.0.0.9" })], assets);
ok("a critical, exposed asset outranks the same vulnerability on an unclassified host", ranked[0].id === "ctx");
// equal score: the finding that COULD be worse (more unknowns) ranks first
const onlySev = F({ id: "unk", severityScore: 8, host: "10.0.0.3" });
const known = F({ id: "known", severityScore: 8, host: "10.0.0.4", exploitEvidence: "Public exploit" });
const rk = R.rankFindings([known, onlySev], new Map());
ok("tie-break uses the top of the range, so missing context never hides a potentially urgent finding", rk[0].risk.score === rk[1].risk.score || rk[0].risk.scoreMax >= rk[1].risk.scoreMax);
ranked = R.rankFindings([F({ id: "o", remediationStatus: "Open" }), F({ id: "r", remediationStatus: "Resolved" }), F({ id: "c", remediationStatus: "Closed" }), F({ id: "p", remediationStatus: "In Progress" }), F({ id: "t", remediationStatus: "Retest Required" })], new Map());
ok("Resolved and Closed findings are left out of the priority queue", ranked.map((f) => f.id).sort().join() === "o,p,t");
ok("...unless asked for", R.rankFindings([F({ remediationStatus: "Closed" })], new Map(), { includeClosed: true }).length === 1);
ok("asset lookup is case-insensitive", R.rankFindings([F({ host: "HOST.Example" })], new Map([["host.example", { host: "host.example", criticality: "High", exposure: "Internal", updatedAt: null, updatedBy: null }]]))[0].asset.criticality === "High");
ok("a finding with no asset record shows Unknown, not undefined", (r => r.asset.criticality === "Unknown" && r.asset.exposure === "Unknown")(R.rankFindings([F()], new Map())[0]));
ok("ranking does not mutate its input", (() => { const input = [F({ id: "1", severityScore: 1 }), F({ id: "2", severityScore: 9 })]; R.rankFindings(input, new Map()); return input[0].id === "1"; })());
ok("methodology names the model and every weight", R.METHODOLOGY.model === R.MODEL && Object.keys(R.METHODOLOGY.weights).length === 5 && /not a probability/i.test(R.METHODOLOGY.note));

// ---------------- assets ----------------
ok("no assets yet", (await A.readAssets()).length === 0);
let r = await A.updateAsset("10.0.0.9", { criticality: "High", exposure: "Internal" }, actor);
ok("create an asset", r.asset.criticality === "High" && r.asset.exposure === "Internal" && r.before === null && r.asset.updatedBy === "a@x");
r = await A.updateAsset("10.0.0.9", { exposure: "Internet-facing" }, actor);
ok("a partial update keeps the other field", r.asset.criticality === "High" && r.asset.exposure === "Internet-facing" && r.before.exposure === "Internal");
r = await A.updateAsset("  10.0.0.9 ", { criticality: "Unknown" }, actor);
ok("host key is trimmed; an explicit Unknown is allowed", r.asset.criticality === "Unknown" && (await A.readAssets()).length === 1);
r = await A.updateAsset("HOST.example", { criticality: "Low" }, actor);
ok("host matching is case-insensitive and the first spelling is kept", (await A.updateAsset("host.EXAMPLE", { exposure: "Internal" }, actor)).asset.host === "HOST.example");
await rejects("invalid criticality", () => A.updateAsset("h", { criticality: "Extreme" }, actor), "INVALID");
await rejects("invalid exposure", () => A.updateAsset("h", { exposure: "DMZ" }, actor), "INVALID");
await rejects("non-string criticality", () => A.updateAsset("h", { criticality: { $gt: "" } }, actor), "INVALID");
await rejects("empty host", () => A.updateAsset("   ", { criticality: "Low" }, actor), "INVALID");
await rejects("over-long host", () => A.updateAsset("h".repeat(300), { criticality: "Low" }, actor), "INVALID");
const cur = (await A.readAssets()).find((a) => a.host === "10.0.0.9");
await rejects("stale expectedUpdatedAt -> conflict", () => A.updateAsset("10.0.0.9", { criticality: "Low", expectedUpdatedAt: "2000-01-01T00:00:00.000Z" }, actor), "CONFLICT");
ok("a matching expectedUpdatedAt succeeds", (await A.updateAsset("10.0.0.9", { criticality: "Medium", expectedUpdatedAt: cur.updatedAt }, actor)).asset.criticality === "Medium");
await rejects("expectedUpdatedAt null on an existing asset -> conflict", () => A.updateAsset("10.0.0.9", { criticality: "Low", expectedUpdatedAt: null }, actor), "CONFLICT");
ok("expectedUpdatedAt null on a new host works", (await A.updateAsset("brand-new", { criticality: "Low", expectedUpdatedAt: null }, actor)).asset.host === "brand-new");
await Promise.all(Array.from({ length: 30 }, (_, i) => A.updateAsset(`host-${i}`, { criticality: "High" }, actor)));
ok("30 concurrent creates: none lost", (await A.readAssets()).filter((a) => a.host.startsWith("host-")).length === 30);
ok("assetMap is keyed by lower-case host", (await A.assetMap()).get("host.example")?.criticality === "Low");

process.chdir(original);
rmSync(work, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
