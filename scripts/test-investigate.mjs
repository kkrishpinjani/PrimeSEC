// Tests for the investigation additions: CVE and MITRE extraction, exact-id OpenCTI lookup, and what they do to a case.
// Run: npm run test:investigate (Node 22.6+; TypeScript is type-stripped).
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const root = process.cwd();
process.chdir(mkdtempSync(path.join(tmpdir(), "primesec-inv2-")));
const url = (f) => path.join(root, "lib", f).replace(/\\/g, "/").replace(/^([A-Za-z]):/, "file:///$1:");
const Co = await import(url("correlation.ts"));
const In = await import(url("investigate.ts"));
const Ca = await import(url("cases.ts"));

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const alice = { email: "alice@x" };

// ---- extraction ----
ok("CVE ids are found, upper-cased and de-duplicated", JSON.stringify(Co.extractCves("Exploit CVE-2021-44228 and cve-2021-45046; again CVE-2021-44228")) === JSON.stringify(["CVE-2021-44228", "CVE-2021-45046"]));
ok("malformed CVE ids are ignored", Co.extractCves("CVE-21-1 CVE-2021-1 XCVE-2021-44228Y").length === 0);
ok("at most 10 CVEs are taken from one alert", Co.extractCves(Array.from({ length: 30 }, (_, i) => `CVE-2024-${1000 + i}`).join(" ")).length === 10);
ok("technique ids, including sub-techniques, are found", JSON.stringify(Co.extractTechniques("rule maps to T1110 and t1059.001")) === JSON.stringify(["T1110"]) && Co.extractTechniques("T1059.001").join() === "T1059.001");
ok("lookalikes are not techniques", Co.extractTechniques("AT1110X T11 T12345 PT1110").length === 0 && Co.extractTechniques("").length === 0 && Co.extractTechniques(undefined).length === 0);

// ---- exact-id OpenCTI lookup ----
const vuln = (name, extra = {}, markings = ["TLP:CLEAR"]) => ({ id: "id-" + name, name, description: "d", x_opencti_cvss_base_score: 9.8, x_opencti_cisa_kev: true, objectMarking: markings.map((definition) => ({ definition })), objectLabel: [], ...extra });
let seen = [];
const deps = (nodes, over = {}) => ({
  query: async (q, v) => { seen.push(v); return { vulnerabilities: { pageInfo: { endCursor: null, hasNextPage: false, globalCount: nodes.length }, edges: nodes.map((n) => ({ node: n })) } }; },
  configured: () => true, safeError: () => "Could not reach the upstream platform.", env: {}, ...over
});

const one = (await In.lookupCves(["CVE-2021-44228"], deps([vuln("CVE-2021-44228"), vuln("CVE-2021-44228-related")])))[0];
ok("an exact match is reported with CVSS and the CISA known-exploited flag", one.known === true && one.cvss === 9.8 && one.knownExploited === true && one.restricted === false);
ok("the CVE is passed as a search variable", seen[0].search === "CVE-2021-44228");
const near = (await In.lookupCves(["CVE-2021-44228"], deps([vuln("CVE-2021-44228-related"), vuln("CVE-2021-442289")])))[0];
ok("a near-miss from OpenCTI's text search is NOT a match", near.known === false && near.knownExploited === null);
const notFound = (await In.lookupCves(["CVE-2030-0001"], deps([])))[0];
ok("a CVE OpenCTI does not hold is known:false, not an error", notFound.known === false && notFound.knownExploited === null);
const notKev = (await In.lookupCves(["CVE-2020-1"], deps([vuln("CVE-2020-1", { x_opencti_cisa_kev: false })])))[0];
ok("known but not on the CISA list is knownExploited:false", notKev.known === true && notKev.knownExploited === false);
const noFlag = (await In.lookupCves(["CVE-2020-2"], deps([vuln("CVE-2020-2", { x_opencti_cisa_kev: null })])))[0];
ok("a missing flag is unknown (null), not false", noFlag.knownExploited === null);
const hidden = (await In.lookupCves(["CVE-2020-3"], deps([vuln("CVE-2020-3", {}, ["TLP:RED"])], { env: { OPENCTI_ALLOWED_MARKINGS: "TLP:CLEAR" } })))[0];
ok("a CVE hidden by the marking policy is reported as restricted, never as 'not found'", hidden.restricted === true && hidden.known === null && hidden.cvss === null);
const broken = await In.lookupCves(["CVE-2020-4", "CVE-2020-5"], deps([], { query: async () => { throw new Error("connect ECONNREFUSED 10.0.0.1 token abc"); } }));
ok("an upstream failure gives unknown for each CVE and does not throw", broken.length === 2 && broken.every((b) => b.known === null && b.knownExploited === null));
ok("lookups are sequential and capped by the caller's list", (await In.lookupCves(["CVE-1-1111", "CVE-2-2222"], deps([]))).length === 2);

// ---- investigateAlert validates before anything else ----
const bad = async (v) => { try { await In.investigateAlert(v); return null; } catch (e) { return e.code; } };
ok("an invalid alert id is refused before any upstream call", await bad("../x") === "INVALID" && await bad("") === "INVALID" && await bad(undefined) === "INVALID" && await bad("a b") === "INVALID");

// ---- what a known-exploited CVE does to a case ----
const inv = (over = {}) => ({ alert: { id: "AL-9", level: 7, description: "Vulnerable package detected", agent: "web-01", timestamp: null, sourceIp: "—" }, searched: 0, openCtiConnected: true, matches: [], ...over });
const plain = await Ca.openCaseFromAlert(inv(), alice);
ok("without intelligence, priority is just the alert level", plain.case.priorityScore === 35);
const withKev = await Ca.openCaseFromAlert(inv({ alert: { ...inv().alert, id: "AL-10" }, vulnerabilities: [{ cve: "CVE-2021-44228", known: true, cvss: 10, knownExploited: true }, { cve: "CVE-2020-1", known: true, cvss: 5, knownExploited: false }], techniques: ["T1190"] }), alice);
ok("one exploited-in-the-wild CVE raises priority like an indicator match (+10); a merely known one does not", withKev.case.priorityScore === 45);
ok("the snapshot keeps the CVEs and techniques", withKev.case.snapshot.vulnerabilities.length === 2 && withKev.case.snapshot.techniques[0] === "T1190");
const plan = Ca.buildPlan(withKev.case);
ok("the plan adds a patch-status step naming the exploited CVE", plan.steps.some((s) => /patch status/i.test(s.step) && s.detail.includes("CVE-2021-44228") && !s.detail.includes("CVE-2020-1")));
ok("the plan adds an ATT&CK review step that says a tag is not proof", plan.steps.some((s) => /ATT&CK/.test(s.step) && /not proof/.test(s.detail)));
ok("a case with neither gets neither step", !Ca.buildPlan(plain.case).steps.some((s) => /patch status|ATT&CK/i.test(s.step)));
const refreshed = await Ca.openCaseFromAlert(inv({ alert: { ...inv().alert, id: "AL-10" }, vulnerabilities: [], techniques: [] }), alice);
ok("a refresh with less information does not lower the priority", refreshed.case.priorityScore === 45 && !refreshed.created);

console.log(`investigate: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
