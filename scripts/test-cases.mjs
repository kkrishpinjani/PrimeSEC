// Tests for investigation cases: lifecycle, validation, dedupe, evidence, plan, concurrency, limits.
// Run: npm run test:cases (Node 22.6+; TypeScript is type-stripped).
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const root = process.cwd();
process.chdir(mkdtempSync(path.join(tmpdir(), "primesec-cases-")));
const url = (f) => path.join(root, "lib", f).replace(/\\/g, "/").replace(/^([A-Za-z]):/, "file:///$1:");
const C = await import(url("cases.ts"));

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const code = async (fn) => { try { await fn(); return null; } catch (e) { return e.code ?? `UNEXPECTED:${e.message}`; } };
const alice = { email: "alice@x" }, bob = { email: "bob@x" };

// ---- priority and severity ----
ok("priority = level x5 + 10 per match (max 3)", C.priorityFrom(7, 0) === 35 && C.priorityFrom(12, 1) === 70 && C.priorityFrom(12, 9) === 90);
ok("priority is capped at 100 and floored at 0", C.priorityFrom(15, 3) === 100 && C.priorityFrom(-5, 0) === 0);
ok("severity bands", C.severityFrom(80) === "critical" && C.severityFrom(60) === "high" && C.severityFrom(35) === "medium" && C.severityFrom(34) === "low");

// ---- manual case ----
const c1 = await C.createCase({ title: "Suspicious login burst", description: "Seen on web-01", severity: "high", links: { assetId: "ast_1" } }, alice);
ok("a new case is 'new', unowned, with a key and a creation event", c1.status === "new" && c1.owner === null && /^PSC-/.test(c1.caseKey) && c1.events[0].type === "case_created" && c1.createdBy === "alice@x");
ok("a case id and key are unique", (await C.createCase({ title: "Another one" }, alice)).caseKey !== c1.caseKey);
ok("title is required (min 3)", await code(() => C.createCase({ title: "ab" }, alice)) === "INVALID");
ok("severity must be a known value", await code(() => C.createCase({ title: "abc", severity: "urgent" }, alice)) === "INVALID");
ok("priorityScore must be an integer 0-100", await code(() => C.createCase({ title: "abc", priorityScore: 101 }, alice)) === "INVALID" && await code(() => C.createCase({ title: "abc", priorityScore: 1.5 }, alice)) === "INVALID");
ok("control characters in the title are rejected", await code(() => C.createCase({ title: "bad\u0007title" }, alice)) === "INVALID");
ok("a multi-line description is allowed", (await C.createCase({ title: "multi", description: "line one\nline two" }, alice)).description.includes("\n"));
ok("links are validated", await code(() => C.createCase({ title: "abc", links: { assetId: 5 } }, alice)) === "INVALID");

// ---- from an alert, with dedupe ----
const inv = (over = {}) => ({ alert: { id: "AL-1", level: 12, description: "SSH brute force", agent: "web-01", timestamp: null, sourceIp: "203.0.113.5" }, searched: 3, openCtiConnected: true, matches: [{ indicatorName: "bad ip", matchedValue: "203.0.113.5", observableType: "ipv4", score: 80 }], ...over });
const a1 = await C.openCaseFromAlert(inv(), alice);
ok("an alert opens a case with a computed priority and severity", a1.created && a1.case.priorityScore === 70 && a1.case.severity === "high" && a1.case.sourceAlertIds[0] === "AL-1" && a1.case.snapshot.matches.length === 1);
const a2 = await C.openCaseFromAlert(inv({ matches: [] }), bob);
ok("the same alert refreshes the open case instead of duplicating it", !a2.created && a2.case.id === a1.case.id);
ok("a refresh never lowers the priority", a2.case.priorityScore === 70);
ok("a refresh is recorded on the timeline", a2.case.events.some((e) => e.type === "correlation_refreshed" && e.actor === "bob@x"));
const a3 = await C.openCaseFromAlert(inv({ alert: { ...inv().alert, level: 15 }, matches: [1, 2, 3, 4].map((n) => ({ indicatorName: "i" + n, matchedValue: "v" + n, observableType: "ipv4", score: 1 })) }), alice);
ok("a refresh can raise the priority", a3.case.priorityScore === 100);
ok("a different alert opens a different case", (await C.openCaseFromAlert(inv({ alert: { ...inv().alert, id: "AL-2" } }), alice)).created);
ok("a no-match case says that is not proof of benign", (await C.openCaseFromAlert(inv({ alert: { ...inv().alert, id: "AL-3" }, matches: [] }), alice)).case.description.includes("does not mean"));

// ---- lifecycle ----
const id = c1.id;
ok("assign sets the owner and records it", (await C.assignCase(id, "carol@x", alice)).owner === "carol@x");
ok("an empty owner unassigns", (await C.assignCase(id, "", alice)).owner === null);
ok("an overlong owner is rejected", await code(() => C.assignCase(id, "x".repeat(257), alice)) === "INVALID");
ok("new -> triaged is allowed", (await C.transitionCase(id, "triaged", "", alice)).status === "triaged");
ok("triaged -> new is not allowed", await code(() => C.transitionCase(id, "new", "", alice)) === "CONFLICT");
ok("an unknown status is rejected", await code(() => C.transitionCase(id, "done", "", alice)) === "INVALID");
ok("resolving needs a note", await code(() => C.transitionCase(id, "resolved", "short", alice)) === "INVALID");
ok("triaged -> investigating -> contained", (await C.transitionCase(id, "investigating", "", alice)).status === "investigating" && (await C.transitionCase(id, "contained", "", alice)).status === "contained");
const resolved = await C.transitionCase(id, "resolved", "Credential reset and session revoked; no further activity.", alice);
ok("resolving stamps closedAt and records the note", resolved.status === "resolved" && resolved.closedAt !== null && resolved.events.at(-1).details.note.includes("Credential"));
ok("a resolved case can be reopened, which clears closedAt", (await C.transitionCase(id, "investigating", "", alice)).closedAt === null);
await C.transitionCase(id, "closed", "Confirmed benign after review with the owner.", alice);
ok("closed is final", await code(() => C.transitionCase(id, "investigating", "", alice)) === "CONFLICT");
ok("a closed case cannot be reassigned, take evidence, or be opened again from its alert", await code(() => C.assignCase(id, "x", alice)) === "CONFLICT" && await code(() => C.addEvidence(id, { type: "note", title: "t" }, alice)) === "CONFLICT");
ok("a missing case is NOT_FOUND", await code(() => C.getCase("nope")) === "NOT_FOUND" && await code(() => C.transitionCase("nope", "triaged", "", alice)) === "NOT_FOUND");
const closedAlert = await C.openCaseFromAlert(inv({ alert: { ...inv().alert, id: "AL-CLOSE" } }), alice);
await C.transitionCase(closedAlert.case.id, "closed", "False positive, confirmed with the host owner.", alice);
ok("once an alert's case is closed, the alert opens a NEW case", (await C.openCaseFromAlert(inv({ alert: { ...inv().alert, id: "AL-CLOSE" } }), alice)).created);

// ---- concurrency: two people move the same case at once ----
const race = await C.createCase({ title: "race case" }, alice);
const both = await Promise.allSettled([C.transitionCase(race.id, "closed", "Closed by the first person.", alice), C.transitionCase(race.id, "triaged", "", bob)]);
ok("conflicting simultaneous transitions: the second is judged against the new state", both.filter((r) => r.status === "fulfilled").length === 1 && both.filter((r) => r.status === "rejected").length === 1, both.map((r) => r.status).join());

// ---- evidence ----
const e1 = await C.createCase({ title: "evidence case" }, alice);
const ev = await C.addEvidence(e1.id, { type: "log", source: "wazuh", title: "auth.log excerpt", content: { lines: ["a", "b"] } }, alice);
ok("evidence is stored with who and when, and logged", ev.evidence.length === 1 && ev.evidence[0].createdBy === "alice@x" && ev.events.at(-1).type === "evidence_added");
ok("evidence content must be an object", await code(() => C.addEvidence(e1.id, { type: "log", title: "t", content: [1] }, alice)) === "INVALID" && await code(() => C.addEvidence(e1.id, { type: "log", title: "t", content: "x" }, alice)) === "INVALID");
ok("oversized evidence content is rejected", await code(() => C.addEvidence(e1.id, { type: "log", title: "t", content: { blob: "x".repeat(20_001) } }, alice)) === "INVALID");
ok("evidence needs a type and a title", await code(() => C.addEvidence(e1.id, { title: "t" }, alice)) === "INVALID" && await code(() => C.addEvidence(e1.id, { type: "log" }, alice)) === "INVALID");

// ---- plan ----
const plan = C.buildPlan(a1.case);
ok("a plan with an IOC match starts with validating it", plan.steps[0].source === "OpenCTI" && /Validate/.test(plan.steps[0].step));
ok("a plan always asks for corroborating evidence and a containment decision", plan.steps.some((s) => /corroborating/i.test(s.step)) && plan.steps.some((s) => /containment/i.test(s.step)));
ok("a plan suggests isolating the alert's agent, but only as a suggestion", plan.suggestedProposals[0].actionType === "isolate_endpoint" && plan.suggestedProposals[0].target === "web-01" && plan.execution === "No action has been executed.");
ok("a plan without OpenCTI warns that no match means nothing yet", C.buildPlan({ caseKey: "K", priorityScore: 0, snapshot: { capturedAt: "x", alert: inv().alert, openCtiConnected: false, matches: [] } }).steps[0].step === "Re-run the OpenCTI lookup");
ok("a manual case with no snapshot still gets a plan and no suggested proposal", C.buildPlan({ caseKey: "K", priorityScore: 0, snapshot: null }).suggestedProposals.length === 0);
const planned = await C.markPlanned((await C.createCase({ title: "to plan" }, alice)).id, plan.steps.length, alice);
ok("generating a plan triages a new case and records it", planned.status === "triaged" && planned.events.some((e) => e.type === "investigation_plan_generated"));

// ---- list and filters ----
const all = await C.listCases();
ok("the list returns summaries without evidence bodies", all.items.every((i) => !("evidence" in i) && typeof i.evidenceCount === "number"));
ok("the list is newest-updated first", all.items.every((c, i) => i === 0 || all.items[i - 1].updatedAt >= c.updatedAt));
ok("filter by status", (await C.listCases({ status: "closed" })).items.every((c) => c.status === "closed"));
ok("search by title", (await C.listCases({ search: "ssh brute" })).items.length >= 1);
ok("open counts exclude resolved and closed", all.openCount === all.items.filter((c) => c.status !== "closed" && c.status !== "resolved").length);
ok("paging", (await C.listCases({ limit: 2, offset: 1 })).items.length === 2);

console.log(`cases: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
