// Tests for the Agent Security module: the evaluator's fail-closed rules, policy handling, validation and storage.
// Run: npm run test:agentsec (Node 22.6+; TypeScript is type-stripped).
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const work = mkdtempSync(path.join(tmpdir(), "primesec-agentsec-"));
process.chdir(work);
const A = await import("../lib/agentsec.ts");

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const rejects = async (name, fn, code) => { try { await fn(); fail++; console.log("FAIL (no error):", name); } catch (e) { (e.code === code) ? pass++ : (fail++, console.log("FAIL (wrong error):", name, e.code, e.message)); } };
const throws = (name, fn, code) => { try { fn(); fail++; console.log("FAIL (no error):", name); } catch (e) { (e.code === code) ? pass++ : (fail++, console.log("FAIL (wrong error):", name, e.code, e.message)); } };

const ev = (state, input) => A.evaluateAction(state, input);
const fresh = () => A.defaultState();

// ---------------- the shipped scenarios ----------------
const run = A.runScenarios(fresh());
ok("all six built-in scenarios pass on the default policy set", run.passed === run.total && run.total === 6, JSON.stringify(run.results.filter((r) => !r.passed)));

// ---------------- core decisions ----------------
let s = fresh();
ok("registered read tool is allowed", ev(s, { agentId: "agent-procurement-01", tool: "purchase_order.read", dataClass: "internal" }).decision === "ALLOW");
ok("unregistered tool is denied", ev(s, { agentId: "agent-procurement-01", tool: "shell.execute" }).decision === "DENY");
ok("registered but sensitive tool needs approval", ev(s, { agentId: "agent-finance-01", tool: "payment.approve" }).decision === "REQUIRE_APPROVAL");
ok("unknown agent is held for review", ev(s, { agentId: "nobody", tool: "x.read" }).decision === "REVIEW");
ok("sensitive data to an external target is denied", ev(s, { agentId: "agent-support-01", tool: "ticket.comment", dataClass: "customer-data", external: true }).decision === "DENY");
ok("external target inferred from the text, not only the flag", ev(s, { agentId: "agent-support-01", tool: "ticket.comment", dataClass: "customer-data", target: "third-party vendor" }).decision === "DENY");
ok("non-sensitive data to an external target is not blocked", ev(s, { agentId: "agent-procurement-01", tool: "purchase_order.read", dataClass: "internal", external: true }).decision === "ALLOW");
ok("caller cannot lower sensitivity (sensitive:false ignored for a payment tool)", ev(s, { agentId: "agent-finance-01", tool: "payment.approve", dataClass: "internal", sensitive: false }).decision === "REQUIRE_APPROVAL");
ok("caller can raise sensitivity", ev(s, { agentId: "agent-procurement-01", tool: "purchase_order.read", dataClass: "internal", sensitive: true }).decision === "REQUIRE_APPROVAL");
ok("evaluation carries the policy revision", ev(s, { agentId: "a", tool: "t" }).policyRevision === 1);
ok("result states that enforcement depends on the caller", /asks before acting/.test(ev(s, { agentId: "a", tool: "t" }).enforcementNote));
ok("an allow result explains itself", ev(s, { agentId: "agent-procurement-01", tool: "purchase_order.read" }).reasons[0].policyId === "BASELINE");

// ---------------- fail-closed even if policies are all disabled or edited by hand ----------------
s = fresh(); s.policies.forEach((p) => { p.enabled = false; });
ok("all policies off: unregistered tool still DENIED", ev(s, { agentId: "agent-procurement-01", tool: "shell.execute" }).decision === "DENY");
ok("all policies off: unknown agent still REVIEWED", ev(s, { agentId: "ghost", tool: "x" }).decision === "REVIEW");
s = fresh(); s.policies = [];
ok("no policies at all: unregistered tool still DENIED", ev(s, { agentId: "agent-procurement-01", tool: "shell.execute" }).decision === "DENY");
ok("no policies at all: unknown agent still REVIEWED", ev(s, { agentId: "ghost", tool: "x" }).decision === "REVIEW");
s = fresh(); s.agents.find((a) => a.id === "agent-procurement-01").status = "suspended";
ok("suspended agent: even a registered read tool is DENIED", ev(s, { agentId: "agent-procurement-01", tool: "purchase_order.read" }).decision === "DENY");
ok("suspension is explained", ev(s, { agentId: "agent-procurement-01", tool: "purchase_order.read" }).reasons.some((r) => r.policyId === "BASELINE-SUSPENDED"));
s = fresh(); s.policies.find((p) => p.id === "POL-001").action = "review"; // tampered state: weaker action
ok("a weakened baseline policy cannot weaken the decision (floor stays DENY)", ev(s, { agentId: "agent-procurement-01", tool: "shell.execute" }).decision === "DENY");

// ---------------- strictest policy wins, a policy can never shadow a stricter one ----------------
s = fresh();
s.policies.unshift({ id: "POL-X", name: "weak", description: "", enabled: true, action: "review", condition: "sensitive_action", severity: "low", version: 1, locked: false, createdAt: "", updatedAt: null });
ok("a weaker policy listed first does not shadow the stricter one", ev(s, { agentId: "agent-finance-01", tool: "payment.approve" }).decision === "REQUIRE_APPROVAL");
s.policies.push({ id: "POL-Y", name: "strict", description: "", enabled: true, action: "deny", condition: "sensitive_action", severity: "critical", version: 1, locked: false, createdAt: "", updatedAt: null });
ok("a stricter added policy makes the decision stricter", ev(s, { agentId: "agent-finance-01", tool: "payment.approve" }).decision === "DENY");
s = fresh(); s.policies.find((p) => p.id === "POL-002").enabled = false;
ok("disabling a non-baseline policy removes only its effect", ev(s, { agentId: "agent-finance-01", tool: "payment.approve" }).decision === "ALLOW");

// ---------------- property test: the three fail-closed rules hold for random inputs ----------------
const rnd = (n) => Math.floor(Math.random() * n);
const pickOne = (xs) => xs[rnd(xs.length)];
let violations = 0, cases = 0;
for (let i = 0; i < 4000; i++) {
  const st = fresh();
  for (const p of st.policies) { if (Math.random() < 0.5) p.enabled = false; if (Math.random() < 0.2) p.action = pickOne(["review", "require_approval", "deny"]); }
  if (Math.random() < 0.2) st.policies = [];
  const agent = pickOne(st.agents);
  if (Math.random() < 0.3) agent.status = "suspended";
  const tools = [...agent.tools, "shell.execute", "payment.approve", "x.read", "email.send", "db.drop"];
  const input = { agentId: Math.random() < 0.3 ? "unregistered-" + rnd(5) : agent.id, tool: pickOne(tools), dataClass: pickOne(["internal", "customer-data", "unknown", "financial"]), external: Math.random() < 0.5, sensitive: Math.random() < 0.3 ? false : undefined };
  const e = A.evaluateAction(st, input);
  const known = st.agents.find((a) => a.id === input.agentId);
  cases++;
  if (!known && e.decision === "ALLOW") violations++;
  if (known && known.status === "suspended" && e.decision !== "DENY") violations++;
  if (known && !known.tools.includes(input.tool) && e.decision !== "DENY") violations++;
}
ok(`fail-closed invariant held for ${cases} random cases`, violations === 0, String(violations));

// ---------------- findings ----------------
s = fresh();
const d1 = ev(s, { agentId: "agent-procurement-01", tool: "shell.execute" });
A.recordFinding(s, d1, "evt1"); A.recordFinding(s, d1, "evt2"); A.recordFinding(s, d1, "evt3");
ok("repeats collapse into one finding with a count", s.findings.length === 1 && s.findings[0].count === 3, JSON.stringify(s.findings.map((f) => f.count)));
ok("a different tool is a different finding", (A.recordFinding(s, ev(s, { agentId: "agent-procurement-01", tool: "fs.write" }), "e"), s.findings.length === 2));
ok("ALLOW creates no finding", A.recordFinding(s, ev(s, { agentId: "agent-procurement-01", tool: "purchase_order.read" }), "e") === null);
ok("approval-needed findings are pending_approval", (A.recordFinding(s, ev(s, { agentId: "agent-finance-01", tool: "payment.approve" }), "e"), s.findings.find((f) => f.decision === "REQUIRE_APPROVAL").status === "pending_approval"));
ok("finding severity reflects the worst reason", s.findings.find((f) => f.decision === "DENY").severity === "high");
let big = fresh();
for (let i = 0; i < 700; i++) A.recordFinding(big, ev(big, { agentId: "agent-procurement-01", tool: "tool.n" + i }), null);
ok("findings are capped at 500", big.findings.length === 500);

// ---------------- validation ----------------
const good = { name: "Report Bot", framework: "LangChain", owner: "Data team", environment: "development", tools: ["report.read", "db.query_ro"] };
const agent = A.buildAgent(good, "admin@x");
ok("agent built with a generated id and registered status", /^agent-report-bot-[0-9a-f]{6}$/.test(agent.id) && agent.status === "registered" && agent.seeded === false);
ok("two agents with the same name get different ids", A.buildAgent(good, "a").id !== A.buildAgent(good, "a").id);
throws("missing owner", () => A.buildAgent({ ...good, owner: "" }, "a"), "INVALID");
throws("unknown framework", () => A.buildAgent({ ...good, framework: "Nope" }, "a"), "INVALID");
throws("bad environment", () => A.buildAgent({ ...good, environment: "prod" }, "a"), "INVALID");
throws("tool name with a space", () => A.buildAgent({ ...good, tools: ["rm -rf /"] }, "a"), "INVALID");
throws("tool name with shell characters", () => A.buildAgent({ ...good, tools: ["a;b"] }, "a"), "INVALID");
ok("control characters stripped from the name", A.buildAgent({ ...good, name: "Bo\u0000b\n" }, "a").name === "Bob");
ok("tools are de-duplicated and capped", A.buildAgent({ ...good, tools: Array.from({ length: 80 }, (_, i) => "t." + i).concat(["t.1"]) }, "a").tools.length === 50);
ok("unknown privilege falls back to moderate", A.buildAgent({ ...good, privileges: "root" }, "a").privileges === "moderate");

// ---------------- storage and mutations ----------------
ok("reading before any write returns the seeded defaults", (await A.readState()).agents.length === 3);
const reg = await A.registerAgent(good, "admin@x");
ok("registered agent persisted", (await A.readState()).agents.some((a) => a.id === reg.id));
await Promise.all(Array.from({ length: 20 }, (_, i) => A.registerAgent({ ...good, name: "Parallel " + i }, "admin@x")));
ok("20 parallel registrations are all kept (no lost updates)", (await A.readState()).agents.length === 3 + 1 + 20);
const suspended = await A.setAgentStatus(reg.id, "suspended");
ok("suspend works and reports the previous status", suspended.agent.status === "suspended" && suspended.before === "registered");
ok("a suspended agent is denied by the evaluator", A.evaluateAction(await A.readState(), { agentId: reg.id, tool: "report.read" }).decision === "DENY");
await A.setAgentStatus(reg.id, "registered");
ok("reactivated agent is allowed again", A.evaluateAction(await A.readState(), { agentId: reg.id, tool: "report.read" }).decision === "ALLOW");
await rejects("bad status value", () => A.setAgentStatus(reg.id, "deleted"), "INVALID");
await rejects("unknown agent id", () => A.setAgentStatus("agent-nope", "suspended"), "NOT_FOUND");

const rev0 = (await A.readState()).policyRevision;
await rejects("baseline policy cannot be disabled", () => A.setPolicyEnabled("POL-001", false), "LOCKED");
await rejects("baseline unknown-agent policy cannot be disabled", () => A.setPolicyEnabled("POL-004", false), "LOCKED");
const off = await A.setPolicyEnabled("POL-002", false);
ok("non-baseline policy can be disabled; version and revision increase", off.policy.enabled === false && off.policy.version === 2 && (await A.readState()).policyRevision === rev0 + 1);
await A.setPolicyEnabled("POL-002", true);
await rejects("unknown policy id", () => A.setPolicyEnabled("POL-NOPE", true), "NOT_FOUND");
await rejects("enabled must be boolean", () => A.setPolicyEnabled("POL-002", "yes"), "INVALID");
await rejects("a policy cannot be created with action allow", () => A.createPolicy({ name: "n", description: "d", condition: "tool_not_registered", action: "allow", severity: "low" }), "INVALID");
await rejects("bad condition", () => A.createPolicy({ name: "n", description: "d", condition: "always", action: "deny", severity: "low" }), "INVALID");
await rejects("bad severity", () => A.createPolicy({ name: "n", description: "d", condition: "sensitive_action", action: "deny", severity: "urgent" }), "INVALID");
const np = await A.createPolicy({ name: "Block everything sensitive", description: "strict", condition: "sensitive_action", action: "deny", severity: "high" });
ok("created policy is enabled, unlocked and takes effect", np.enabled && !np.locked && A.evaluateAction(await A.readState(), { agentId: "agent-finance-01", tool: "payment.approve" }).decision === "DENY");
ok("the scenario suite notices that a policy change altered behaviour", A.runScenarios(await A.readState()).passed < 6);

console.log(`${pass} passed, ${fail} failed`);
process.chdir(tmpdir());
process.exit(fail ? 1 : 0);
