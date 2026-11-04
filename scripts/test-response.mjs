// Tests for governed response: policy gates, separation of duties, idempotency, concurrency, failure handling, verify/rollback.
// The adapter below is a test double that exists only here: PrimeSEC ships with NO adapter.
// Run: npm run test:response (Node 22.6+; TypeScript is type-stripped).
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const root = process.cwd();
process.chdir(mkdtempSync(path.join(tmpdir(), "primesec-resp-")));
const R = await import(path.join(root, "lib", "response.ts").replace(/\\/g, "/").replace(/^([A-Za-z]):/, "file:///$1:"));

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const code = async (fn) => { try { await fn(); return null; } catch (e) { return e.code ?? `UNEXPECTED:${e.message}`; } };

const alice = { email: "alice@x" }, bob = { email: "bob@x" }, carol = { email: "carol@x" };
const ON = { ...R.responseConfig({}), enabled: true, allowedActions: new Set(["block_ip"]) };
const calls = [];
let behaviour = "ok";
const adapter = {
  name: "test-fw", supportedActions: ["block_ip"],
  async execute(action, target, key) {
    calls.push({ action, target, key });
    if (behaviour === "slow") await new Promise((r) => setTimeout(r, 80));
    if (behaviour === "fail") throw new Error("firewall said no at https://fw.internal/api?key=SECRET");
    return { blocked: target };
  },
  async verify() { return { verified: behaviour !== "unverifiable" }; },
  async rollback() { return { rolledBack: behaviour !== "norollback" }; }
};
const reg = new R.AdapterRegistry([adapter]);
const empty = new R.AdapterRegistry();
const prop = async (over = {}) => R.createProposal({ actionType: "block_ip", target: "198.51.100.7", rationale: "Beaconing to a known C2 address", ...over }, alice, ON);
const approved = async (over = {}) => { const p = await prop(over); return R.reviewProposal(p.id, "approve", "ok", bob, ON); };

// ---- defaults are locked down ----
const d = R.responseConfig({});
ok("execution is off by default", d.enabled === false && d.allowedActions.size === 0 && d.dualControl === true);
ok("only the literal word true enables it", !R.responseConfig({ RESPONSE_EXECUTION_ENABLED: "1" }).enabled && !R.responseConfig({ RESPONSE_EXECUTION_ENABLED: "yes" }).enabled && R.responseConfig({ RESPONSE_EXECUTION_ENABLED: "TRUE" }).enabled);
ok("dual control stays on unless explicitly false", R.responseConfig({ RESPONSE_REQUIRE_DUAL_CONTROL: "0" }).dualControl && !R.responseConfig({ RESPONSE_REQUIRE_DUAL_CONTROL: "false" }).dualControl);
ok("the shipped registry has no adapter", R.registry.adapters.length === 0 && R.responseStatus().adapters.length === 0);

// ---- proposal validation ----
ok("bad action type rejected", await code(() => R.createProposal({ actionType: "Block IP; rm", target: "x", rationale: "long enough reason" }, alice, ON)) === "INVALID");
ok("empty target rejected", await code(() => R.createProposal({ actionType: "block_ip", target: "  ", rationale: "long enough reason" }, alice, ON)) === "INVALID");
ok("control characters in target rejected", await code(() => R.createProposal({ actionType: "block_ip", target: "1.2.3.4\nDROP", rationale: "long enough reason" }, alice, ON)) === "INVALID");
ok("overlong target rejected", await code(() => R.createProposal({ actionType: "block_ip", target: "x".repeat(301), rationale: "long enough reason" }, alice, ON)) === "INVALID");
ok("a rationale is required", await code(() => R.createProposal({ actionType: "block_ip", target: "1.2.3.4", rationale: "short" }, alice, ON)) === "INVALID");
ok("link values are validated", await code(() => R.createProposal({ actionType: "block_ip", target: "1.2.3.4", rationale: "long enough reason", links: { alertId: 5 } }, alice, ON)) === "INVALID");

// ---- review: separation of duties ----
const p1 = await prop();
ok("a new proposal is 'proposed'", p1.status === "proposed" && p1.proposedBy === "alice@x");
ok("proposer cannot approve their own", await code(() => R.reviewProposal(p1.id, "approve", "", alice, ON)) === "FORBIDDEN");
ok("rejecting needs a reason", await code(() => R.reviewProposal(p1.id, "reject", "", bob, ON)) === "INVALID");
ok("bad decision rejected", await code(() => R.reviewProposal(p1.id, "maybe", "", bob, ON)) === "INVALID");
const ap = await R.reviewProposal(p1.id, "approve", "looks right", bob, ON);
ok("another person can approve", ap.status === "approved" && ap.reviewedBy === "bob@x");
ok("a reviewed proposal cannot be reviewed again", await code(() => R.reviewProposal(p1.id, "reject", "changed my mind", carol, ON)) === "CONFLICT");
ok("dual control can be turned off by policy", (await R.reviewProposal((await prop()).id, "approve", "", alice, { ...ON, dualControl: false })).status === "approved");
ok("only the proposer can cancel", await code(async () => R.cancelProposal((await prop()).id, bob)) === "FORBIDDEN");

// ---- execution gates, in order ----
const key = (n) => `key-${n}-0000000000`;
ok("disabled by policy -> LOCKED", await code(() => R.executeProposal(ap.id, key(1), carol, reg, { ...ON, enabled: false })) === "LOCKED");
ok("action not allow-listed -> FORBIDDEN", await code(() => R.executeProposal(ap.id, key(2), carol, reg, { ...ON, allowedActions: new Set(["other"]) })) === "FORBIDDEN");
ok("an unapproved proposal -> CONFLICT", await code(async () => R.executeProposal((await prop()).id, key(3), carol, reg, ON)) === "CONFLICT");
ok("proposer cannot execute their own -> FORBIDDEN", await code(() => R.executeProposal(ap.id, key(4), alice, reg, ON)) === "FORBIDDEN");
ok("a stale approval -> CONFLICT", await code(() => R.executeProposal(ap.id, key(5), carol, reg, ON, {}, Date.now() + 31 * 60_000)) === "CONFLICT");
ok("allow-listed but no adapter -> UNAVAILABLE (as shipped)", await code(() => R.executeProposal(ap.id, key(6), carol, empty, ON)) === "UNAVAILABLE");
ok("a missing or short Idempotency-Key -> INVALID", await code(() => R.executeProposal(ap.id, undefined, carol, reg, ON)) === "INVALID" && await code(() => R.executeProposal(ap.id, "short", carol, reg, ON)) === "INVALID");
ok("nothing was called by any refused attempt", calls.length === 0);
ok("a refused attempt leaves the proposal approved", (await R.readResponse()).proposals.find((x) => x.id === ap.id).status === "approved");

// ---- happy path ----
const phases = [];
const hooks = { onPhase: async (ph) => { phases.push(ph); } };
const run1 = await R.executeProposal(ap.id, key(7), carol, reg, ON, hooks);
ok("an approved proposal executes through the adapter", run1.execution.status === "executed" && run1.replay === false && calls.length === 1 && calls[0].target === "198.51.100.7");
ok("the adapter received the idempotency key", calls[0].key === key(7));
ok("'requested' is audited before 'executed'", phases.join() === "requested,executed");
ok("the proposal becomes executed", (await R.readResponse()).proposals.find((x) => x.id === ap.id).status === "executed");
ok("the record names requester and approver", run1.execution.requestedBy === "carol@x" && run1.execution.approvedBy === "bob@x");

// ---- idempotency ----
const replay = await R.executeProposal(ap.id, key(7), carol, reg, ON);
ok("the same key replays the stored result and does not call again", replay.replay === true && replay.execution.id === run1.execution.id && calls.length === 1);
ok("the same key for another proposal is refused", await code(async () => R.executeProposal((await approved()).id, key(7), carol, reg, ON)) === "CONFLICT");
ok("a new key on an executed proposal is refused", await code(() => R.executeProposal(ap.id, key(8), carol, reg, ON)) === "CONFLICT");

// ---- concurrency: two requests, two keys, one action ----
behaviour = "slow";
const c1 = await approved();
const before = calls.length;
const both = await Promise.allSettled([R.executeProposal(c1.id, key(9), carol, reg, ON), R.executeProposal(c1.id, key(10), carol, reg, ON)]);
ok("two concurrent executions: exactly one runs", both.filter((r) => r.status === "fulfilled").length === 1 && both.filter((r) => r.status === "rejected").length === 1 && calls.length === before + 1, both.map((r) => r.status).join());
behaviour = "ok";

// ---- failure handling ----
behaviour = "fail";
const f = await approved({ target: "203.0.113.9" });
const failed = await R.executeProposal(f.id, key(11), carol, reg, ON, hooks);
ok("an adapter failure is recorded as failed", failed.execution.status === "failed");
ok("the stored error has no URL or secret", !/https?:|SECRET/.test(JSON.stringify(failed.execution.result)), JSON.stringify(failed.execution.result));
ok("the proposal is locked as execution_failed", (await R.readResponse()).proposals.find((x) => x.id === f.id).status === "execution_failed");
ok("a failed action is NOT retried with a new key", await code(() => R.executeProposal(f.id, key(12), carol, reg, ON)) === "CONFLICT");
ok("the same key still returns the failed record", (await R.executeProposal(f.id, key(11), carol, reg, ON)).execution.status === "failed");
behaviour = "ok";

// ---- audit failure is fail-closed ----
const g = await approved({ target: "203.0.113.50" });
const callsBefore = calls.length;
ok("if the audit cannot be written, nothing is executed", await code(() => R.executeProposal(g.id, key(13), carol, reg, ON, { onPhase: async (ph) => { if (ph === "requested") throw new Error("disk full"); } })) === "UNAVAILABLE" && calls.length === callsBefore);
ok("... and the proposal is locked for inspection", (await R.readResponse()).proposals.find((x) => x.id === g.id).status === "execution_failed");

// ---- verify and rollback ----
const v = await R.verifyExecution(run1.execution.id, reg);
ok("verification marks the execution verified", v.status === "verified");
behaviour = "unverifiable";
const v2 = await R.verifyExecution((await R.executeProposal((await approved({ target: "203.0.113.77" })).id, key(14), carol, reg, ON)).execution.id, reg);
ok("an unconfirmed action is verification_failed, not verified", v2.status === "verification_failed");
behaviour = "ok";
ok("a failed execution cannot be verified", await code(() => R.verifyExecution(failed.execution.id, reg)) === "CONFLICT");
const rb = await R.rollbackExecution(run1.execution.id, reg);
ok("rollback marks the execution rolled_back", rb.status === "rolled_back");
ok("a rolled-back execution cannot be rolled back again", await code(() => R.rollbackExecution(run1.execution.id, reg)) === "CONFLICT");
ok("a failed execution cannot be rolled back", await code(() => R.rollbackExecution(failed.execution.id, reg)) === "CONFLICT");
ok("verify needs the original adapter to be registered", await code(() => R.verifyExecution(v2.id, empty)) === "UNAVAILABLE");
behaviour = "norollback";
const rbf = await R.rollbackExecution(v2.id, reg);
ok("a rollback the adapter cannot do is rollback_failed", rbf.status === "rollback_failed");
behaviour = "ok";

// ---- reads ----
ok("lists are newest first", (await R.listExecutions())[0].createdAt >= (await R.listExecutions()).at(-1).createdAt);
ok("status reports adapters and the allow-list", R.responseStatus(reg, ON).allowedActions[0] === "block_ip" && R.responseStatus(reg, ON).adapters[0].name === "test-fw");

console.log(`response: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
