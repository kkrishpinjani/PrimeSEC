// Tests for the action gateway: one-time permits bound to an exact action, approvals with four-eyes and single use,
// expiry, concurrency, and the guarantee that an approval never overrides a denial.
// Run: npm run test:agentgate (Node 22.6+; TypeScript is type-stripped).
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const work = mkdtempSync(path.join(tmpdir(), "primesec-agentgate-"));
process.chdir(work);
const G = await import("../lib/agentgate.ts");
const A = await import("../lib/agentsec.ts");

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };

const alice = { email: "alice@x.io", name: "Alice" };   // analyst who proposes actions
const bob = { email: "bob@x.io", name: "Bob" };         // someone else
const read = { agentId: "agent-procurement-01", tool: "purchase_order.read", dataClass: "internal" };
const pay = { agentId: "agent-finance-01", tool: "payment.approve", dataClass: "financial" };
const T0 = Date.parse("2026-10-26T10:00:00Z");

// ---------------- ALLOW -> permit ----------------
const a1 = await G.authorize(read, alice, T0);
ok("ALLOW issues a permit", a1.decision === "ALLOW" && typeof a1.permit === "string" && a1.permit.length >= 40 && a1.status === "authorized_not_executed");
ok("permit is short-lived (60 s)", a1.permitExpiresInSeconds === 60);
ok("the response says nothing was executed", /Nothing was executed/.test(a1.message));
const stateFile = readFileSync(path.join(work, "data", "agentsec-state.json"), "utf8");
ok("only a hash of the permit is stored, never the permit", !stateFile.includes(a1.permit) && /"grantHash": "[0-9a-f]{64}"/.test(stateFile));

// ---------------- consume: exact action, once ----------------
let c = await G.consumePermit(a1.permit, read, T0 + 1000);
ok("permit consumed with the same action", c.ok === true && c.tool === "purchase_order.read" && c.via === "policy");
c = await G.consumePermit(a1.permit, read, T0 + 2000);
ok("replay is rejected (409)", c.ok === false && c.status === 409 && c.reason === "replay");

const a2 = await G.authorize(read, alice, T0);
c = await G.consumePermit(a2.permit, { ...read, tool: "purchase_order.delete" }, T0 + 1000);
ok("a permit cannot be used for a different tool", c.ok === false && c.status === 403 && c.reason === "mismatch");
c = await G.consumePermit(a2.permit, { ...read, agentId: "agent-support-01" }, T0 + 1000);
ok("a permit cannot be used by a different agent", c.ok === false && c.reason === "mismatch");
c = await G.consumePermit(a2.permit, { ...read, target: "external vendor" }, T0 + 1000);
ok("a permit cannot be used for a different destination", c.ok === false && c.reason === "mismatch");
c = await G.consumePermit(a2.permit, { ...read, dataClass: "financial" }, T0 + 1000);
ok("a permit cannot be used for a different data class", c.ok === false && c.reason === "mismatch");
c = await G.consumePermit(a2.permit, { ...read, sensitive: true }, T0 + 1000);
ok("a permit cannot be used with a different sensitivity flag", c.ok === false && c.reason === "mismatch");
c = await G.consumePermit(a2.permit, read, T0 + 1000);
ok("a mismatch does not spend the permit: the right action still works", c.ok === true);
ok("tool name in a permit match is case sensitive", (await G.consumePermit((await G.authorize(read, alice, T0)).permit, { ...read, tool: "Purchase_Order.Read" }, T0)).ok === false);

const a3 = await G.authorize(read, alice, T0);
c = await G.consumePermit(a3.permit, read, T0 + 61_000);
ok("an expired permit is rejected (410)", c.ok === false && c.status === 410 && c.reason === "expired");
ok("a permit is still valid just inside its lifetime", (await G.consumePermit((await G.authorize(read, alice, T0)).permit, read, T0 + 59_000)).ok === true);
for (const bad of [undefined, null, 5, "", "short", "x".repeat(300), {}]) {
  c = await G.consumePermit(bad, read, T0);
  if (!(c.ok === false && c.status === 400)) { fail++; console.log("FAIL: malformed permit accepted", String(bad)); } else pass++;
}
c = await G.consumePermit("A".repeat(43), read, T0);
ok("a made-up permit is rejected (403)", c.ok === false && c.status === 403 && c.reason === "unknown");

// ---------------- concurrency: one permit, many simultaneous consumers ----------------
const a4 = await G.authorize(read, alice, T0);
const raced = await Promise.all(Array.from({ length: 25 }, () => G.consumePermit(a4.permit, read, T0 + 500)));
ok("25 simultaneous consumes: exactly ONE succeeds", raced.filter((r) => r.ok).length === 1 && raced.filter((r) => !r.ok && r.status === 409).length === 24, JSON.stringify(raced.map((r) => r.ok)));

// ---------------- DENY / REVIEW issue nothing ----------------
const deny = await G.authorize({ agentId: "agent-procurement-01", tool: "shell.execute" }, alice, T0);
ok("DENY returns no permit and no approval", deny.decision === "DENY" && !deny.permit && !deny.approvalId && deny.status === "blocked");
const review = await G.authorize({ agentId: "ghost", tool: "ticket.read" }, alice, T0);
ok("REVIEW returns no permit and no approval", review.decision === "REVIEW" && !review.permit && !review.approvalId && review.status === "blocked");
ok("a denied action creates no approval request", (await A.readState()).approvals.length === 0);

// ---------------- approval flow ----------------
const p1 = await G.authorize(pay, alice, T0);
ok("REQUIRE_APPROVAL creates a pending approval and no permit", p1.decision === "REQUIRE_APPROVAL" && p1.status === "pending_approval" && !p1.permit && /^APR-/.test(p1.approvalId));
const p1b = await G.authorize(pay, alice, T0 + 1000);
ok("asking again returns the SAME pending approval (no flood)", p1b.approvalId === p1.approvalId && (await A.readState()).approvals.length === 1);
const pOther = await G.authorize({ ...pay, target: "vendor-b" }, alice, T0);
ok("a different action creates its own approval", pOther.approvalId && pOther.approvalId !== p1.approvalId);

let d = await G.decideApproval(p1.approvalId, "approve", "ok", alice, T0 + 2000);
ok("self-approval is refused (four-eyes)", d.ok === false && d.status === 403);
d = await G.decideApproval(p1.approvalId, "maybe", "", bob, T0 + 2000);
ok("a bad decision value is refused", d.ok === false && d.status === 400);
d = await G.decideApproval("APR-NOPE", "approve", "", bob, T0 + 2000);
ok("unknown approval id 404", d.ok === false && d.status === 404);
const stillPending = await G.authorize(pay, alice, T0 + 3000);
ok("before approval, re-submitting still gives no permit", !stillPending.permit && stillPending.status === "pending_approval");

d = await G.decideApproval(p1.approvalId, "approve", "reviewed the invoice", bob, T0 + 4000);
ok("another person can approve", d.ok === true && d.approval.status === "approved" && d.approval.decidedBy.email === bob.email && d.approval.approvedUntil);
ok("approving does not itself create a permit or run anything", (await A.readState()).grants.filter((g) => g.via === "approval").length === 0);
d = await G.decideApproval(p1.approvalId, "reject", "", bob, T0 + 5000);
ok("a decided request cannot be decided again (409)", d.ok === false && d.status === 409);

const byBob = await G.authorize(pay, bob, T0 + 6000);
ok("someone else cannot spend the requester's approval", !byBob.permit && byBob.status === "pending_approval");
const used = await G.authorize(pay, alice, T0 + 6000);
ok("the requester re-submitting the same action now gets a permit", used.status === "authorized_not_executed" && !!used.permit && used.authorizedByApproval === true && used.approvalId === p1.approvalId && used.decision === "REQUIRE_APPROVAL");
c = await G.consumePermit(used.permit, pay, T0 + 7000);
ok("that permit works once, for exactly that action", c.ok === true && c.via === "approval");
ok("and cannot be used for a different payment target", (await G.consumePermit((await (async () => { const x = await G.decideApproval(pOther.approvalId, "approve", "", bob, T0 + 8000); return G.authorize({ ...pay, target: "vendor-b" }, alice, T0 + 8500); })()).permit, pay, T0 + 9000)).reason === "mismatch");
const again = await G.authorize(pay, alice, T0 + 9500);
ok("the approval is used up: the same action asks for approval again", !again.permit && again.status === "pending_approval" && again.approvalId !== p1.approvalId);

// ---------------- approval expiry ----------------
const e1 = await G.authorize({ ...pay, target: "vendor-c" }, alice, T0);
d = await G.decideApproval(e1.approvalId, "approve", "", bob, T0 + 31 * 60_000);
ok("a request that sat for over 30 minutes expires and cannot be approved (410)", d.ok === false && d.status === 410);
const e2 = await G.authorize({ ...pay, target: "vendor-d" }, alice, T0);
await G.decideApproval(e2.approvalId, "approve", "", bob, T0 + 1000);
const late = await G.authorize({ ...pay, target: "vendor-d" }, alice, T0 + 1000 + 11 * 60_000);
ok("an approval not used within 10 minutes lapses", !late.permit && late.status === "pending_approval");
const e3 = await G.authorize({ ...pay, target: "vendor-e" }, alice, T0);
await G.decideApproval(e3.approvalId, "reject", "no", bob, T0 + 1000);
const rej = await G.authorize({ ...pay, target: "vendor-e" }, alice, T0 + 2000);
ok("a rejected approval never yields a permit", !rej.permit);

// ---------------- request flood is capped ----------------
const mallory = { email: "mallory@x.io", name: "Mallory" };
let last;
for (let i = 0; i < 25; i++) last = await G.authorize({ ...pay, target: "t" + i }, mallory, T0 + 40_000);
ok("pending approvals per requester are capped (20)", last.status === "blocked" && (await A.readState()).approvals.filter((x) => x.status === "pending" && x.requestedBy.email === mallory.email).length === 20);

// ---------------- approval cannot override a denial ----------------
const st0 = await A.readState();
st0.policies.push({ id: "POL-STRICT", name: "deny payments", description: "", enabled: true, action: "deny", condition: "sensitive_action", severity: "critical", version: 1, locked: false, createdAt: "", updatedAt: null });
await A.withState((s) => ({ state: { ...s, policies: st0.policies, policyRevision: s.policyRevision + 1 }, result: null }));
const afterDeny = await G.authorize(pay, alice, T0 + 20_000);
ok("when policy tightens to DENY, an earlier approval no longer helps", afterDeny.decision === "DENY" && !afterDeny.permit && !afterDeny.approvalId);

// ---------------- suspended agent: permit cannot be minted ----------------
await A.setAgentStatus("agent-procurement-01", "suspended");
const susp = await G.authorize(read, alice, T0 + 30_000);
ok("a suspended agent gets no permit", susp.decision === "DENY" && !susp.permit);
await A.setAgentStatus("agent-procurement-01", "registered");

// ---------------- limits and hygiene ----------------
const f1 = (await A.readState()).findings.filter((f) => f.agentId === "agent-finance-01" && f.decision === "REQUIRE_APPROVAL");
ok("repeats do not multiply findings (one per agent, tool and decision)", f1.length === 1 && f1[0].count > 5, String(f1.length));
ok("fingerprint ignores case and spacing of the destination only", G.fingerprint({ ...pay, target: " Vendor-B " }) === G.fingerprint({ ...pay, target: "vendor-b" }) && G.fingerprint(pay) !== G.fingerprint({ ...pay, tool: "payment.cancel" }));
const v = await G.authorize(read, alice, T0 + 50_000);
await G.voidGrant(v.grantId, T0 + 50_000);
ok("a withdrawn permit (e.g. audit failed) cannot be used", (await G.consumePermit(v.permit, read, T0 + 50_500)).ok === false);

console.log(`${pass} passed, ${fail} failed`);
process.chdir(tmpdir());
process.exit(fail ? 1 : 0);
