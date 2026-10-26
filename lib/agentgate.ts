/**
 * Action gateway (Day 13): turns a policy decision into something an agent adapter can act on, without ever executing
 * anything itself.
 *
 *   ALLOW            -> a one-time permit (60 s), bound to this exact action.
 *   REQUIRE_APPROVAL -> a pending approval for a human. Once approved, the SAME requester can re-submit the SAME action
 *                       once, and then gets a permit. An approval never overrides a DENY or REVIEW.
 *   DENY / REVIEW    -> nothing is issued.
 *
 * Everything that changes state runs inside one serialised read-modify-write, so two simultaneous requests cannot both
 * consume one permit or both use one approval. Only a SHA-256 hash of a permit is stored.
 * A permit proves that the policy allowed an action at a moment in time. It protects nothing unless the adapter that
 * performs the action consumes it first, with the exact same action details, and refuses to act otherwise.
 */
import { createHash, randomBytes } from "crypto";
import { evaluateAction, recordFinding, withState, type Approval, type Decision, type Evaluation, type Grant } from "./agentsec.ts";

export const PERMIT_TTL_MS = 60_000;
export const APPROVAL_REQUEST_TTL_MS = 30 * 60_000;
export const APPROVAL_USE_WINDOW_MS = 10 * 60_000;
const MAX_PENDING_PER_USER = 20;

export type Actor = { email?: string | null; name?: string | null };
export type GatewayInput = { agentId: string; tool: string; dataClass?: string; target?: string; external?: boolean; sensitive?: boolean };
const who = (a: Actor) => a.email || a.name || "unknown";
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const clip = (v: unknown, n: number) => (typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, n) : "");

export function normalizeAction(i: GatewayInput): Required<GatewayInput> {
  return { agentId: clip(i.agentId, 120), tool: clip(i.tool, 160), dataClass: clip(i.dataClass, 80) || "unknown", target: clip(i.target, 160), external: i.external === true, sensitive: i.sensitive === true };
}
/** Identifies one exact action. A permit or approval only ever applies to the action with this fingerprint. */
export function fingerprint(i: GatewayInput): string {
  const n = normalizeAction(i);
  return sha(JSON.stringify([n.agentId, n.tool, n.target.toLowerCase(), n.dataClass.toLowerCase(), n.external, n.sensitive]));
}

export type GatewayResult = {
  requestId: string; decision: Decision; status: "authorized_not_executed" | "pending_approval" | "blocked";
  permit?: string; permitExpiresInSeconds?: number; grantId?: string; approvalId?: string; approvalExpiresAt?: string;
  authorizedByApproval: boolean; reasons: Evaluation["reasons"]; policyRevision: number; agent: Evaluation["agent"]; tool: string; message: string;
};

/** Decides one proposed action and records what the decision allows. Executes nothing. */
export async function authorize(input: GatewayInput, actor: Actor, now = Date.now()): Promise<GatewayResult> {
  const action = normalizeAction(input);
  const fp = fingerprint(action);
  const nowIso = new Date(now).toISOString();
  return withState((state) => {
    const e = evaluateAction(state, action, nowIso);
    const requestId = `gw_${now.toString(36)}_${randomBytes(4).toString("hex")}`;
    const base = { requestId, decision: e.decision, reasons: e.reasons, policyRevision: e.policyRevision, agent: e.agent, tool: e.tool, authorizedByApproval: false };

    // Housekeeping inside the same write: expire stale approvals, drop dead permits.
    for (const a of state.approvals) {
      if (a.status === "pending" && Date.parse(a.expiresAt) <= now) a.status = "expired";
      if (a.status === "approved" && a.approvedUntil && Date.parse(a.approvedUntil) <= now) a.status = "expired";
    }
    state.grants = state.grants.filter((g) => !(Date.parse(g.expiresAt) < now - 3_600_000)).slice(0, 2000);
    state.approvals = state.approvals.slice(0, 500);
    recordFinding(state, e, null, nowIso);

    const issue = (via: Grant["via"], approvalId: string | null) => {
      const permit = randomBytes(32).toString("base64url");
      const grant: Grant = { id: requestId, grantHash: sha(permit), fingerprint: fp, agentId: action.agentId, tool: action.tool, via, approvalId, requestedBy: who(actor), issuedAt: nowIso, expiresAt: new Date(now + PERMIT_TTL_MS).toISOString(), consumedAt: null };
      state.grants.unshift(grant);
      return { permit, grant };
    };

    if (e.decision === "ALLOW") {
      const { permit } = issue("policy", null);
      const r: GatewayResult = { ...base, status: "authorized_not_executed", permit, permitExpiresInSeconds: PERMIT_TTL_MS / 1000, grantId: requestId, message: "Policy allowed this action. Nothing was executed: the adapter must consume this permit, with the same action details, before it acts." };
      return { state, result: r };
    }

    if (e.decision === "REQUIRE_APPROVAL") {
      // Same requester, same exact action, approved and still inside the use window: spend the approval, issue a permit.
      const approved = state.approvals.find((a) => a.status === "approved" && a.fingerprint === fp && a.requestedBy.email === (actor.email ?? null) && a.requestedBy.name === (actor.name ?? null) && a.approvedUntil && Date.parse(a.approvedUntil) > now);
      if (approved) {
        approved.status = "used"; approved.usedAt = nowIso;
        const { permit } = issue("approval", approved.id);
        return { state, result: { ...base, status: "authorized_not_executed", permit, permitExpiresInSeconds: PERMIT_TTL_MS / 1000, grantId: requestId, approvalId: approved.id, authorizedByApproval: true, message: "A human approved this exact action. The approval is now used up. Nothing was executed: the adapter must consume this permit first." } as GatewayResult };
      }
      const open = state.approvals.find((a) => a.status === "pending" && a.fingerprint === fp && a.requestedBy.email === (actor.email ?? null) && a.requestedBy.name === (actor.name ?? null));
      if (open) return { state, result: { ...base, status: "pending_approval", approvalId: open.id, approvalExpiresAt: open.expiresAt, message: "Still waiting for a human decision on this exact action. Nothing was executed." } as GatewayResult };
      if (state.approvals.filter((a) => a.status === "pending" && a.requestedBy.email === (actor.email ?? null) && a.requestedBy.name === (actor.name ?? null)).length >= MAX_PENDING_PER_USER) {
        return { state, result: { ...base, status: "blocked", message: `Too many approval requests are waiting from you (${MAX_PENDING_PER_USER}). Wait for decisions before asking for more.` } as GatewayResult };
      }
      const approval: Approval = {
        id: `APR-${randomBytes(4).toString("hex").toUpperCase()}`, requestId, fingerprint: fp, agentId: action.agentId, agentName: e.agent?.name ?? "Unregistered agent",
        tool: action.tool, target: action.target, dataClass: action.dataClass, status: "pending", requestedBy: { email: actor.email ?? null, name: actor.name ?? null },
        createdAt: nowIso, expiresAt: new Date(now + APPROVAL_REQUEST_TTL_MS).toISOString(), decidedBy: null, decidedAt: null, decisionNote: "", approvedUntil: null, usedAt: null,
        reasons: e.reasons.map((r) => r.reason).slice(0, 5)
      };
      state.approvals.unshift(approval);
      return { state, result: { ...base, status: "pending_approval", approvalId: approval.id, approvalExpiresAt: approval.expiresAt, message: "A human must approve this exact action. Nothing was executed. After approval, submit the same action again to receive a one-time permit." } as GatewayResult };
    }

    return { state, result: { ...base, status: "blocked", message: e.decision === "DENY" ? "Denied by policy. Nothing was executed, and no approval can change that." : "Held for security review. Nothing was executed." } as GatewayResult };
  });
}

/** Cancels a permit that was issued but could not be audited (fail closed). */
export async function voidGrant(grantId: string, now = Date.now()): Promise<void> {
  await withState((state) => {
    const g = state.grants.find((x) => x.id === grantId);
    if (g && !g.consumedAt) g.consumedAt = new Date(now).toISOString();
    return { state, result: undefined };
  });
}

export type ConsumeOutcome =
  | { ok: true; grantId: string; agentId: string; tool: string; via: Grant["via"]; consumedAt: string }
  | { ok: false; status: 400 | 403 | 409 | 410; error: string; reason: "malformed" | "unknown" | "mismatch" | "replay" | "expired" };

/**
 * Validates and spends a permit. The caller must present the SAME action details the permit was issued for; a permit
 * cannot be used for a different tool, target or data class. A mismatch does not spend the permit.
 */
export async function consumePermit(permit: unknown, input: GatewayInput, now = Date.now()): Promise<ConsumeOutcome> {
  if (typeof permit !== "string" || permit.length < 30 || permit.length > 200) return { ok: false, status: 400, error: "Invalid permit.", reason: "malformed" };
  const hash = sha(permit);
  const fp = fingerprint(input);
  return withState((state) => {
    const g = state.grants.find((x) => x.grantHash === hash);
    if (!g) return { state, result: { ok: false, status: 403, error: "Permit is not valid.", reason: "unknown" } as ConsumeOutcome };
    if (g.consumedAt) return { state, result: { ok: false, status: 409, error: "Permit has already been used.", reason: "replay" } as ConsumeOutcome };
    if (Date.parse(g.expiresAt) <= now) return { state, result: { ok: false, status: 410, error: "Permit expired. Evaluate the action again.", reason: "expired" } as ConsumeOutcome };
    if (g.fingerprint !== fp) return { state, result: { ok: false, status: 403, error: "This permit was issued for a different action (agent, tool, destination or data class).", reason: "mismatch" } as ConsumeOutcome };
    g.consumedAt = new Date(now).toISOString();
    return { state, result: { ok: true, grantId: g.id, agentId: g.agentId, tool: g.tool, via: g.via, consumedAt: g.consumedAt } as ConsumeOutcome };
  });
}

export type DecisionOutcome =
  | { ok: true; approval: Approval }
  | { ok: false; status: 400 | 403 | 404 | 409 | 410; error: string };

/** Records a human approve or reject. The approver must not be the person who asked (four-eyes). Execution is never triggered. */
export async function decideApproval(id: string, decision: unknown, note: unknown, actor: Actor, now = Date.now()): Promise<DecisionOutcome> {
  if (decision !== "approve" && decision !== "reject") return { ok: false, status: 400, error: 'decision must be "approve" or "reject".' };
  const nowIso = new Date(now).toISOString();
  const text = clip(note, 500);
  return withState((state) => {
    const a = state.approvals.find((x) => x.id === id);
    if (!a) return { state, result: { ok: false, status: 404, error: "Approval request not found." } as DecisionOutcome };
    if (a.status === "pending" && Date.parse(a.expiresAt) <= now) {
      a.status = "expired";
      return { state, result: { ok: false, status: 410, error: "This approval request has expired." } as DecisionOutcome };
    }
    if (a.status !== "pending") return { state, result: { ok: false, status: 409, error: `This request is already ${a.status}.` } as DecisionOutcome };
    const same = (a.requestedBy.email && a.requestedBy.email === (actor.email ?? null)) || (!a.requestedBy.email && a.requestedBy.name === (actor.name ?? null));
    if (same) return { state, result: { ok: false, status: 403, error: "You cannot decide a request you made yourself. Another person must approve or reject it." } as DecisionOutcome };
    a.status = decision === "approve" ? "approved" : "rejected";
    a.decidedBy = { email: actor.email ?? null, name: actor.name ?? null };
    a.decidedAt = nowIso; a.decisionNote = text;
    a.approvedUntil = decision === "approve" ? new Date(now + APPROVAL_USE_WINDOW_MS).toISOString() : null;
    return { state, result: { ok: true, approval: { ...a } } as DecisionOutcome };
  });
}
