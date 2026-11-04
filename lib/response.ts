/**
 * Governed response: a proposal is written, a different person approves it, and only then can a registered adapter
 * execute it, under policy gates, with an idempotency key, verification and rollback. Port of the Phase II
 * "Governed Response" package.
 *
 * SAFE BY DEFAULT: execution is disabled (RESPONSE_EXECUTION_ENABLED=false), the action allow-list is empty and NO adapter
 * ships with PrimeSEC, so as delivered nothing can act on any system. Proposals and approvals are a governance record.
 * Enabling a real action means writing a narrowly scoped adapter, registering it (registerAdapter) and listing the exact
 * action type in RESPONSE_ALLOWED_ACTIONS. See docs/phase2-response-graph.md.
 */
import { promises as fs } from "fs";
import path from "path";

export const PROPOSAL_STATUSES = ["proposed", "approved", "rejected", "executing", "executed", "execution_failed", "cancelled"] as const;
export type ProposalStatus = (typeof PROPOSAL_STATUSES)[number];
export const EXECUTION_STATUSES = ["executing", "executed", "failed", "verified", "verification_failed", "rolled_back", "rollback_failed"] as const;
export type ExecutionStatus = (typeof EXECUTION_STATUSES)[number];

export type Actor = { email?: string | null; name?: string | null };
export const actorId = (a: Actor) => a.email || a.name || "unknown";

export type Proposal = {
  id: string;
  actionType: string;
  target: string;
  rationale: string;
  /** Optional pointers to what prompted it, for the audit trail. */
  links: { alertId?: string; findingId?: string; assetId?: string; caseId?: string };
  status: ProposalStatus;
  proposedBy: string;
  proposedAt: string;
  reviewedBy: string | null;
  reviewedAt: string | null;
  reviewNote: string;
};
export type Execution = {
  id: string;
  proposalId: string;
  idempotencyKey: string;
  actionType: string;
  target: string;
  status: ExecutionStatus;
  adapter: string;
  result: Record<string, unknown>;
  verification: Record<string, unknown>;
  rollback: Record<string, unknown>;
  requestedBy: string;
  approvedBy: string;
  createdAt: string;
  updatedAt: string;
};
type Store = { proposals: Proposal[]; executions: Execution[] };

export class ResponseError extends Error {
  code: "INVALID" | "NOT_FOUND" | "CONFLICT" | "FORBIDDEN" | "LOCKED" | "UNAVAILABLE" | "UPSTREAM";
  constructor(message: string, code: ResponseError["code"]) {
    super(message);
    this.code = code;
  }
}

/* ------------------------------ configuration ------------------------------ */

export type ResponseConfig = { enabled: boolean; allowedActions: Set<string>; maxTargetLength: number; approvalMaxAgeMinutes: number; dualControl: boolean };

export function responseConfig(env: Record<string, string | undefined> = process.env): ResponseConfig {
  const n = (v: string | undefined, d: number) => { const x = Number(v); return Number.isFinite(x) && x > 0 ? x : d; };
  return {
    enabled: (env.RESPONSE_EXECUTION_ENABLED ?? "").trim().toLowerCase() === "true",
    allowedActions: new Set((env.RESPONSE_ALLOWED_ACTIONS ?? "").split(",").map((x) => x.trim()).filter(Boolean)),
    maxTargetLength: Math.min(n(env.RESPONSE_MAX_TARGET_LENGTH, 300), 1000),
    approvalMaxAgeMinutes: n(env.RESPONSE_APPROVAL_MAX_AGE_MINUTES, 30),
    // Anything but an explicit "false" keeps separation of duties on.
    dualControl: (env.RESPONSE_REQUIRE_DUAL_CONTROL ?? "true").trim().toLowerCase() !== "false"
  };
}

/* ------------------------------ adapters ------------------------------ */

export interface ResponseAdapter {
  name: string;
  supportedActions: readonly string[];
  /** Must be safe to call again with the same idempotencyKey (the provider deduplicates, or the adapter reconciles first). */
  execute(actionType: string, target: string, idempotencyKey: string): Promise<Record<string, unknown>>;
  verify(execution: Pick<Execution, "id" | "actionType" | "target" | "result">): Promise<{ verified: boolean } & Record<string, unknown>>;
  rollback(execution: Pick<Execution, "id" | "actionType" | "target" | "result">): Promise<{ rolledBack: boolean } & Record<string, unknown>>;
}
export class AdapterRegistry {
  adapters: ResponseAdapter[];
  constructor(adapters: ResponseAdapter[] = []) { this.adapters = adapters; }
  forAction(actionType: string): ResponseAdapter {
    const found = this.adapters.find((a) => a.supportedActions.includes(actionType));
    if (!found) throw new ResponseError(`No approved adapter is registered for action "${actionType}".`, "UNAVAILABLE");
    return found;
  }
  byName(name: string): ResponseAdapter | undefined { return this.adapters.find((a) => a.name === name); }
}
/** The process-wide registry. Empty as shipped. */
export const registry = new AdapterRegistry();
export function registerAdapter(adapter: ResponseAdapter): void { registry.adapters.push(adapter); }

/* ------------------------------ storage ------------------------------ */

const storePath = () => path.join(process.cwd(), "data", "response.json");
const EMPTY = (): Store => ({ proposals: [], executions: [] });

export async function readResponse(): Promise<Store> {
  try {
    const v = JSON.parse(await fs.readFile(storePath(), "utf8"));
    return { proposals: Array.isArray(v?.proposals) ? v.proposals : [], executions: Array.isArray(v?.executions) ? v.executions : [] };
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return EMPTY();
    throw error;
  }
}

let chain: Promise<unknown> = Promise.resolve();
function withStore<T>(fn: (s: Store) => { store: Store; result: T }): Promise<T> {
  const run = chain.then(async () => {
    const { store, result } = fn(await readResponse());
    await fs.mkdir(path.dirname(storePath()), { recursive: true });
    const temp = `${storePath()}.${process.pid}.tmp`;
    await fs.writeFile(temp, JSON.stringify(store), { mode: 0o600 });
    await fs.rename(temp, storePath());
    return result;
  });
  chain = run.catch(() => undefined);
  return run;
}

const newId = (p: string) => `${p}_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 7)}`;
const ACTION_RE = /^[a-z][a-z0-9_]{1,40}$/;
const CONTROL_RE = /[\u0000-\u001f\u007f]/;
export const MAX_NOTE = 1000;

/* ------------------------------ proposals ------------------------------ */

export type ProposalInput = { actionType: unknown; target: unknown; rationale: unknown; links?: unknown };

export function validateProposal(input: ProposalInput, cfg = responseConfig()): Pick<Proposal, "actionType" | "target" | "rationale" | "links"> {
  if (typeof input.actionType !== "string" || !ACTION_RE.test(input.actionType)) throw new ResponseError("actionType must be lowercase letters, digits and underscores (for example block_ip).", "INVALID");
  if (typeof input.target !== "string" || !input.target.trim() || CONTROL_RE.test(input.target)) throw new ResponseError("A target is required and must be plain text.", "INVALID");
  if (input.target.trim().length > cfg.maxTargetLength) throw new ResponseError(`The target is longer than ${cfg.maxTargetLength} characters.`, "INVALID");
  if (typeof input.rationale !== "string" || input.rationale.trim().length < 10) throw new ResponseError("Explain why in at least 10 characters: the approver reads this.", "INVALID");
  if (input.rationale.length > MAX_NOTE) throw new ResponseError(`The rationale is longer than ${MAX_NOTE} characters.`, "INVALID");
  const links: Proposal["links"] = {};
  if (input.links !== undefined) {
    if (typeof input.links !== "object" || input.links === null || Array.isArray(input.links)) throw new ResponseError("links must be an object.", "INVALID");
    for (const k of ["alertId", "findingId", "assetId", "caseId"] as const) {
      const v = (input.links as Record<string, unknown>)[k];
      if (v === undefined || v === "") continue;
      if (typeof v !== "string" || v.length > 200 || CONTROL_RE.test(v)) throw new ResponseError(`links.${k} must be short plain text.`, "INVALID");
      links[k] = v;
    }
  }
  return { actionType: input.actionType, target: input.target.trim(), rationale: input.rationale.trim(), links };
}

export async function createProposal(input: ProposalInput, actor: Actor, cfg = responseConfig()): Promise<Proposal> {
  const v = validateProposal(input, cfg);
  return withStore((s) => {
    const p: Proposal = { id: newId("prop"), ...v, status: "proposed", proposedBy: actorId(actor), proposedAt: new Date().toISOString(), reviewedBy: null, reviewedAt: null, reviewNote: "" };
    s.proposals.push(p);
    return { store: s, result: p };
  });
}

/** Approve or reject. With dual control on, the proposer cannot review their own proposal. */
export async function reviewProposal(id: string, decision: unknown, note: unknown, actor: Actor, cfg = responseConfig(), now = Date.now()): Promise<Proposal> {
  if (decision !== "approve" && decision !== "reject") throw new ResponseError('decision must be "approve" or "reject".', "INVALID");
  if (note !== undefined && (typeof note !== "string" || note.length > MAX_NOTE)) throw new ResponseError(`note must be text up to ${MAX_NOTE} characters.`, "INVALID");
  if (decision === "reject" && (typeof note !== "string" || note.trim().length < 5)) throw new ResponseError("Say why you are rejecting it (at least 5 characters).", "INVALID");
  return withStore((s) => {
    const p = s.proposals.find((x) => x.id === id);
    if (!p) throw new ResponseError("Proposal not found.", "NOT_FOUND");
    if (p.status !== "proposed") throw new ResponseError(`This proposal is already ${p.status}.`, "CONFLICT");
    if (cfg.dualControl && p.proposedBy === actorId(actor)) throw new ResponseError("Dual control: you cannot review your own proposal.", "FORBIDDEN");
    p.status = decision === "approve" ? "approved" : "rejected";
    p.reviewedBy = actorId(actor);
    p.reviewedAt = new Date(now).toISOString();
    p.reviewNote = typeof note === "string" ? note.trim() : "";
    return { store: s, result: { ...p } };
  });
}

export async function cancelProposal(id: string, actor: Actor): Promise<Proposal> {
  return withStore((s) => {
    const p = s.proposals.find((x) => x.id === id);
    if (!p) throw new ResponseError("Proposal not found.", "NOT_FOUND");
    if (p.proposedBy !== actorId(actor)) throw new ResponseError("Only the proposer can cancel a proposal.", "FORBIDDEN");
    if (p.status !== "proposed" && p.status !== "approved") throw new ResponseError(`A ${p.status} proposal cannot be cancelled.`, "CONFLICT");
    p.status = "cancelled";
    return { store: s, result: { ...p } };
  });
}

/* ------------------------------ execution ------------------------------ */

/** Policy gates, checked in this order. Throws a ResponseError naming the first gate that fails. */
export function checkPolicy(p: Proposal, actor: Actor, cfg: ResponseConfig, now: number): void {
  if (!cfg.enabled) throw new ResponseError("Active response execution is disabled by platform policy.", "LOCKED");
  if (!cfg.allowedActions.has(p.actionType)) throw new ResponseError(`Action type "${p.actionType}" is not on the allow-list.`, "FORBIDDEN");
  if (!p.target.trim() || p.target.length > cfg.maxTargetLength) throw new ResponseError("Invalid response target.", "INVALID");
  if (p.status !== "approved") throw new ResponseError(`The proposal must be approved before execution (it is ${p.status}).`, "CONFLICT");
  if (!p.reviewedAt) throw new ResponseError("The approval timestamp is missing.", "CONFLICT");
  if (now - Date.parse(p.reviewedAt) > cfg.approvalMaxAgeMinutes * 60_000) throw new ResponseError("The approval has expired. Request a fresh review.", "CONFLICT");
  if (cfg.dualControl && p.proposedBy === actorId(actor)) throw new ResponseError("Dual control: the proposer cannot execute their own proposal.", "FORBIDDEN");
}

export type Phase = "requested" | "executed" | "failed" | "verified" | "verification_failed" | "rolled_back" | "rollback_failed";
export type Hooks = { onPhase?: (phase: Phase, e: Execution) => Promise<void> };
export type ExecuteResult = { execution: Execution; replay: boolean };

const KEY_RE = /^[A-Za-z0-9._:-]{8,128}$/;
const safeError = (e: unknown) => ({ error: e instanceof Error ? e.name : "Error", message: (e instanceof Error ? e.message : "").replace(/https?:\/\/\S+/g, "[url]").slice(0, 300) });

/**
 * Executes an approved proposal. Order matters:
 *  1. an already-used Idempotency-Key for this proposal returns the stored execution (a retry, not a second action);
 *  2. policy gates;
 *  3. the execution record is reserved and the proposal moved to "executing" in ONE atomic write, so two concurrent
 *     requests cannot both run, and a crash leaves an inspectable "executing" record instead of inviting a duplicate;
 *  4. the audit "requested" hook runs, and if it fails nothing is executed (fail closed);
 *  5. the adapter is called. A failure marks the proposal execution_failed: it is NOT retried automatically, because
 *     the action may have partly happened; a person must inspect it and propose again.
 */
export async function executeProposal(proposalId: string, idempotencyKey: unknown, actor: Actor, reg: AdapterRegistry = registry, cfg = responseConfig(), hooks: Hooks = {}, now = Date.now()): Promise<ExecuteResult> {
  if (typeof idempotencyKey !== "string" || !KEY_RE.test(idempotencyKey)) throw new ResponseError("An Idempotency-Key of 8 to 128 letters, digits or . _ : - is required.", "INVALID");
  const reserved = await withStore((s) => {
    const prior = s.executions.find((e) => e.idempotencyKey === idempotencyKey);
    if (prior) {
      if (prior.proposalId !== proposalId) throw new ResponseError("This Idempotency-Key was already used for a different proposal.", "CONFLICT");
      return { store: s, result: { replay: prior } as { replay?: Execution; exec?: Execution; proposal?: Proposal } };
    }
    const p = s.proposals.find((x) => x.id === proposalId);
    if (!p) throw new ResponseError("Proposal not found.", "NOT_FOUND");
    checkPolicy(p, actor, cfg, now);
    const adapter = reg.forAction(p.actionType);
    const at = new Date(now).toISOString();
    const exec: Execution = { id: newId("exec"), proposalId: p.id, idempotencyKey, actionType: p.actionType, target: p.target, status: "executing", adapter: adapter.name, result: {}, verification: {}, rollback: {}, requestedBy: actorId(actor), approvedBy: p.reviewedBy ?? "", createdAt: at, updatedAt: at };
    s.executions.push(exec);
    p.status = "executing";
    return { store: s, result: { exec: { ...exec }, proposal: { ...p } } };
  });
  if (reserved.replay) return { execution: reserved.replay, replay: true };
  const exec = reserved.exec!;
  const adapter = reg.byName(exec.adapter)!;

  const finish = (patch: Partial<Execution>, proposalStatus: ProposalStatus) => withStore((s) => {
    const e = s.executions.find((x) => x.id === exec.id)!;
    Object.assign(e, patch, { updatedAt: new Date().toISOString() });
    const p = s.proposals.find((x) => x.id === proposalId);
    if (p) p.status = proposalStatus;
    return { store: s, result: { ...e } };
  });

  try {
    await hooks.onPhase?.("requested", exec);
  } catch {
    await finish({ status: "failed", result: { error: "AuditUnavailable", message: "The audit record could not be written, so nothing was executed." } }, "execution_failed");
    throw new ResponseError("The audit trail is unavailable, so the action was not executed. Inspect the execution record and propose again.", "UNAVAILABLE");
  }
  try {
    const result = await adapter.execute(exec.actionType, exec.target, exec.idempotencyKey);
    const done = await finish({ status: "executed", result }, "executed");
    await hooks.onPhase?.("executed", done).catch(() => undefined);
    return { execution: done, replay: false };
  } catch (error) {
    const failed = await finish({ status: "failed", result: safeError(error) }, "execution_failed");
    await hooks.onPhase?.("failed", failed).catch(() => undefined);
    return { execution: failed, replay: false };
  }
}

async function loadExecution(id: string): Promise<Execution> {
  const e = (await readResponse()).executions.find((x) => x.id === id);
  if (!e) throw new ResponseError("Execution not found.", "NOT_FOUND");
  return e;
}
async function updateExecution(id: string, patch: Partial<Execution>): Promise<Execution> {
  return withStore((s) => {
    const e = s.executions.find((x) => x.id === id)!;
    Object.assign(e, patch, { updatedAt: new Date().toISOString() });
    return { store: s, result: { ...e } };
  });
}

export async function verifyExecution(id: string, reg: AdapterRegistry = registry, hooks: Hooks = {}): Promise<Execution> {
  const e = await loadExecution(id);
  if (e.status !== "executed" && e.status !== "verification_failed") throw new ResponseError(`A ${e.status} execution cannot be verified.`, "CONFLICT");
  const adapter = reg.byName(e.adapter);
  if (!adapter) throw new ResponseError("The adapter that ran this action is not registered.", "UNAVAILABLE");
  let out: Record<string, unknown>;
  let verified = false;
  try {
    const r = await adapter.verify(e);
    verified = r.verified === true;
    out = r;
  } catch (error) { out = safeError(error); }
  const done = await updateExecution(id, { status: verified ? "verified" : "verification_failed", verification: out });
  await hooks.onPhase?.(verified ? "verified" : "verification_failed", done).catch(() => undefined);
  return done;
}

export async function rollbackExecution(id: string, reg: AdapterRegistry = registry, hooks: Hooks = {}): Promise<Execution> {
  const e = await loadExecution(id);
  if (!["executed", "verified", "verification_failed"].includes(e.status)) throw new ResponseError("Only an executed action can be rolled back.", "CONFLICT");
  const adapter = reg.byName(e.adapter);
  if (!adapter) throw new ResponseError("The adapter that ran this action is not registered.", "UNAVAILABLE");
  let out: Record<string, unknown>;
  let rolledBack = false;
  try {
    const r = await adapter.rollback(e);
    rolledBack = r.rolledBack === true;
    out = r;
  } catch (error) { out = safeError(error); }
  const done = await updateExecution(id, { status: rolledBack ? "rolled_back" : "rollback_failed", rollback: out });
  await hooks.onPhase?.(rolledBack ? "rolled_back" : "rollback_failed", done).catch(() => undefined);
  return done;
}

/* ------------------------------ reads ------------------------------ */

export async function listProposals(limit = 100): Promise<Proposal[]> {
  return (await readResponse()).proposals.slice().reverse().slice(0, Math.min(Math.max(Math.floor(limit) || 100, 1), 500));
}
export async function listExecutions(limit = 100): Promise<Execution[]> {
  return (await readResponse()).executions.slice().reverse().slice(0, Math.min(Math.max(Math.floor(limit) || 100, 1), 500));
}
export function responseStatus(reg: AdapterRegistry = registry, cfg = responseConfig()) {
  return { executionEnabled: cfg.enabled, allowedActions: [...cfg.allowedActions], adapters: reg.adapters.map((a) => ({ name: a.name, actions: [...a.supportedActions] })), dualControl: cfg.dualControl, approvalMaxAgeMinutes: cfg.approvalMaxAgeMinutes };
}
