/**
 * Investigation cases: a persistent record of one investigation with an owner, a status lifecycle, evidence and a full event
 * timeline. Port of the Phase II "investigation / agentic SOC" package (primesoc_cases), single-organisation.
 *
 * A case RECORDS work and plans next steps; it never changes a system. Response proposals made from a case live in the governed
 * response store (lib/response.ts) and carry the case id, so approval, dual control and execution policy apply to them unchanged.
 * The investigation plan is rule-based decision support, not an AI verdict.
 */
import { promises as fs } from "fs";
import path from "path";

export const CASE_STATUSES = ["new", "triaged", "investigating", "contained", "resolved", "closed"] as const;
export type CaseStatus = (typeof CASE_STATUSES)[number];
export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];
/** Allowed next statuses. "closed" is final. */
export const TRANSITIONS: Record<CaseStatus, CaseStatus[]> = {
  new: ["triaged", "investigating", "closed"],
  triaged: ["investigating", "contained", "resolved", "closed"],
  investigating: ["contained", "resolved", "closed"],
  contained: ["investigating", "resolved", "closed"],
  resolved: ["investigating", "closed"],
  closed: []
};
/** Actions a case may propose to the governed response workflow. */
export const CASE_ACTIONS = ["isolate_endpoint", "block_ip", "disable_user", "quarantine_file", "run_scan"] as const;

export const MAX_CASES = 2000;
export const MAX_EVIDENCE = 100;
export const MAX_EVENTS = 1000;
export const MAX_EVIDENCE_JSON = 20_000;
export const MIN_CLOSE_NOTE = 10;

export type Actor = { email?: string | null; name?: string | null };
const who = (a: Actor) => a.email || a.name || "unknown";

export type CaseSnapshot = {
  capturedAt: string;
  alert?: { id: string; level: number; description: string; agent: string; timestamp: string | null; sourceIp: string };
  searched?: number;
  openCtiConnected?: boolean;
  matches?: { indicatorName: string; matchedValue: string; observableType: string; score: number | null }[];
  /** CVE ids found in the alert and what OpenCTI knows about each. */
  vulnerabilities?: { cve: string; known: boolean | null; cvss: number | null; knownExploited: boolean | null }[];
  /** MITRE ATT&CK technique ids from the alert, for context. */
  techniques?: string[];
};
export type Evidence = { id: string; type: string; source: string; title: string; content: Record<string, unknown>; createdBy: string; createdAt: string };
export type CaseEvent = { id: string; type: string; actor: string; at: string; details: Record<string, unknown> };
export type Case = {
  id: string;
  caseKey: string;
  title: string;
  description: string;
  severity: Severity;
  status: CaseStatus;
  /** 0-100 heuristic for ordering work; see priorityFrom. */
  priorityScore: number;
  owner: string | null;
  sourceAlertIds: string[];
  links: { findingId?: string; assetId?: string };
  snapshot: CaseSnapshot | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  evidence: Evidence[];
  events: CaseEvent[];
};
type Store = { cases: Case[] };

export class CaseError extends Error {
  code: "INVALID" | "NOT_FOUND" | "CONFLICT" | "LIMIT";
  constructor(message: string, code: CaseError["code"]) {
    super(message);
    this.code = code;
  }
}

/* ------------------------------ storage ------------------------------ */

const storePath = () => path.join(process.cwd(), "data", "cases.json");
export async function readCases(): Promise<Case[]> {
  try {
    const v = JSON.parse(await fs.readFile(storePath(), "utf8"));
    return Array.isArray(v?.cases) ? v.cases : [];
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return [];
    throw error;
  }
}
let chain: Promise<unknown> = Promise.resolve();
function withStore<T>(fn: (cases: Case[]) => T): Promise<T> {
  const run = chain.then(async () => {
    const cases = await readCases();
    const result = fn(cases);
    await fs.mkdir(path.dirname(storePath()), { recursive: true });
    const temp = `${storePath()}.${process.pid}.tmp`;
    await fs.writeFile(temp, JSON.stringify({ cases } satisfies Store), { mode: 0o600 });
    await fs.rename(temp, storePath());
    return result;
  });
  chain = run.catch(() => undefined);
  return run;
}

let counter = 0;
const rid = (p: string) => `${p}_${Date.now().toString(36)}${(counter++).toString(36)}${Math.random().toString(36).slice(2, 6)}`;
const caseKey = () => "PSC-" + Math.random().toString(36).slice(2, 7).toUpperCase() + Date.now().toString(36).slice(-5).toUpperCase();
const now = () => new Date().toISOString();

function event(c: Case, type: string, actor: string, details: Record<string, unknown> = {}): CaseEvent {
  const e: CaseEvent = { id: rid("evt"), type, actor, at: now(), details };
  c.events.push(e);
  if (c.events.length > MAX_EVENTS) c.events = c.events.slice(-MAX_EVENTS);
  c.updatedAt = e.at;
  return e;
}

/* ------------------------------ validation ------------------------------ */

const CONTROL = /[\u0000-\u001f\u007f]/;
const text = (v: unknown, label: string, min: number, max: number, multiline = false): string => {
  if (typeof v !== "string") throw new CaseError(`${label} must be text.`, "INVALID");
  const t = v.trim();
  if (t.length < min) throw new CaseError(`${label} must be at least ${min} characters.`, "INVALID");
  if (t.length > max) throw new CaseError(`${label} must be at most ${max} characters.`, "INVALID");
  if ((multiline ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/ : CONTROL).test(t)) throw new CaseError(`${label} contains control characters.`, "INVALID");
  return t;
};

/** 0-100: alert level x5 (Wazuh levels run to 15) plus 10 per distinct threat-intelligence match, up to three. A heuristic, not a probability. */
export function priorityFrom(level: number, matchCount: number): number {
  return Math.max(0, Math.min(100, Math.round(level * 5 + Math.min(matchCount, 3) * 10)));
}
export function severityFrom(score: number): Severity {
  return score >= 80 ? "critical" : score >= 60 ? "high" : score >= 35 ? "medium" : "low";
}

export type CaseInput = { title?: unknown; description?: unknown; severity?: unknown; priorityScore?: unknown; links?: unknown };

export function validateCaseInput(i: CaseInput) {
  const title = text(i.title, "title", 3, 300);
  const description = i.description === undefined || i.description === "" ? "" : text(i.description, "description", 0, 4000, true);
  const severity = i.severity === undefined ? "medium" : i.severity;
  if (!SEVERITIES.includes(severity as Severity)) throw new CaseError(`severity must be one of ${SEVERITIES.join(", ")}.`, "INVALID");
  let priority = 0;
  if (i.priorityScore !== undefined) {
    if (typeof i.priorityScore !== "number" || !Number.isInteger(i.priorityScore) || i.priorityScore < 0 || i.priorityScore > 100) throw new CaseError("priorityScore must be a whole number from 0 to 100.", "INVALID");
    priority = i.priorityScore;
  }
  const links: Case["links"] = {};
  if (i.links !== undefined) {
    if (typeof i.links !== "object" || i.links === null || Array.isArray(i.links)) throw new CaseError("links must be an object.", "INVALID");
    for (const k of ["findingId", "assetId"] as const) {
      const v = (i.links as Record<string, unknown>)[k];
      if (v !== undefined && v !== "") links[k] = text(v, `links.${k}`, 1, 200);
    }
  }
  return { title, description, severity: severity as Severity, priorityScore: priority, links };
}

/* ------------------------------ create ------------------------------ */

function guardLimit(cases: Case[]) {
  if (cases.length >= MAX_CASES) throw new CaseError(`The case store is full (${MAX_CASES}). Close and archive old cases first.`, "LIMIT");
}

export async function createCase(input: CaseInput, actor: Actor): Promise<Case> {
  const v = validateCaseInput(input);
  return withStore((cases) => {
    guardLimit(cases);
    const t = now();
    const c: Case = { id: rid("case"), caseKey: caseKey(), ...v, status: "new", owner: null, sourceAlertIds: [], snapshot: null, createdBy: who(actor), createdAt: t, updatedAt: t, closedAt: null, evidence: [], events: [] };
    event(c, "case_created", who(actor), { title: c.title });
    cases.push(c);
    return c;
  });
}

export type AlertInvestigation = {
  alert: NonNullable<CaseSnapshot["alert"]>;
  searched: number;
  openCtiConnected: boolean;
  matches: NonNullable<CaseSnapshot["matches"]>;
  vulnerabilities?: NonNullable<CaseSnapshot["vulnerabilities"]>;
  techniques?: string[];
};

/**
 * Opens a case from a re-read alert investigation. If an OPEN case already exists for the same alert, it is refreshed with the new
 * snapshot instead of creating a duplicate (priority can rise, never fall, while it is open).
 */
export async function openCaseFromAlert(inv: AlertInvestigation, actor: Actor): Promise<{ case: Case; created: boolean }> {
  // Distinct indicator matches count once each; a CVE that CISA lists as exploited in the wild counts like a match.
  const exploited = (inv.vulnerabilities ?? []).filter((v) => v.knownExploited === true).length;
  const priority = priorityFrom(inv.alert.level, new Set(inv.matches.map((m) => m.matchedValue)).size + exploited);
  const snapshot: CaseSnapshot = { capturedAt: now(), alert: inv.alert, searched: inv.searched, openCtiConnected: inv.openCtiConnected, matches: inv.matches.slice(0, 50), vulnerabilities: (inv.vulnerabilities ?? []).slice(0, 10), techniques: (inv.techniques ?? []).slice(0, 25) };
  return withStore((cases) => {
    const existing = cases.find((c) => c.sourceAlertIds.includes(inv.alert.id) && c.status !== "resolved" && c.status !== "closed");
    if (existing) {
      existing.snapshot = snapshot;
      existing.priorityScore = Math.max(existing.priorityScore, priority);
      event(existing, "correlation_refreshed", who(actor), { alertId: inv.alert.id, matches: inv.matches.length });
      return { case: existing, created: false };
    }
    guardLimit(cases);
    const t = now();
    const c: Case = {
      id: rid("case"), caseKey: caseKey(), title: `Wazuh alert: ${inv.alert.description}`.slice(0, 300),
      description: inv.matches.length ? `${inv.matches.length} potential threat-intelligence match(es): analyst validation required.` : "Cross-source alert correlation found no threat-intelligence match. That does not mean the alert is benign.",
      severity: severityFrom(priority), status: "new", priorityScore: priority, owner: null, sourceAlertIds: [inv.alert.id], links: {}, snapshot,
      createdBy: who(actor), createdAt: t, updatedAt: t, closedAt: null, evidence: [], events: []
    };
    event(c, "case_created_from_alert", who(actor), { alertId: inv.alert.id });
    cases.push(c);
    return { case: c, created: true };
  });
}

/* ------------------------------ read ------------------------------ */

export type CaseSummary = Omit<Case, "evidence" | "events"> & { evidenceCount: number; eventCount: number };
const summarize = ({ evidence, events, ...rest }: Case): CaseSummary => ({ ...rest, evidenceCount: evidence.length, eventCount: events.length });

export async function listCases(q: { status?: string; owner?: string; severity?: string; search?: string; limit?: number; offset?: number } = {}) {
  const limit = Math.min(Math.max(Math.floor(q.limit ?? 100) || 100, 1), 500);
  const offset = Math.max(Math.floor(q.offset ?? 0) || 0, 0);
  const term = (q.search ?? "").trim().toLowerCase().slice(0, 100);
  let rows = await readCases();
  if (q.status) rows = rows.filter((c) => c.status === q.status);
  if (q.severity) rows = rows.filter((c) => c.severity === q.severity);
  if (q.owner) rows = rows.filter((c) => c.owner === q.owner);
  if (term) rows = rows.filter((c) => [c.title, c.caseKey, c.description].some((f) => f.toLowerCase().includes(term)));
  rows.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  const open = (await readCases()).filter((c) => c.status !== "closed" && c.status !== "resolved");
  return { items: rows.slice(offset, offset + limit).map(summarize), total: rows.length, limit, offset, openCount: open.length, openBySeverity: Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((c) => c.severity === s).length])) };
}

export async function getCase(id: string): Promise<Case> {
  const c = (await readCases()).find((x) => x.id === id);
  if (!c) throw new CaseError("Case not found.", "NOT_FOUND");
  return c;
}

/* ------------------------------ change ------------------------------ */

function mutate<T>(id: string, fn: (c: Case) => T): Promise<T> {
  return withStore((cases) => {
    const c = cases.find((x) => x.id === id);
    if (!c) throw new CaseError("Case not found.", "NOT_FOUND");
    return fn(c);
  });
}

export async function assignCase(id: string, owner: unknown, actor: Actor): Promise<Case> {
  const next = owner === null || owner === "" ? null : text(owner, "owner", 1, 256);
  return mutate(id, (c) => {
    if (c.status === "closed") throw new CaseError("A closed case cannot be reassigned.", "CONFLICT");
    const from = c.owner;
    c.owner = next;
    event(c, "case_assigned", who(actor), { from, to: next });
    return c;
  });
}

/** Validates against the CURRENT status inside the write, so two people changing a case at once cannot both succeed from the same state. */
export async function transitionCase(id: string, status: unknown, note: unknown, actor: Actor): Promise<Case> {
  if (typeof status !== "string" || !CASE_STATUSES.includes(status as CaseStatus)) throw new CaseError(`status must be one of ${CASE_STATUSES.join(", ")}.`, "INVALID");
  const to = status as CaseStatus;
  const n = note === undefined || note === "" ? "" : text(note, "note", 0, 2000, true);
  if ((to === "resolved" || to === "closed") && n.length < MIN_CLOSE_NOTE) throw new CaseError(`Say what was found or decided (at least ${MIN_CLOSE_NOTE} characters) before resolving or closing a case.`, "INVALID");
  return mutate(id, (c) => {
    if (!TRANSITIONS[c.status].includes(to)) throw new CaseError(`A ${c.status} case cannot move to ${to}.`, "CONFLICT");
    const from = c.status;
    c.status = to;
    c.closedAt = to === "resolved" || to === "closed" ? now() : null;
    event(c, "status_changed", who(actor), { from, to, note: n });
    return c;
  });
}

export async function addEvidence(id: string, input: { type?: unknown; source?: unknown; title?: unknown; content?: unknown }, actor: Actor): Promise<Case> {
  const type = text(input.type, "type", 1, 80);
  const source = input.source === undefined ? "analyst" : text(input.source, "source", 1, 80);
  const title = text(input.title, "title", 1, 300);
  let content: Record<string, unknown> = {};
  if (input.content !== undefined) {
    if (typeof input.content !== "object" || input.content === null || Array.isArray(input.content)) throw new CaseError("content must be an object.", "INVALID");
    if (JSON.stringify(input.content).length > MAX_EVIDENCE_JSON) throw new CaseError(`content is larger than ${MAX_EVIDENCE_JSON} characters.`, "INVALID");
    content = input.content as Record<string, unknown>;
  }
  return mutate(id, (c) => {
    if (c.status === "closed") throw new CaseError("A closed case cannot take new evidence. Reopen is not allowed; open a new case.", "CONFLICT");
    if (c.evidence.length >= MAX_EVIDENCE) throw new CaseError(`A case holds at most ${MAX_EVIDENCE} evidence items.`, "LIMIT");
    c.evidence.push({ id: rid("ev"), type, source, title, content, createdBy: who(actor), createdAt: now() });
    event(c, "evidence_added", who(actor), { type, title });
    return c;
  });
}

/** Records a timeline entry (used by the API for things that happen elsewhere, such as a response proposal). */
export function noteEvent(id: string, type: string, actor: Actor, details: Record<string, unknown>): Promise<Case> {
  return mutate(id, (c) => { event(c, type, who(actor), details); return c; });
}

/** Moves a brand-new case to triaged when its plan is first generated. */
export function markPlanned(id: string, steps: number, actor: Actor): Promise<Case> {
  return mutate(id, (c) => {
    if (c.status === "new") { c.status = "triaged"; event(c, "triage_started", who(actor), {}); }
    event(c, "investigation_plan_generated", who(actor), { steps });
    return c;
  });
}

/* ------------------------------ plan ------------------------------ */

export type PlanStep = { step: string; detail: string; source: string };
export type Plan = { caseKey: string; assessment: string; steps: PlanStep[]; suggestedProposals: { actionType: string; target: string; rationale: string }[]; execution: string };

/** Rule-based next steps from what the case actually holds. It never executes anything and does not decide whether there was a compromise. */
export function buildPlan(c: Pick<Case, "caseKey" | "snapshot" | "priorityScore">): Plan {
  const s = c.snapshot;
  const steps: PlanStep[] = [];
  if (s?.matches?.length) steps.push({ step: "Validate the threat-intelligence match", detail: "Review each matched indicator: its pattern, confidence, validity dates and TLP marking, and confirm the observable really is the same thing.", source: "OpenCTI" });
  else if (s?.alert && s.openCtiConnected === false) steps.push({ step: "Re-run the OpenCTI lookup", detail: "OpenCTI was not reachable when this case was opened, so the absence of a match means nothing yet.", source: "OpenCTI" });
  const exploited = s?.vulnerabilities?.filter((v) => v.knownExploited === true) ?? [];
  if (exploited.length) steps.push({ step: "Check patch status for exploited-in-the-wild CVEs", detail: `CISA lists ${exploited.map((v) => v.cve).join(", ")} as exploited in the wild. Confirm whether the affected software is present and patched on this endpoint.`, source: "OpenCTI / CISA" });
  if (s?.techniques?.length) steps.push({ step: "Review the mapped ATT&CK techniques", detail: `This alert maps to ${s.techniques.join(", ")}. Look for related behaviour in the surrounding events. A technique tag describes the rule, not proof of the technique.`, source: "Wazuh" });
  if (s?.alert) steps.push({ step: "Confirm endpoint context", detail: `Review agent ${s.alert.agent || "(unknown)"}: its OS, its other recent alerts and recent changes.`, source: "Wazuh" });
  steps.push({ step: "Collect corroborating evidence", detail: "Check adjacent events and their timestamps before concluding compromise. Add what you find as evidence on this case.", source: "Analyst" });
  steps.push({ step: "Decide whether containment is needed", detail: "Only if the evidence supports an active compromise, create a response proposal for a second person to review.", source: "PrimeSEC" });
  const suggestedProposals = s?.alert?.agent ? [{ actionType: "isolate_endpoint", target: s.alert.agent, rationale: "Consider isolation only after confirming active compromise and weighing business impact." }] : [];
  return {
    caseKey: c.caseKey,
    assessment: "Rule-based investigation plan built from the data stored on this case. It is decision support, not a verdict.",
    steps, suggestedProposals, execution: "No action has been executed."
  };
}
