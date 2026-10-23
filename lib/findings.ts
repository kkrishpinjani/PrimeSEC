/**
 * Greenbone findings: normalisation, de-duplication and remediation tracking.
 *
 * This module RECORDS work; it never changes a target. A "retest" is a request for a new authorized scan
 * that goes through the same scope, audit and rate-limit path as any other scan (see vaptLaunch.ts).
 * Findings are scanner evidence for analyst triage, not proof that an asset is compromised.
 */
import { createHash } from "crypto";
import { promises as fs } from "fs";
import path from "path";

export const STATUSES = ["Open", "In Progress", "Resolved", "Retest Required", "Closed"] as const;
/** What the analyst knows about exploitation of this vulnerability (for example from CISA KEV or a vendor advisory). */
export const EXPLOIT_EVIDENCE = ["Unknown", "None known", "Public exploit", "Exploited in the wild"] as const;
export type ExploitEvidence = (typeof EXPLOIT_EVIDENCE)[number];
export type FindingStatus = (typeof STATUSES)[number];
export type FindingSeverity = "Critical" | "High" | "Medium" | "Low" | "Info";

export type RawFinding = {
  reportId?: unknown; resultId?: unknown; taskName?: unknown; host?: unknown; port?: unknown; name?: unknown; oid?: unknown;
  cves?: unknown; severity?: unknown; threat?: unknown; description?: unknown; solution?: unknown; creationTime?: unknown;
  /** Position of the finding's report in the import, 0 = newest. Missing means "treat as current". */
  reportIndex?: unknown;
};

export type Finding = {
  /** Stable id: sha256(host | port | NVT oid), so a renamed vulnerability keeps its remediation history. */
  id: string;
  source: "Greenbone";
  reportId: string;
  resultId: string;
  taskName: string;
  host: string;
  port: string;
  name: string;
  oid: string;
  cves: string[];
  severityScore: number;
  severity: FindingSeverity;
  threat: string;
  description: string;
  solution: string;
  firstSeen: string | null;
  /** When this finding last appeared in an imported report. An old value means it has stopped appearing. */
  lastSeen: string;
  firstImportedAt: string;
  /** True when the latest complete sync did not contain this finding (it may be fixed: verify before closing). */
  notInLatestSync: boolean;
  remediationStatus: FindingStatus;
  owner: string;
  remediationNotes: string;
  /** Input to the risk score. Preserved across syncs like the other analyst fields. */
  exploitEvidence: ExploitEvidence;
  retestTaskId: string | null;
  retestRequestedAt: string | null;
  updatedAt: string | null;
  updatedBy: string | null;
};

export type SyncResult = { findings: Finding[]; imported: number; updated: number; missing: number; truncated: boolean; retrievedAt: string };

const storePath = () => path.join(process.cwd(), "data", "vapt-findings.json");
export const MAX_NOTES = 2000;
export const MAX_OWNER = 120;
export const MIN_CLOSE_JUSTIFICATION = 10;

/* ------------------------------ normalisation ------------------------------ */

export function severityLabel(score: number, threat: string): FindingSeverity {
  if (threat.toLowerCase() === "log") return "Info";
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  if (score > 0) return "Low";
  return "Info";
}

export function findingId(host: string, port: string, oid: string, name: string): string {
  // The NVT oid is the stable identity; the display name is only a fallback for results without one.
  const identity = [host.trim().toLowerCase(), port.trim().toLowerCase(), (oid || name).trim().toLowerCase()].join("|");
  return `vuln_${createHash("sha256").update(identity).digest("hex").slice(0, 16)}`;
}

const text = (v: unknown, max: number) => String(v ?? "").trim().slice(0, max);

export function normalizeFinding(raw: RawFinding, now = new Date().toISOString()): Finding {
  const host = text(raw.host, 255);
  const port = text(raw.port, 40);
  const name = text(raw.name, 300) || "Unnamed vulnerability result";
  const oid = text(raw.oid, 200);
  const cves = Array.isArray(raw.cves) ? [...new Set(raw.cves.map((x) => text(x, 40)).filter(Boolean))].sort() : [];
  const parsed = Number(raw.severity);
  const score = Number.isFinite(parsed) ? Math.max(0, Math.min(10, parsed)) : 0;
  const threat = text(raw.threat, 40) || "Log";
  return {
    id: findingId(host, port, oid, name),
    source: "Greenbone",
    reportId: text(raw.reportId, 100),
    resultId: text(raw.resultId, 100),
    taskName: text(raw.taskName, 200),
    host, port, name, oid, cves,
    severityScore: score,
    severity: severityLabel(score, threat),
    threat,
    description: text(raw.description, 6000),
    solution: text(raw.solution, 3000),
    firstSeen: text(raw.creationTime, 60) || null,
    lastSeen: now,
    firstImportedAt: now,
    notInLatestSync: false,
    remediationStatus: "Open",
    owner: "",
    remediationNotes: "",
    exploitEvidence: "Unknown",
    retestTaskId: null,
    retestRequestedAt: null,
    updatedAt: null,
    updatedBy: null
  };
}

/* ---------------------------------- storage --------------------------------- */

let chain: Promise<unknown> = Promise.resolve();
/** Serialises read-modify-write cycles so two concurrent edits cannot silently lose one another's update. */
function withStore<T>(fn: (items: Finding[]) => Promise<{ items: Finding[]; result: T }>): Promise<T> {
  const run = chain.then(async () => {
    const { items, result } = await fn(await readFindings());
    await fs.mkdir(path.dirname(storePath()), { recursive: true });
    const temp = `${storePath()}.${process.pid}.tmp`;
    await fs.writeFile(temp, JSON.stringify(items, null, 2), { mode: 0o600 });
    await fs.rename(temp, storePath());
    return result;
  });
  chain = run.catch(() => undefined);
  return run;
}

export async function readFindings(): Promise<Finding[]> {
  try {
    const value = JSON.parse(await fs.readFile(storePath(), "utf8"));
    // Records written before a field existed get its safe default instead of "undefined".
    return Array.isArray(value) ? (value as Finding[]).map((f) => ({ ...f, exploitEvidence: f.exploitEvidence ?? "Unknown" })) : [];
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return [];
    throw error;
  }
}

const bySeverity = (a: Finding, b: Finding) => b.severityScore - a.severityScore || a.host.localeCompare(b.host) || a.name.localeCompare(b.name);

/* ----------------------------------- sync ----------------------------------- */

/**
 * Merges freshly imported results into the store.
 *
 * Scanner evidence is refreshed; remediation fields (status, owner, notes, retest metadata) always survive.
 * Results repeated across reports collapse to one finding (highest severity among the current ones wins).
 *
 * "Current" is decided PER HOST: only the most recent report that covers a host describes its present state.
 * A finding seen in an older report of a host but absent from that host's latest report is flagged
 * `notInLatestSync`. This is what makes a retest useful: the fixed vulnerability still sits in the older report,
 * and disappears from the new one. It is a hint to verify, never an automatic close. A finding that is in the
 * store but in none of the imported reports is flagged too, unless the import was truncated (then nothing is
 * flagged, because the import is incomplete).
 */
export async function syncFindings(raws: RawFinding[], opts: { truncated?: boolean; now?: string } = {}): Promise<SyncResult> {
  const now = opts.now ?? new Date().toISOString();
  const idx = (r: RawFinding) => (Number.isFinite(Number(r.reportIndex)) && r.reportIndex !== null && r.reportIndex !== "" ? Number(r.reportIndex) : 0);
  const latestByHost = new Map<string, number>();
  for (const r of raws) {
    const host = String(r.host ?? "").trim().toLowerCase();
    latestByHost.set(host, Math.min(latestByHost.get(host) ?? Infinity, idx(r)));
  }

  type Candidate = { finding: Finding; current: boolean; index: number };
  const incoming = new Map<string, Candidate>();
  for (const raw of raws) {
    const finding = normalizeFinding(raw, now);
    const current = idx(raw) === latestByHost.get(finding.host.toLowerCase());
    const candidate: Candidate = { finding, current, index: idx(raw) };
    const seen = incoming.get(finding.id);
    if (!seen) { incoming.set(finding.id, candidate); continue; }
    // A current sighting beats an older one; among equals the highest severity (then the newest report) wins.
    const better =
      (candidate.current && !seen.current) ||
      (candidate.current === seen.current && (finding.severityScore > seen.finding.severityScore || (finding.severityScore === seen.finding.severityScore && candidate.index < seen.index)));
    if (better) incoming.set(finding.id, candidate);
  }

  return withStore(async (stored) => {
    const merged = new Map(stored.map((f) => [f.id, f]));
    let imported = 0, updated = 0, missing = 0;
    for (const { finding: fresh, current } of incoming.values()) {
      const previous = merged.get(fresh.id);
      const wasFlagged = previous?.notInLatestSync ?? false;
      if (!current && !wasFlagged) missing++;
      const base = { ...fresh, notInLatestSync: !current };
      if (previous) {
        updated++;
        merged.set(fresh.id, {
          ...base,
          firstImportedAt: previous.firstImportedAt,
          remediationStatus: previous.remediationStatus,
          owner: previous.owner,
          remediationNotes: previous.remediationNotes,
          exploitEvidence: previous.exploitEvidence,
          retestTaskId: previous.retestTaskId,
          retestRequestedAt: previous.retestRequestedAt,
          updatedAt: previous.updatedAt,
          updatedBy: previous.updatedBy
        });
      } else {
        imported++;
        merged.set(fresh.id, base);
      }
    }
    if (!opts.truncated) {
      for (const [id, f] of merged) {
        if (!incoming.has(id)) {
          if (!f.notInLatestSync) missing++;
          merged.set(id, { ...f, notInLatestSync: true });
        }
      }
    }
    const items = [...merged.values()].sort(bySeverity);
    return { items, result: { findings: items, imported, updated, missing, truncated: Boolean(opts.truncated), retrievedAt: now } };
  });
}

/* ---------------------------------- updates --------------------------------- */

export type Patch = { remediationStatus?: unknown; owner?: unknown; remediationNotes?: unknown; exploitEvidence?: unknown; expectedUpdatedAt?: unknown };
export class FindingError extends Error {
  code: "NOT_FOUND" | "INVALID" | "CONFLICT" | "FORBIDDEN";
  constructor(message: string, code: "NOT_FOUND" | "INVALID" | "CONFLICT" | "FORBIDDEN") {
    super(message);
    this.code = code;
  }
}

/**
 * Partial update: only the fields present in the patch change (a status-only patch never erases the owner
 * or notes). `expectedUpdatedAt` is optimistic concurrency: if someone else edited the finding since the
 * caller loaded it, the update is refused (CONFLICT) instead of overwriting their work.
 *
 * Closing: a finding may be closed only after a retest was requested for it, or by a SOC_Admin who records a
 * written justification in the notes. A vulnerability is never closed on a status click alone.
 */
export async function updateFinding(id: string, patch: Patch, actor: { email?: string | null; name?: string | null; roles: string[] }): Promise<Finding> {
  return withStore<Finding>(async (items) => {
    const index = items.findIndex((f) => f.id === id);
    if (index < 0) throw new FindingError("Finding not found. Sync Greenbone findings and try again.", "NOT_FOUND");
    const current = items[index];
    if ("expectedUpdatedAt" in patch && (patch.expectedUpdatedAt ?? null) !== current.updatedAt) {
      throw new FindingError("This finding was changed by someone else. Reload it and try again.", "CONFLICT");
    }
    let status = current.remediationStatus;
    if (patch.remediationStatus !== undefined) {
      if (!STATUSES.includes(patch.remediationStatus as FindingStatus)) throw new FindingError(`Invalid remediation status. Allowed: ${STATUSES.join(", ")}.`, "INVALID");
      status = patch.remediationStatus as FindingStatus;
    }
    let exploitEvidence = current.exploitEvidence;
    if (patch.exploitEvidence !== undefined) {
      if (!EXPLOIT_EVIDENCE.includes(patch.exploitEvidence as ExploitEvidence)) throw new FindingError(`Invalid exploit evidence. Allowed: ${EXPLOIT_EVIDENCE.join(", ")}.`, "INVALID");
      exploitEvidence = patch.exploitEvidence as ExploitEvidence;
    }
    const owner = patch.owner === undefined ? current.owner : text(patch.owner, MAX_OWNER);
    const notes = patch.remediationNotes === undefined ? current.remediationNotes : text(patch.remediationNotes, MAX_NOTES);
    if (status === "Closed" && current.remediationStatus !== "Closed") {
      const verified = Boolean(current.retestTaskId);
      const justifiedByAdmin = actor.roles.includes("SOC_Admin") && notes.length >= MIN_CLOSE_JUSTIFICATION;
      if (!verified && !justifiedByAdmin) {
        throw new FindingError(
          `A finding can be closed only after a retest was requested for it, or by a SOC_Admin who writes a justification (at least ${MIN_CLOSE_JUSTIFICATION} characters) in the notes.`,
          "FORBIDDEN"
        );
      }
    }
    const updated: Finding = { ...current, remediationStatus: status, owner, remediationNotes: notes, exploitEvidence, updatedAt: new Date().toISOString(), updatedBy: actor.email || actor.name || "unknown" };
    const next = items.slice();
    next[index] = updated;
    return { items: next, result: updated };
  });
}

/** Records that a retest scan was requested (the scan itself is started by vaptLaunch.ts, with all its guards). */
export async function markRetestRequested(id: string, taskId: string | null, actor: { email?: string | null; name?: string | null }): Promise<Finding> {
  return withStore<Finding>(async (items) => {
    const index = items.findIndex((f) => f.id === id);
    if (index < 0) throw new FindingError("Finding not found.", "NOT_FOUND");
    const now = new Date().toISOString();
    const updated: Finding = { ...items[index], remediationStatus: "Retest Required", retestTaskId: taskId, retestRequestedAt: now, updatedAt: now, updatedBy: actor.email || actor.name || "unknown" };
    const next = items.slice();
    next[index] = updated;
    return { items: next, result: updated };
  });
}

/** Removes one finding from the local store. Greenbone is untouched: a later sync re-imports it if it is still reported. */
export async function deleteFinding(id: string): Promise<Finding> {
  return withStore<Finding>(async (items) => {
    const found = items.find((f) => f.id === id);
    if (!found) throw new FindingError("Finding not found.", "NOT_FOUND");
    return { items: items.filter((f) => f.id !== id), result: found };
  });
}

/** Empties the local findings store; returns how many were removed. */
export async function clearFindings(): Promise<number> {
  return withStore<number>(async (items) => ({ items: [], result: items.length }));
}

export async function getFinding(id: string): Promise<Finding | null> {
  return (await readFindings()).find((f) => f.id === id) ?? null;
}
