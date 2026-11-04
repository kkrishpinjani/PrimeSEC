/**
 * Continuous synchronisation: pulls Wazuh agents, Greenbone findings and OpenCTI intelligence into PrimeSEC's own
 * stores, with durable run history and per-stream watermarks. Port of the Phase II "Continuous Sync v1.5" package.
 *
 * Read-only toward every upstream: a sync never scans, remediates, writes back or triggers an active response.
 * Runs are started on request (the API or an external scheduler calling it); there is no background worker, and
 * overlapping runs of the same source are refused rather than queued.
 */
import { promises as fs } from "fs";
import path from "path";
import { ingestAssets, validateAssetInput, type AssetInput, type IngestResult } from "./inventory.ts";

export const SYNC_SOURCES = ["wazuh", "greenbone", "opencti"] as const;
export type SyncSource = (typeof SYNC_SOURCES)[number];
export const MAX_RUNS = 200;
export const MAX_INTEL = 5000;
/** A run still "running" after this long is presumed dead (process crash) and no longer blocks a new one. */
export const STALE_RUN_MS = 15 * 60_000;

export type SyncRun = {
  id: string;
  source: SyncSource;
  stream: string;
  status: "running" | "completed" | "failed";
  startedAt: string;
  finishedAt: string | null;
  recordsSeen: number;
  recordsIngested: number;
  /** Short, safe description of a failure. Never contains a credential or an upstream response body. */
  error: string | null;
  note: string | null;
  triggeredBy: string;
};
export type Watermark = { source: SyncSource; stream: string; cursor: Record<string, unknown>; updatedAt: string };
export type IntelObject = {
  entityType: string;
  externalId: string;
  name: string;
  /** True when the object's markings are not on the allow-list: only identity and policy metadata are kept, never content. */
  restricted: boolean;
  markings: string[];
  payload: Record<string, string | number | null> | null;
  updatedAt: string;
};
type SyncStore = { runs: SyncRun[]; watermarks: Watermark[]; intel: IntelObject[] };

export class SyncError extends Error {
  code: "INVALID" | "CONFLICT" | "UPSTREAM";
  constructor(message: string, code: "INVALID" | "CONFLICT" | "UPSTREAM") {
    super(message);
    this.code = code;
  }
}

/* ------------------------------ storage ------------------------------ */

const storePath = () => path.join(process.cwd(), "data", "sync.json");
const EMPTY = (): SyncStore => ({ runs: [], watermarks: [], intel: [] });

export async function readSync(): Promise<SyncStore> {
  try {
    const v = JSON.parse(await fs.readFile(storePath(), "utf8"));
    return { runs: Array.isArray(v?.runs) ? v.runs : [], watermarks: Array.isArray(v?.watermarks) ? v.watermarks : [], intel: Array.isArray(v?.intel) ? v.intel : [] };
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return EMPTY();
    throw error;
  }
}

let chain: Promise<unknown> = Promise.resolve();
function withStore<T>(fn: (s: SyncStore) => { store: SyncStore; result: T }): Promise<T> {
  const run = chain.then(async () => {
    const { store, result } = fn(await readSync());
    store.runs = store.runs.slice(-MAX_RUNS);
    store.intel = store.intel.slice(-MAX_INTEL);
    await fs.mkdir(path.dirname(storePath()), { recursive: true });
    const temp = `${storePath()}.${process.pid}.tmp`;
    await fs.writeFile(temp, JSON.stringify(store), { mode: 0o600 });
    await fs.rename(temp, storePath());
    return result;
  });
  chain = run.catch(() => undefined);
  return run;
}

/* ------------------------------ run lifecycle ------------------------------ */

const newRunId = () => `run_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 7)}`;

/** Refuses to start when this source already has a live run; a run older than STALE_RUN_MS is marked failed and replaced. */
async function startRun(source: SyncSource, stream: string, triggeredBy: string, now: number): Promise<SyncRun> {
  return withStore((s) => {
    for (const r of s.runs) {
      if (r.source !== source || r.status !== "running") continue;
      if (now - Date.parse(r.startedAt) < STALE_RUN_MS) throw new SyncError(`A ${source} sync is already running. Wait for it to finish.`, "CONFLICT");
      r.status = "failed";
      r.finishedAt = new Date(now).toISOString();
      r.error = "Interrupted: the previous run never reported completion.";
    }
    const run: SyncRun = { id: newRunId(), source, stream, status: "running", startedAt: new Date(now).toISOString(), finishedAt: null, recordsSeen: 0, recordsIngested: 0, error: null, note: null, triggeredBy };
    s.runs.push(run);
    return { store: s, result: run };
  });
}

async function finishRun(id: string, patch: Partial<Pick<SyncRun, "recordsSeen" | "recordsIngested" | "error" | "note">>, watermark?: Omit<Watermark, "updatedAt">, intel?: IntelObject[]): Promise<SyncRun> {
  return withStore((s) => {
    const run = s.runs.find((r) => r.id === id);
    if (!run) throw new SyncError("The sync run record disappeared.", "UPSTREAM");
    Object.assign(run, patch);
    run.status = patch.error ? "failed" : "completed";
    run.finishedAt = new Date().toISOString();
    if (watermark && !patch.error) {
      const at = new Date().toISOString();
      const i = s.watermarks.findIndex((w) => w.source === watermark.source && w.stream === watermark.stream);
      const row: Watermark = { ...watermark, updatedAt: at };
      if (i >= 0) s.watermarks[i] = row; else s.watermarks.push(row);
    }
    for (const o of intel ?? []) {
      const i = s.intel.findIndex((x) => x.entityType === o.entityType && x.externalId === o.externalId);
      if (i >= 0) s.intel[i] = o; else s.intel.push(o);
    }
    return { store: s, result: { ...run } };
  });
}

/** Failures are reduced to a short message so no upstream body or credential is persisted or returned. */
export function safeMessage(error: unknown): string {
  if (error instanceof SyncError) return error.message;
  const msg = error instanceof Error ? error.message : "";
  const code = (error as { code?: string } | null)?.code;
  if (code === "NOT_CONFIGURED") return msg.slice(0, 200);
  // Adapter errors are already scrubbed ("Wazuh API request failed (401)."), but cap and strip anything URL-like.
  return (msg || "The upstream request failed.").replace(/https?:\/\/\S+/g, "[url]").slice(0, 200);
}

/* ------------------------------ asset sources ------------------------------ */

export type SyncOutcome = { run: SyncRun; ingest: IngestResult | null };

/**
 * Runs one asset sync: fetch -> validate -> ingest, recording the run either way. A fetch that returns invalid
 * records fails the whole run rather than ingesting a partial, unreliable picture.
 */
export async function runAssetSync(source: SyncSource, triggeredBy: string, fetchItems: () => Promise<{ items: unknown[]; note?: string }>, now = Date.now()): Promise<SyncOutcome> {
  const run = await startRun(source, "assets", triggeredBy, now);
  try {
    const { items, note } = await fetchItems();
    const valid: AssetInput[] = items.map((raw, i) => validateAssetInput(raw, i));
    const ingest = valid.length ? await ingestAssets(valid, new Date(now).toISOString()) : null;
    const done = await finishRun(run.id, { recordsSeen: items.length, recordsIngested: valid.length, note: note ?? null }, { source, stream: "assets", cursor: { lastSuccessAt: run.startedAt, records: valid.length } });
    return { run: done, ingest };
  } catch (error) {
    return { run: await finishRun(run.id, { error: safeMessage(error) }), ingest: null };
  }
}

export type WazuhAgentLike = { id: string; name: string; status: string; ip: string | null; version: string | null; os: string | null; groups: string[] };

export function wazuhAgentToAsset(a: WazuhAgentLike): AssetInput {
  return {
    source: "wazuh", sourceAssetId: a.id, assetType: a.id === "000" ? "server" : "endpoint", name: a.name || `Wazuh agent ${a.id}`, hostname: a.name || null,
    primaryIp: a.ip, operatingSystem: a.os, identifiers: { agent_id: a.id }, tags: a.groups
  };
}

type FindingLike = {
  id: string; host: string; port: string; name: string; oid: string; cves: string[]; severityScore: number; severity: string; remediationStatus: string; threat: string;
};
type HostContext = { criticality: string; exposure: string };

const CRITICALITY_VALUE: Record<string, number> = { Low: 2, Medium: 3, High: 4, Critical: 5 };
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Greenbone findings already imported into PrimeSEC become inventory assets, one per host. Criticality and exposure
 * come from the analyst's host settings in the VAPT workspace. A finding the analyst has Resolved or Closed counts as
 * closed; one that merely stopped appearing in the latest scan stays open until someone verifies and closes it.
 */
export function findingsToAssets(findings: FindingLike[], hosts: Map<string, HostContext>): AssetInput[] {
  const byHost = new Map<string, FindingLike[]>();
  for (const f of findings) {
    const key = f.host.trim().toLowerCase();
    if (!key) continue;
    byHost.set(key, [...(byHost.get(key) ?? []), f]);
  }
  const out: AssetInput[] = [];
  for (const [host, list] of byHost) {
    const ctx = hosts.get(host);
    out.push({
      source: "greenbone", sourceAssetId: host, assetType: "host", name: list[0].host.trim(),
      hostname: IPV4.test(host) ? null : list[0].host.trim(), primaryIp: IPV4.test(host) ? host : null,
      criticality: ctx ? CRITICALITY_VALUE[ctx.criticality] ?? null : null,
      internetFacing: ctx?.exposure === "Internet-facing",
      vulnerabilities: list.map((f) => ({
        cve: f.cves[0] ?? null, key: f.cves[0] ?? (f.oid || f.id), title: f.name.slice(0, 300), severity: f.severity.toLowerCase(), cvss: f.severityScore >= 0 && f.severityScore <= 10 ? f.severityScore : null,
        status: ["Resolved", "Closed"].includes(f.remediationStatus) ? "closed" : "open"
      }))
    });
  }
  return out;
}

/* ------------------------------ OpenCTI snapshot ------------------------------ */

export type CtiRecordLike = { id: string; name: string; markings: string[]; fields: Record<string, string | number | null> };

/** OPENCTI_ALLOWED_MARKINGS is a comma list such as "TLP:CLEAR,TLP:GREEN". Unset = no restriction. */
export function allowedMarkings(env: string | undefined = process.env.OPENCTI_ALLOWED_MARKINGS): Set<string> | null {
  const list = (env ?? "").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  return list.length ? new Set(list) : null;
}

/** With an allow-list, an unmarked object or one carrying any marking outside it is restricted: identity kept, content dropped. */
export function isRestricted(markings: string[], allow: Set<string> | null): boolean {
  return allow !== null && (markings.length === 0 || markings.some((m) => !allow.has(m.toLowerCase())));
}

export function toIntelObject(entityType: string, r: CtiRecordLike, allow: Set<string> | null, now: string): IntelObject {
  const restricted = isRestricted(r.markings, allow);
  return { entityType, externalId: r.id, name: restricted ? "" : r.name.slice(0, 300), restricted, markings: r.markings, payload: restricted ? null : r.fields, updatedAt: now };
}

export async function runOpenCtiSync(
  entityType: string, triggeredBy: string,
  fetchPage: (after: string | null) => Promise<{ items: CtiRecordLike[]; endCursor: string | null; hasNextPage: boolean }>,
  allow: Set<string> | null = allowedMarkings(), now = Date.now()
): Promise<SyncOutcome> {
  const run = await startRun("opencti", entityType, triggeredBy, now);
  try {
    // Resume where the last page of this stream ended; a finished stream starts over from the top next time.
    const prior = (await readSync()).watermarks.find((w) => w.source === "opencti" && w.stream === entityType);
    const resume = prior && prior.cursor.hasNextPage === true && typeof prior.cursor.endCursor === "string" ? prior.cursor.endCursor : null;
    const page = await fetchPage(resume);
    const at = new Date(now).toISOString();
    const intel = page.items.map((r) => toIntelObject(entityType, r, allow, at));
    const restricted = intel.filter((o) => o.restricted).length;
    const done = await finishRun(
      run.id,
      { recordsSeen: page.items.length, recordsIngested: page.items.length, note: restricted ? `${restricted} object(s) outside the allowed markings were stored without content.` : null },
      { source: "opencti", stream: entityType, cursor: { endCursor: page.endCursor, hasNextPage: page.hasNextPage, syncedAt: at } },
      intel
    );
    return { run: done, ingest: null };
  } catch (error) {
    return { run: await finishRun(run.id, { error: safeMessage(error) }), ingest: null };
  }
}

/* ------------------------------ reads ------------------------------ */

export async function listRuns(opts: { source?: string; limit?: number } = {}): Promise<SyncRun[]> {
  const limit = Math.min(Math.max(Math.floor(opts.limit ?? 50) || 50, 1), 200);
  const { runs } = await readSync();
  return runs.filter((r) => !opts.source || r.source === opts.source).slice().reverse().slice(0, limit);
}
export async function listWatermarks(): Promise<Watermark[]> {
  return (await readSync()).watermarks;
}
export async function listIntel(opts: { entityType?: string; limit?: number } = {}): Promise<IntelObject[]> {
  const limit = Math.min(Math.max(Math.floor(opts.limit ?? 100) || 100, 1), 500);
  const { intel } = await readSync();
  return intel.filter((o) => !opts.entityType || o.entityType === opts.entityType).slice().sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)).slice(0, limit);
}
