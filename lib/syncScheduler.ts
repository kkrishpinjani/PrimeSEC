/**
 * Optional in-process sync scheduler. OFF unless SYNC_SCHEDULE_MINUTES is set (5 to 1440).
 *
 * It only calls the same read-only syncs an administrator can start by hand: Wazuh agents, Greenbone findings already imported into PrimeSEC
 * (it does NOT call Greenbone or start a scan) and OpenCTI intelligence pages. Each run is recorded in the sync history and the audit log with
 * "scheduler" as the actor. A source that is already syncing is skipped, a failing source never stops the others, and the first run waits a
 * minute after start-up so it never competes with the server coming up.
 *
 * It lives inside the Next.js server process: if that process is not running, nothing is scheduled, and with several instances each would
 * run its own. For anything stricter, call POST /api/sync from an external scheduler instead.
 */
import { readSync, SYNC_SOURCES, type SyncOutcome, type SyncSource } from "./sync.ts";

export const MIN_MINUTES = 5;
export const MAX_MINUTES = 1440;
export const FIRST_RUN_DELAY_MS = 60_000;
export const SCHEDULER_ACTOR = "scheduler";

export type SchedulerConfig = { intervalMs: number; sources: SyncSource[]; openctiEntities: string[]; openctiMaxPages: number };

const OPENCTI_ENTITIES = ["indicators", "vulnerabilities", "reports", "threat_actors", "malwares"];

/** Reads the environment. Returns null (scheduler off) unless a valid interval is set; throws nothing, so a typo can never stop the server. */
export function schedulerConfig(env: Record<string, string | undefined>): SchedulerConfig | null {
  const minutes = Number(env.SYNC_SCHEDULE_MINUTES);
  if (!Number.isFinite(minutes) || minutes < MIN_MINUTES || minutes > MAX_MINUTES) return null;
  const listed = (env.SYNC_SCHEDULE_SOURCES ?? "wazuh,greenbone,opencti").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  const sources = SYNC_SOURCES.filter((s) => listed.includes(s));
  if (!sources.length) return null;
  const entities = (env.SYNC_SCHEDULE_OPENCTI_ENTITIES ?? "vulnerabilities,indicators").split(",").map((x) => x.trim()).filter((x) => OPENCTI_ENTITIES.includes(x));
  const pages = Number(env.SYNC_SCHEDULE_OPENCTI_MAX_PAGES);
  return { intervalMs: Math.round(minutes * 60_000), sources, openctiEntities: entities.length ? entities : ["vulnerabilities"], openctiMaxPages: Number.isInteger(pages) && pages >= 1 && pages <= 50 ? pages : 5 };
}

export type Runners = {
  wazuh: (by: string) => Promise<SyncOutcome>;
  greenbone: (by: string) => Promise<SyncOutcome>;
  opencti: (entity: string, by: string) => Promise<SyncOutcome>;
  audit: (outcome: SyncOutcome) => Promise<void>;
};

export type TickResult = { source: string; stream: string; status: "completed" | "failed" | "skipped"; note: string }[];
export type SchedulerStatus = { enabled: boolean; intervalMinutes: number | null; sources: string[]; lastTickAt: string | null; nextTickAt: string | null; lastResult: TickResult };
const KEY = "__primesecSyncScheduler";
type Holder = { status: SchedulerStatus; timer: ReturnType<typeof setTimeout> | null; running: boolean };
const holder = (): Holder => ((globalThis as any)[KEY] ??= { status: { enabled: false, intervalMinutes: null, sources: [], lastTickAt: null, nextTickAt: null, lastResult: [] }, timer: null, running: false });

export const schedulerStatus = (): SchedulerStatus => ({ ...holder().status });

/** One pass over the configured sources. Never throws; every outcome is returned. */
export async function tick(cfg: SchedulerConfig, runners: Runners): Promise<TickResult> {
  const out: TickResult = [];
  const record = async (source: string, stream: string, run: () => Promise<SyncOutcome>) => {
    try {
      const outcome = await run();
      await runners.audit(outcome).catch(() => undefined);
      out.push({ source, stream, status: outcome.run.status === "failed" ? "failed" : "completed", note: outcome.run.error ?? `${outcome.run.recordsSeen} read` });
    } catch (error) {
      // startRun throws CONFLICT when that source is already syncing (for example someone started it by hand): skip, do not fail.
      const conflict = (error as { code?: string })?.code === "CONFLICT";
      out.push({ source, stream, status: conflict ? "skipped" : "failed", note: conflict ? "already running" : "could not start" });
    }
  };
  if (cfg.sources.includes("wazuh")) await record("wazuh", "assets", () => runners.wazuh(SCHEDULER_ACTOR));
  if (cfg.sources.includes("greenbone")) await record("greenbone", "assets", () => runners.greenbone(SCHEDULER_ACTOR));
  if (cfg.sources.includes("opencti")) {
    for (const entity of cfg.openctiEntities) {
      // One page per run, resuming from the stored cursor; keep going while the stream has more, up to the page limit.
      for (let page = 0; page < cfg.openctiMaxPages; page++) {
        await record("opencti", entity, () => runners.opencti(entity, SCHEDULER_ACTOR));
        if (out[out.length - 1].status !== "completed") break;
        const mark = (await readSync()).watermarks.find((w) => w.source === "opencti" && w.stream === entity);
        if (mark?.cursor.hasNextPage !== true) break;
      }
    }
  }
  return out;
}

/** Starts the timer. Safe to call more than once (dev reloads): a second call is ignored. Returns whether a scheduler is now running. */
export function startSyncScheduler(env: Record<string, string | undefined>, runners: Runners, log: (m: string) => void = () => undefined): boolean {
  const cfg = schedulerConfig(env);
  const h = holder();
  if (!cfg) { h.status = { ...h.status, enabled: false }; return false; }
  if (h.timer) return true;
  h.status = { enabled: true, intervalMinutes: cfg.intervalMs / 60_000, sources: cfg.sources, lastTickAt: null, nextTickAt: null, lastResult: [] };
  const schedule = (delay: number) => {
    h.status.nextTickAt = new Date(Date.now() + delay).toISOString();
    h.timer = setTimeout(async () => {
      if (!h.running) {
        h.running = true;
        try {
          h.status.lastResult = await tick(cfg, runners);
          h.status.lastTickAt = new Date().toISOString();
          log(`sync scheduler: ${h.status.lastResult.map((r) => `${r.source}/${r.stream} ${r.status}`).join(", ")}`);
        } catch { /* tick never throws; this is only a last guard */ } finally { h.running = false; }
      }
      schedule(cfg.intervalMs);
    }, delay);
    // Never keep the process alive just for the timer.
    (h.timer as { unref?: () => void }).unref?.();
  };
  schedule(FIRST_RUN_DELAY_MS);
  log(`sync scheduler on: every ${cfg.intervalMs / 60_000} min (${cfg.sources.join(", ")})`);
  return true;
}

export function stopSyncSchedulerForTests(): void {
  const h = holder();
  if (h.timer) clearTimeout(h.timer);
  h.timer = null; h.running = false;
  h.status = { enabled: false, intervalMinutes: null, sources: [], lastTickAt: null, nextTickAt: null, lastResult: [] };
}
