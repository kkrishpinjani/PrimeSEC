import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { listIntel, listRuns, listWatermarks, SyncError, SYNC_SOURCES } from "../../../lib/sync";
import { schedulerStatus } from "../../../lib/syncScheduler";
import { isOpenCtiEntity, syncGreenbone, syncOpenCti, syncWazuh } from "../../../lib/syncSources";
import { writeAuditEvent } from "../../../lib/audit";
import { allowRequest } from "../../../lib/rateLimit";
import { logError } from "../../../lib/log";

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

/**
 * GET: run history, watermarks and (with ?intel=1) the OpenCTI snapshot. Any PrimeSEC role.
 * POST { source: "wazuh" | "greenbone" | "opencti", entity?, first? }: start a sync. SOC_Admin only, origin-checked, rate-limited, audited.
 * A sync reads from the source and writes only PrimeSEC's own stores. It never scans, remediates or writes back.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    const ctx = await agentGuard(req, res, "view");
    if (!ctx) return;
    try {
      const source = one(req.query.source);
      if (one(req.query.intel) === "1") return res.status(200).json({ items: await listIntel({ entityType: one(req.query.entity), limit: Number(one(req.query.limit)) || undefined }) });
      return res.status(200).json({ runs: await listRuns({ source, limit: Number(one(req.query.limit)) || undefined }), watermarks: await listWatermarks(), sources: SYNC_SOURCES, scheduler: schedulerStatus() });
    } catch (error) {
      logError("sync list", error);
      return res.status(500).json({ error: "The synchronization history is unavailable." });
    }
  }
  if (req.method !== "POST") { res.setHeader("Allow", "GET, POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "admin");
  if (!ctx) return;
  const by = ctx.actor.email || ctx.actor.name || "unknown";
  if (!allowRequest(`sync-run:${by}`, 12, 10 * 60_000)) {
    res.setHeader("Retry-After", "600");
    return res.status(429).json({ error: "Too many sync requests. Wait a few minutes and try again." });
  }
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    let outcome;
    if (body.source === "wazuh") outcome = await syncWazuh(by);
    else if (body.source === "greenbone") outcome = await syncGreenbone(by);
    else if (body.source === "opencti") {
      if (!isOpenCtiEntity(body.entity)) throw new SyncError("entity must be one of indicators, vulnerabilities, reports, threat_actors, malwares.", "INVALID");
      const first = typeof body.first === "number" && Number.isInteger(body.first) ? Math.min(Math.max(body.first, 1), 200) : 100;
      outcome = await syncOpenCti(body.entity, first, by);
    } else throw new SyncError(`source must be one of ${SYNC_SOURCES.join(", ")}.`, "INVALID");

    const { run, ingest } = outcome;
    let auditRecorded = true;
    try {
      await writeAuditEvent({ action: "sync_run", actor: ctx.actor, source: run.source, stream: run.stream, runId: run.id, status: run.status, recordsSeen: run.recordsSeen, recordsIngested: run.recordsIngested, error: run.error });
    } catch (error) {
      auditRecorded = false;
      logError("sync: run recorded but the audit write failed", error);
    }
    return res.status(run.status === "failed" ? 502 : 200).json({ run, created: ingest?.created ?? 0, updated: ingest?.updated ?? 0, auditRecorded });
  } catch (error) {
    if (error instanceof SyncError) return res.status(error.code === "CONFLICT" ? 409 : 400).json({ error: error.message });
    logError("sync run", error);
    return res.status(500).json({ error: "The synchronization could not be started." });
  }
}
