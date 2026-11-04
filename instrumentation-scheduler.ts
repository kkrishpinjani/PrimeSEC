/**
 * Starts the optional sync scheduler (lib/syncScheduler.ts) when SYNC_SCHEDULE_MINUTES is set. Imported only from the Node runtime
 * branch of instrumentation.ts. With the variable unset this does nothing.
 */
import { startSyncScheduler } from "./lib/syncScheduler";
import { syncGreenbone, syncOpenCti, syncWazuh, isOpenCtiEntity } from "./lib/syncSources";
import { writeAuditEvent } from "./lib/audit";
import { logError } from "./lib/log";

startSyncScheduler(
  process.env,
  {
    wazuh: (by) => syncWazuh(by),
    greenbone: (by) => syncGreenbone(by),
    opencti: async (entity, by) => {
      if (!isOpenCtiEntity(entity)) throw new Error("Unsupported OpenCTI entity type.");
      return syncOpenCti(entity, 100, by);
    },
    audit: async ({ run }) => {
      try {
        await writeAuditEvent({ action: "sync_run", actor: { name: "scheduler", email: null, roles: [] }, source: run.source, stream: run.stream, runId: run.id, status: run.status, recordsSeen: run.recordsSeen, recordsIngested: run.recordsIngested, error: run.error });
      } catch (error) {
        logError("sync scheduler: run recorded but the audit write failed", error);
      }
    }
  },
  (message) => console.log(message)
);
