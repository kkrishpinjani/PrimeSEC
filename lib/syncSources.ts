/**
 * Wires the sync engine (sync.ts) to the real Wazuh, Greenbone-findings and OpenCTI readers. Kept separate so the engine
 * can be tested without any platform. Every function here is read-only toward its upstream.
 */
import { listOpenCtiEntities, listWazuhAgents, OPENCTI_SYNC_ENTITIES, type OpenCtiSyncEntity } from "./integrations.ts";
import { readFindings } from "./findings.ts";
import { readAssets, hostKey } from "./assets.ts";
import { findingsToAssets, runAssetSync, runOpenCtiSync, SyncError, wazuhAgentToAsset, type SyncOutcome } from "./sync.ts";

export function isOpenCtiEntity(v: unknown): v is OpenCtiSyncEntity {
  return typeof v === "string" && (OPENCTI_SYNC_ENTITIES as readonly string[]).includes(v);
}

/** The demo servers answer on the same URLs as real platforms, so a demo sync is labelled rather than silently mixed in. */
const demoNote = () => (process.env.DEMO_INTEGRATIONS === "true" ? "Demo data: records came from the demo integrations server, not a real platform." : undefined);

export function syncWazuh(triggeredBy: string): Promise<SyncOutcome> {
  return runAssetSync("wazuh", triggeredBy, async () => {
    const { items, truncated } = await listWazuhAgents();
    const note = [truncated ? "Stopped at the agent limit; some agents were not read." : "", demoNote() ?? ""].filter(Boolean).join(" ") || undefined;
    return { items: items.map(wazuhAgentToAsset), note };
  });
}

export function syncGreenbone(triggeredBy: string): Promise<SyncOutcome> {
  return runAssetSync("greenbone", triggeredBy, async () => {
    const [findings, hosts] = await Promise.all([readFindings(), readAssets()]);
    if (findings.length === 0) throw new SyncError("There are no imported Greenbone findings yet. Run a findings sync in the VAPT workspace first.", "INVALID");
    const ctx = new Map(hosts.map((h) => [hostKey(h.host), { criticality: h.criticality, exposure: h.exposure }]));
    return { items: findingsToAssets(findings, ctx), note: "Built from findings already imported in the VAPT workspace; this does not call Greenbone." };
  });
}

export function syncOpenCti(entity: OpenCtiSyncEntity, first: number, triggeredBy: string): Promise<SyncOutcome> {
  return runOpenCtiSync(entity, triggeredBy, (after) => listOpenCtiEntities(entity, first, after));
}
