import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { chunkBatch, GraphClient, GraphError, projectInventory, projectionKeys, validateBatch } from "../../../lib/graph";
import { readInventory } from "../../../lib/inventory";
import { writeAuditEvent } from "../../../lib/audit";
import { allowRequest } from "../../../lib/rateLimit";
import { logError } from "../../../lib/log";

/**
 * POST { action: "schema" }                  create the indexes.
 * POST { action: "project" }                 copy the asset inventory into the graph (assets, open vulnerabilities, links).
 * POST { action: "ingest", nodes, relationships }   add validated nodes and links.
 * SOC_Admin only, origin-checked, rate-limited, audited. Writes only to the configured Neo4j namespace; touches no host.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "admin");
  if (!ctx) return;
  const by = ctx.actor.email || ctx.actor.name || "unknown";
  if (!allowRequest(`graph-write:${by}`, 10, 10 * 60_000)) { res.setHeader("Retry-After", "600"); return res.status(429).json({ error: "Too many graph writes. Wait a few minutes and try again." }); }
  const graph = new GraphClient();
  if (!graph.configured) return res.status(503).json({ error: "Set NEO4J_HTTP_URL, NEO4J_USERNAME and NEO4J_PASSWORD in .env to enable the security graph." });
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    let summary: Record<string, number>;
    if (body.action === "schema") summary = { indexes: await graph.ensureSchema() };
    else if (body.action === "project") {
      let nodes = 0, relationships = 0, linked = 0, skipped = 0;
      const projection = projectInventory(await readInventory());
      for (const chunk of chunkBatch(projection)) {
        const r = await graph.upsert(chunk);
        nodes += r.nodes; relationships += r.relationships; linked += r.linked; skipped += r.skipped;
      }
      // Only after every chunk was written: remove what an earlier projection left behind (merged-away assets, closed findings).
      const keys = projectionKeys(projection);
      const pruned = await graph.pruneProjection(keys.assetIds, keys.pairs);
      summary = { nodes, relationships, linked, skipped, prunedLinks: pruned.links, prunedAssets: pruned.assets, prunedVulnerabilities: pruned.vulnerabilities };
    } else if (body.action === "ingest") summary = await graph.upsert(validateBatch(body));
    else return res.status(400).json({ error: 'action must be "schema", "project" or "ingest".' });
    let auditRecorded = true;
    try { await writeAuditEvent({ action: "graph_write", actor: ctx.actor, operation: String(body.action), summary }); }
    catch (error) { auditRecorded = false; logError("graph: write applied but the audit write failed", error); }
    return res.status(200).json({ ...summary, auditRecorded });
  } catch (error) {
    if (error instanceof GraphError) return res.status(error.code === "INVALID" ? 400 : error.code === "NOT_CONFIGURED" ? 503 : 502).json({ error: error.message });
    logError("graph write", error);
    return res.status(500).json({ error: "The graph write failed." });
  }
}
