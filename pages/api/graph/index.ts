import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { GraphClient, GraphError } from "../../../lib/graph";
import { logError } from "../../../lib/log";

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

/**
 * GET: graph status (configured / reachable). With ?view=exposure, assets ranked by open vulnerabilities; with ?view=paths&asset=ID,
 * the connection paths from one asset (up to 5 hops). Any PrimeSEC role; read-only; the graph holds only what an admin projected into it.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "view");
  if (!ctx) return;
  const graph = new GraphClient();
  if (!graph.configured) return res.status(200).json({ configured: false, reachable: false, message: "Set NEO4J_HTTP_URL, NEO4J_USERNAME and NEO4J_PASSWORD in .env to enable the security graph." });
  try {
    const view = one(req.query.view);
    if (view === "exposure") return res.status(200).json({ configured: true, reachable: true, items: await graph.assetExposure(Number(one(req.query.limit)) || undefined) });
    if (view === "paths") return res.status(200).json({ configured: true, reachable: true, paths: await graph.attackPaths(String(one(req.query.asset) ?? ""), Number(one(req.query.limit)) || undefined) });
    return res.status(200).json({ configured: true, reachable: await graph.health(), message: "Neo4j answered." });
  } catch (error) {
    if (error instanceof GraphError) return res.status(error.code === "INVALID" ? 400 : 200).json(error.code === "INVALID" ? { error: error.message } : { configured: true, reachable: false, message: error.message });
    logError("graph read", error);
    return res.status(500).json({ error: "The graph request failed." });
  }
}
