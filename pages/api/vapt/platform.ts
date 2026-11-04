import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { getScanPlatform } from "../../../lib/vapt";

/** Read-only view of the Greenbone instance: scanners, scan configs, port lists, schedules, alert definitions (names only) and feed status. Any PrimeSEC role. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "view");
  if (!ctx) return;
  return res.status(200).json(await getScanPlatform());
}
