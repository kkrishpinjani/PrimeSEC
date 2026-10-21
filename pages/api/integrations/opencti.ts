import type { NextApiRequest, NextApiResponse } from "next";
import { requireSocSession } from "../../../lib/auth";
import { getOpenCtiOverview } from "../../../lib/integrations";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  if (!(await requireSocSession(req, res))) return;
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  return res.status(200).json(await getOpenCtiOverview());
}
