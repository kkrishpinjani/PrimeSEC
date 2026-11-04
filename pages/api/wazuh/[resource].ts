import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { explore, WazuhError, type Args } from "../../../lib/wazuh";
import { wazuhApiConfigured, wazuhApiRequest, wazuhIndexerReady, wazuhIndexerSearch, wazuhSafeError } from "../../../lib/integrations";
import { logError } from "../../../lib/log";

const STATUS = { INVALID: 400, FORBIDDEN: 403, NOT_CONFIGURED: 409, UPSTREAM: 502 } as const;

/**
 * Read-only Wazuh explorer: GET /api/wazuh/<resource>?agent=&group=&limit=&offset=&search=...
 * Any PrimeSEC role. Only the fixed resources in lib/wazuh.ts exist; nothing here changes Wazuh or runs active response.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "view");
  if (!ctx) return;
  const args: Args = {};
  for (const [k, v] of Object.entries(req.query)) if (k !== "resource") args[k] = Array.isArray(v) ? v[0] : v;
  try {
    const result = await explore(req.query.resource, args, {
      api: wazuhApiRequest, indexer: wazuhIndexerSearch, apiConfigured: wazuhApiConfigured, indexerConfigured: wazuhIndexerReady, safeError: wazuhSafeError, env: process.env
    });
    return res.status(200).json(result);
  } catch (error) {
    if (error instanceof WazuhError) return res.status(STATUS[error.code]).json({ error: error.message });
    logError("wazuh explorer", error);
    return res.status(500).json({ error: "The Wazuh request failed." });
  }
}
