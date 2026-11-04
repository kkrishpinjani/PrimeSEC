import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { browse, getEntity, OpenCtiError, searchObservables, type Deps } from "../../../lib/opencti";
import { openCtiConfigured, openCtiRequest, wazuhSafeError } from "../../../lib/integrations";
import { logError } from "../../../lib/log";

const STATUS = { INVALID: 400, NOT_FOUND: 404, NOT_CONFIGURED: 409, UPSTREAM: 502 } as const;
const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

/**
 * Read-only OpenCTI explorer. Any PrimeSEC role.
 *   GET /api/opencti/indicators|reports|threat_actors|vulnerabilities|malwares?first=&after=&search=
 *   GET /api/opencti/observables?value=&first=          search observables (IPs, domains, hashes ...)
 *   GET /api/opencti/entity?type=indicator&id=<id>     one entity
 * The OpenCTI token stays on the server; OPENCTI_ALLOWED_MARKINGS is applied to everything returned.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return res.status(405).json({ error: "Method not allowed" }); }
  const ctx = await agentGuard(req, res, "view");
  if (!ctx) return;
  const deps: Deps = { query: openCtiRequest, configured: openCtiConfigured, safeError: wazuhSafeError, env: process.env };
  try {
    const kind = String(req.query.kind);
    if (kind === "observables") return res.status(200).json(await searchObservables(one(req.query.value), one(req.query.first), deps));
    if (kind === "entity") return res.status(200).json(await getEntity(one(req.query.type), one(req.query.id), deps));
    return res.status(200).json(await browse(kind, { first: one(req.query.first), after: one(req.query.after), search: one(req.query.search) }, deps));
  } catch (error) {
    if (error instanceof OpenCtiError) return res.status(STATUS[error.code]).json({ error: error.message });
    logError("opencti explorer", error);
    return res.status(500).json({ error: "The OpenCTI request failed." });
  }
}
