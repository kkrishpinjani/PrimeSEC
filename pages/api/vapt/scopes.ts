import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed, PRIMESEC_ROLES } from "../../../lib/auth";
import { createScope, readScopes, revokeScope } from "../../../lib/vapt";
import { writeAuditEvent } from "../../../lib/audit";

/** GET: list scopes (any PrimeSEC role). POST: approve a scope. DELETE: revoke one. Both writes are SOC_Admin only and audited. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => PRIMESEC_ROLES.includes(r))) return res.status(403).json({ error: "A PrimeSEC role is required." });

  if (req.method === "GET") return res.status(200).json({ scopes: await readScopes() });
  if (req.method !== "POST" && req.method !== "DELETE") return res.status(405).json({ error: "Method not allowed" });
  if (!roles.includes("SOC_Admin")) return res.status(403).json({ error: "Only SOC_Admin can approve or revoke assessment scope." });
  if (!originIsAllowed(req)) return res.status(403).json({ error: "Cross-origin request rejected." });

  const actor = { name: session.user?.name ?? null, email: session.user?.email ?? null, roles };

  if (req.method === "DELETE") {
    const id = typeof req.body?.id === "string" ? req.body.id : "";
    if (!/^scope_[A-Za-z0-9_]{1,60}$/.test(id)) return res.status(400).json({ error: "A valid scope id is required." });
    const outcome = await revokeScope(id, actor);
    if (!outcome) return res.status(404).json({ error: "Scope not found." });
    const { scope, changed } = outcome;
    if (changed) {
      await writeAuditEvent({
        action: "vapt_scope_revoked", actor,
        scope: { id: scope.id, name: scope.name, targets: scope.targets, authorizationReference: scope.authorizationReference, expiresAt: scope.expiresAt, includesPublicRanges: scope.includesPublicRanges }
      });
    }
    return res.status(200).json({ scope });
  }

  try {
    const scope = await createScope(req.body ?? {}, actor);
    await writeAuditEvent({
      action: "vapt_scope_approved", actor,
      scope: { id: scope.id, name: scope.name, targets: scope.targets, authorizationReference: scope.authorizationReference, expiresAt: scope.expiresAt, includesPublicRanges: scope.includesPublicRanges }
    });
    return res.status(201).json({ scope });
  } catch (error) {
    return res.status(400).json({ error: (error as Error).message || "Could not create authorized scope." });
  }
}
