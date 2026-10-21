import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed, PRIMESEC_ROLES } from "../../../lib/auth";
import { createScope, deleteScope, readScopes, revokeScope, type VaptScope } from "../../../lib/vapt";
import { writeAuditEvent } from "../../../lib/audit";
import { logError } from "../../../lib/log";

const scopeAudit = (s: VaptScope) => ({
  id: s.id, name: s.name, targets: s.targets, authorizationReference: s.authorizationReference, expiresAt: s.expiresAt, includesPublicRanges: s.includesPublicRanges
});

/** GET: list scopes (any PrimeSEC role). POST: approve a scope. DELETE: revoke one. Both writes are SOC_Admin only and audited. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => PRIMESEC_ROLES.includes(r))) return res.status(403).json({ error: "A PrimeSEC role is required." });

  if (req.method === "GET") {
    try {
      return res.status(200).json({ scopes: await readScopes() });
    } catch (error) {
      logError("vapt scopes: reading scope store", error);
      return res.status(500).json({ error: "The scope store is unavailable." });
    }
  }
  if (req.method !== "POST" && req.method !== "DELETE") return res.status(405).json({ error: "Method not allowed" });
  if (!roles.includes("SOC_Admin")) return res.status(403).json({ error: "Only SOC_Admin can approve or revoke assessment scope." });
  if (!originIsAllowed(req)) return res.status(403).json({ error: "Cross-origin request rejected." });

  const actor = { name: session.user?.name ?? null, email: session.user?.email ?? null, roles };

  if (req.method === "DELETE") {
    const id = typeof req.body?.id === "string" ? req.body.id : "";
    if (!/^scope_[A-Za-z0-9_]{1,60}$/.test(id)) return res.status(400).json({ error: "A valid scope id is required." });
    try {
      const outcome = await revokeScope(id, actor);
      if (!outcome) return res.status(404).json({ error: "Scope not found." });
      let auditRecorded = true;
      if (outcome.changed) {
        // The revocation has already taken effect (the safe direction), so a failed audit write is reported, not undone.
        try {
          await writeAuditEvent({ action: "vapt_scope_revoked", actor, scope: scopeAudit(outcome.scope) });
        } catch (error) {
          auditRecorded = false;
          logError("vapt scopes: scope revoked but the audit write failed", error);
        }
      }
      return res.status(200).json({ scope: outcome.scope, auditRecorded });
    } catch (error) {
      logError("vapt scopes: revoke failed", error);
      return res.status(500).json({ error: "The scope store is unavailable." });
    }
  }

  let scope: VaptScope;
  try {
    scope = await createScope(req.body ?? {}, actor);
  } catch (error) {
    // createScope throws readable validation messages; anything else is a storage problem.
    const message = (error as Error).message || "";
    if ((error as NodeJS.ErrnoException).code) {
      logError("vapt scopes: storing a scope", error);
      return res.status(500).json({ error: "The scope store is unavailable." });
    }
    return res.status(400).json({ error: message || "Could not create authorized scope." });
  }
  try {
    await writeAuditEvent({ action: "vapt_scope_approved", actor, scope: scopeAudit(scope) });
  } catch (error) {
    // An approval without an audit record must not stay live: roll it back.
    logError("vapt scopes: audit failed, rolling the approval back", error);
    await deleteScope(scope.id).catch((e) => logError("vapt scopes: rollback failed", e));
    return res.status(503).json({ error: "The audit log is unavailable, so the scope was not approved." });
  }
  return res.status(201).json({ scope });
}
