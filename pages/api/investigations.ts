import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed, PRIMESEC_ROLES } from "../../lib/auth";
import { investigateAlert, InvestigateError } from "../../lib/investigate";
import { readAuditEvents, writeAuditEvent } from "../../lib/audit";
import { allowRequest } from "../../lib/rateLimit";
import { logError } from "../../lib/log";

const INVESTIGATOR_ROLES = ["SOC_Admin", "SOC_Analyst"];

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");

  const roles = Array.isArray(session.user?.roles) ? session.user.roles : [];
  if (!roles.some((r) => PRIMESEC_ROLES.includes(r))) return res.status(403).json({ error: "A PrimeSEC role is required." });

  if (req.method === "GET") {
    try {
      return res.status(200).json({ events: await readAuditEvents(25, ["alert_investigation_created"]) });
    } catch (error) {
      logError("investigations: reading audit events", error);
      return res.status(500).json({ error: "Could not read audit events." });
    }
  }
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  if (!roles.some((r) => INVESTIGATOR_ROLES.includes(r))) {
    return res.status(403).json({ error: "SOC_Analyst or SOC_Admin role required to create an investigation." });
  }
  if (!originIsAllowed(req)) return res.status(403).json({ error: "Cross-origin request rejected." });

  const actorKey = session.user?.email || session.user?.name || "unknown";
  if (!allowRequest(`investigate:${actorKey}`, 10, 60_000)) {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({ error: "Too many investigations. Wait a minute and try again." });
  }

  try {
    // The alert is always re-read from Wazuh: the browser never supplies alert contents.
    let result;
    try {
      result = await investigateAlert(req.body?.alertId);
    } catch (error) {
      if (error instanceof InvestigateError) return res.status(error.code === "INVALID" ? 400 : error.code === "NOT_FOUND" ? 404 : 409).json({ error: error.message });
      throw error;
    }
    const { alert, searched, openCti, correlation, vulnerabilities, techniques } = result;

    const event = await writeAuditEvent({
      action: "alert_investigation_created",
      actor: { name: session.user?.name ?? null, email: session.user?.email ?? null, roles },
      alert: { ...alert },
      openCti: { connected: openCti.connected && openCti.configured, searched },
      correlation: {
        matchCount: correlation.matchCount,
        matchedIndicators: correlation.matches.map((m) => ({ id: m.indicatorId, name: m.indicatorName, matchedValue: m.matchedValue }))
      }
    });

    return res.status(200).json({
      investigationId: event.eventId,
      createdAt: event.timestamp,
      alert,
      openCti,
      correlation,
      vulnerabilities,
      techniques
    });
  } catch (error) {
    logError("investigation failed", error);
    return res.status(502).json({ error: "Investigation could not be completed. Check integration health and server logs." });
  }
}
