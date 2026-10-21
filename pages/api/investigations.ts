import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, originIsAllowed, PRIMESEC_ROLES } from "../../lib/auth";
import { getWazuhAlertById, searchOpenCtiIndicators } from "../../lib/integrations";
import { correlate, extractObservables, MAX_OBSERVABLES } from "../../lib/correlation";
import { readAuditEvents, writeAuditEvent } from "../../lib/audit";
import { allowRequest } from "../../lib/rateLimit";
import { logError } from "../../lib/log";

const INVESTIGATOR_ROLES = ["SOC_Admin", "SOC_Analyst"];
// Wazuh/OpenSearch document ids: short, URL-safe. Anything else is rejected before it reaches an upstream query.
const ALERT_ID = /^[A-Za-z0-9_\-:.]{1,200}$/;

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

  const alertId = typeof req.body?.alertId === "string" ? req.body.alertId : "";
  if (!alertId) return res.status(400).json({ error: "alertId is required." });
  if (!ALERT_ID.test(alertId)) return res.status(400).json({ error: "alertId is not a valid Wazuh alert id." });

  try {
    // The alert is always re-read from Wazuh: the browser never supplies alert contents.
    let detail;
    try {
      detail = await getWazuhAlertById(alertId);
    } catch (error) {
      if ((error as { code?: string })?.code === "NOT_CONFIGURED") {
        return res.status(409).json({ error: "The Wazuh Indexer is not configured, so alerts cannot be investigated." });
      }
      throw error;
    }
    if (!detail) return res.status(404).json({ error: "Alert not found in Wazuh. Refresh and try again." });

    const observables = extractObservables(detail.text).slice(0, MAX_OBSERVABLES);
    const cti = await searchOpenCtiIndicators(observables.map((o) => o.value));
    const correlation = correlate(detail.text, cti.indicators);

    const event = await writeAuditEvent({
      action: "alert_investigation_created",
      actor: { name: session.user?.name ?? null, email: session.user?.email ?? null, roles },
      alert: { ...detail.alert },
      openCti: { connected: cti.connected && cti.configured, searched: observables.length },
      correlation: {
        matchCount: correlation.matchCount,
        matchedIndicators: correlation.matches.map((m) => ({ id: m.indicatorId, name: m.indicatorName, matchedValue: m.matchedValue }))
      }
    });

    return res.status(200).json({
      investigationId: event.eventId,
      createdAt: event.timestamp,
      alert: detail.alert,
      openCti: { configured: cti.configured, connected: cti.connected, message: cti.message },
      correlation
    });
  } catch (error) {
    logError("investigation failed", error);
    return res.status(502).json({ error: "Investigation could not be completed. Check integration health and server logs." });
  }
}
