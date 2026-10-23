import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, PRIMESEC_ROLES } from "../../../lib/auth";
import { allowRequest } from "../../../lib/rateLimit";

type ServiceState = { name: string; state: "connected" | "degraded" | "unavailable" | "not_configured"; latencyMs: number | null; message: string };

const trim = (v: string | undefined, fallback: string) => (v || fallback).trim().replace(/\/+$/, "");

/** GET a health endpoint with a short timeout. Reports only state and latency: never the URL, headers or body. */
async function check(name: string, url: string | null): Promise<ServiceState> {
  if (!url) return { name, state: "not_configured", latencyMs: null, message: "Endpoint is not configured." };
  const started = Date.now();
  try {
    const response = await fetch(url, { cache: "no-store", redirect: "error", signal: AbortSignal.timeout(2500) });
    return { name, state: response.ok ? "connected" : "degraded", latencyMs: Date.now() - started, message: response.ok ? "Health endpoint responded." : `Health endpoint returned HTTP ${response.status}.` };
  } catch (error) {
    const timedOut = (error as Error)?.name === "TimeoutError";
    return { name, state: "unavailable", latencyMs: Date.now() - started, message: timedOut ? "Health check timed out." : "Health endpoint could not be reached." };
  }
}

type AlertSummary = { available: boolean; firing: number; pending: number; items: { name: string; severity: string; state: string }[] };

/** Active alerts from Prometheus. Only the rule name, severity and state are returned (never labels that could hold data). */
async function readAlerts(base: string): Promise<AlertSummary> {
  const none: AlertSummary = { available: false, firing: 0, pending: 0, items: [] };
  try {
    const response = await fetch(`${base}/api/v1/alerts`, { cache: "no-store", redirect: "error", signal: AbortSignal.timeout(2500) });
    if (!response.ok) return none;
    const body = (await response.json()) as { data?: { alerts?: { labels?: Record<string, string>; state?: string }[] } };
    const items = (body.data?.alerts ?? []).slice(0, 20).map((a) => ({
      name: String(a.labels?.alertname ?? "").slice(0, 80), severity: String(a.labels?.severity ?? "").slice(0, 20), state: a.state === "firing" ? "firing" : "pending"
    }));
    return { available: true, firing: items.filter((i) => i.state === "firing").length, pending: items.filter((i) => i.state === "pending").length, items };
  } catch {
    return none;
  }
}

/** Reachability of the local telemetry stack (any PrimeSEC role). It cannot show that data is flowing end to end. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => PRIMESEC_ROLES.includes(r))) return res.status(403).json({ error: "A PrimeSEC role is required." });
  // Each call makes five outbound requests, so it is rate-limited per user.
  if (!allowRequest(`observe-health:${session.user?.email || session.user?.name || "unknown"}`, 30, 60_000)) {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({ error: "Too many health checks. Wait a minute and try again." });
  }
  const prometheus = trim(process.env.PROMETHEUS_URL, "http://127.0.0.1:9090");
  const [services, alerts] = await Promise.all([
    Promise.all([
      check("OpenTelemetry Collector", trim(process.env.OTEL_COLLECTOR_HEALTH_URL, "http://127.0.0.1:13133")),
      check("Jaeger", `${trim(process.env.JAEGER_QUERY_URL, "http://127.0.0.1:16686")}/api/services`),
      check("Prometheus", `${prometheus}/-/healthy`),
      check("Grafana", `${trim(process.env.GRAFANA_URL, "http://127.0.0.1:3001")}/api/health`)
    ]),
    readAlerts(prometheus)
  ]);
  return res.status(200).json({
    checkedAt: new Date().toISOString(),
    service: process.env.OTEL_SERVICE_NAME || "primesec-web",
    telemetryEnabled: process.env.OTEL_ENABLED === "true",
    alerts,
    services
  });
}
