import type { NextApiRequest, NextApiResponse } from "next";
import { agentGuard } from "../../../lib/agentApi";
import { isLaunchPlatform, launch, LaunchError } from "../../../lib/launch";
import { writeAuditEvent } from "../../../lib/audit";
import { allowRequest } from "../../../lib/rateLimit";
import { logError } from "../../../lib/log";

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const page = (res: NextApiResponse, status: number, title: string, text: string) =>
  res.status(status).setHeader("Content-Type", "text/html; charset=utf-8").send(
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><body style="font:15px system-ui;background:#040d0d;color:#ecfdfa;max-width:36rem;margin:12vh auto;padding:0 16px"><h1 style="font-size:1.2rem">${esc(title)}</h1><p style="color:#9fc3bf">${esc(text)}</p><p><a style="color:#5eead4" href="/dashboard">Back to the dashboard</a></p>`
  );

/**
 * GET /api/launch/<opencti|wazuh|greenbone|neo4j>: signs the administrator into that platform and redirects to it.
 * SOC_Admin only (the stored account is a platform administrator), only from a navigation that began on PrimeSEC or by hand,
 * rate limited, and every use is audited. See lib/launch.ts.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return res.status(405).json({ error: "Method not allowed" }); }
  const site = req.headers["sec-fetch-site"];
  if (site && site !== "same-origin" && site !== "none") return res.status(403).json({ error: "Cross-site request rejected." });
  const ctx = await agentGuard(req, res, "admin");
  if (!ctx) return;
  const platform = req.query.platform;
  if (!isLaunchPlatform(platform)) return page(res, 404, "Unknown platform", "That platform is not one PrimeSEC can open.");
  if (!allowRequest(`launch:${ctx.actor.email ?? ctx.actor.name ?? "anon"}`, 20, 60_000)) return page(res, 429, "Slow down", "Too many launches in a minute. Try again shortly.");
  try {
    const result = await launch(platform);
    await writeAuditEvent({ action: "platform_launch", actor: ctx.actor, platform, outcome: "opened" });
    if (result.cookies.length) res.setHeader("Set-Cookie", result.cookies);
    res.setHeader("Referrer-Policy", "no-referrer");
    return res.redirect(302, result.location);
  } catch (error) {
    const known = error instanceof LaunchError;
    if (!known) logError("platform launch", error);
    await writeAuditEvent({ action: "platform_launch", actor: ctx.actor, platform, outcome: "failed", reason: known ? error.message : "unexpected error" }).catch(() => undefined);
    return known && error.code === "UNAVAILABLE"
      ? page(res, 503, "Not set up yet", error.message)
      : page(res, 502, "Could not sign in", known ? `${error.message} Check that the platform is running (scripts\stacks.ps1 status).` : "Something went wrong while opening the platform.");
  }
}
