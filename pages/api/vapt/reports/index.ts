import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions, PRIMESEC_ROLES } from "../../../../lib/auth";
import { readSnapshots } from "../../../../lib/reports";
import { logError } from "../../../../lib/log";

/** The imported Greenbone report snapshots (summary only), newest first. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  const roles = session.user?.roles ?? [];
  if (!roles.some((r) => PRIMESEC_ROLES.includes(r))) return res.status(403).json({ error: "A PrimeSEC role is required." });
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  try {
    const reports = (await readSnapshots())
      .map((s) => ({
        reportId: s.reportId, capturedAt: s.capturedAt, reportTime: s.reportTime, status: s.status, complete: s.complete,
        completenessSource: s.completenessSource, taskName: s.taskName, findingCount: s.findings.length,
        hostsScanned: s.scannedHosts ? s.scannedHosts.length : null
      }))
      .sort((a, b) => String(b.reportTime ?? b.capturedAt).localeCompare(String(a.reportTime ?? a.capturedAt)));
    return res.status(200).json({ reports });
  } catch (error) {
    logError("report snapshots", error);
    return res.status(500).json({ error: "Could not read report snapshots." });
  }
}
