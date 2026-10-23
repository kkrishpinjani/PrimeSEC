/**
 * Greenbone report snapshots and baseline/retest comparison.
 *
 * Comparison answers one question: "is this baseline finding still present in a later report?". It reports
 * FIXED only when it can PROVE absence, and it never closes a finding by itself.
 *
 *   STILL_PRESENT  the same finding (same host, port and NVT) is in the retest report.
 *   FIXED          absent from a report that Greenbone marked finished AND that demonstrably scanned this host.
 *   INCONCLUSIVE   absent, but that cannot be trusted: the report is not marked finished, the host is not confirmed
 *                  scanned (a host that was down also yields a finished report with no results), or the import
 *                  was capped. Absence is then NOT evidence of a fix.
 */
import { promises as fs } from "fs";
import path from "path";
import { normalizeFinding, type RawFinding } from "./findings.ts";

export type SnapshotFinding = { id: string; host: string; port: string; oid: string; name: string; cves: string[]; severityScore: number; severity: string };
export type ReportSnapshot = {
  reportId: string;
  capturedAt: string;
  /** Time Greenbone gives for the report, when it gives one. */
  reportTime: string | null;
  /** Greenbone's own scan status for the report ("Done", "Running", "Interrupted", "Unknown"...). */
  status: string;
  /** True only if the bridge confirmed the report finished AND the import was not capped. Never downgraded once true. */
  complete: boolean;
  completenessSource: string;
  /** Hosts that have a finished entry in the report; null when the bridge could not tell (then absence is inconclusive). */
  scannedHosts: string[] | null;
  taskName: string;
  findings: SnapshotFinding[];
};

export type BridgeReportMeta = { id?: unknown; status?: unknown; scannedHosts?: unknown; timestamp?: unknown };
export type CaptureMeta = { reports?: BridgeReportMeta[]; completedReports?: unknown; truncated?: boolean; now?: string };

export type Outcome = "STILL_PRESENT" | "FIXED" | "INCONCLUSIVE";
export type Reason = "present-in-retest" | "complete-and-host-scanned" | "report-not-complete" | "host-not-confirmed-scanned" | "import-truncated";
export type ComparedFinding = { finding: SnapshotFinding; outcome: Outcome; reason: Reason; explanation: string; retestSeverityScore: number | null };
export type Comparison = {
  baselineReportId: string;
  retestReportId: string;
  baselineCapturedAt: string;
  retestCapturedAt: string;
  baselineComplete: boolean;
  retestComplete: boolean;
  warnings: string[];
  results: ComparedFinding[];
  /** In the retest report but not in the baseline: something new (or a regression). */
  newInRetest: SnapshotFinding[];
  summary: { fixed: number; stillPresent: number; inconclusive: number; new: number };
};

const MAX_SNAPSHOTS = 200;
const storePath = () => path.join(process.cwd(), "data", "vapt-report-snapshots.json");
const lc = (v: string) => v.trim().toLowerCase();

let chain: Promise<unknown> = Promise.resolve();
function withStore<T>(fn: (items: ReportSnapshot[]) => Promise<{ items: ReportSnapshot[]; result: T }>): Promise<T> {
  const run = chain.then(async () => {
    const { items, result } = await fn(await readSnapshots());
    await fs.mkdir(path.dirname(storePath()), { recursive: true });
    const temp = `${storePath()}.${process.pid}.tmp`;
    await fs.writeFile(temp, JSON.stringify(items, null, 2), { mode: 0o600 });
    await fs.rename(temp, storePath());
    return result;
  });
  chain = run.catch(() => undefined);
  return run;
}

export async function readSnapshots(): Promise<ReportSnapshot[]> {
  try {
    const value = JSON.parse(await fs.readFile(storePath(), "utf8"));
    return Array.isArray(value) ? (value as ReportSnapshot[]) : [];
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return [];
    throw error;
  }
}

/**
 * Records one snapshot per Greenbone report seen in an import. A report that has metadata but no results (a clean scan)
 * still gets a snapshot, so "nothing found" can be compared. A snapshot that is already complete is frozen: a finished
 * report does not change, and a later partial read must not weaken it.
 */
export async function captureSnapshots(raws: RawFinding[], meta: CaptureMeta = {}): Promise<{ captured: number }> {
  const now = meta.now ?? new Date().toISOString();
  const completed = new Set(Array.isArray(meta.completedReports) ? (meta.completedReports as unknown[]).map(String) : []);
  const byReport = new Map<string, { findings: Map<string, SnapshotFinding>; taskName: string }>();
  const group = (id: string) => { let g = byReport.get(id); if (!g) byReport.set(id, (g = { findings: new Map(), taskName: "" })); return g; };

  for (const raw of raws) {
    const f = normalizeFinding(raw, now);
    if (!f.reportId) continue; // no report id, no snapshot: nothing to anchor a comparison to
    const g = group(f.reportId);
    g.taskName = g.taskName || f.taskName;
    const prev = g.findings.get(f.id);
    if (!prev || f.severityScore > prev.severityScore) {
      g.findings.set(f.id, { id: f.id, host: f.host, port: f.port, oid: f.oid, name: f.name, cves: f.cves, severityScore: f.severityScore, severity: f.severity });
    }
  }
  const metaById = new Map<string, BridgeReportMeta>();
  for (const m of meta.reports ?? []) {
    const id = String(m.id ?? "").trim();
    if (!id) continue;
    metaById.set(id, m);
    group(id); // a report with metadata but no results is still a report
  }

  return withStore(async (stored) => {
    const merged = new Map(stored.map((s) => [s.reportId, s]));
    let captured = 0;
    for (const [reportId, g] of byReport) {
      const m = metaById.get(reportId);
      const status = String(m?.status ?? "Unknown");
      const hosts = Array.isArray(m?.scannedHosts) ? (m!.scannedHosts as unknown[]).map((h) => String(h).trim()).filter(Boolean) : null;
      const complete = !meta.truncated && completed.has(reportId);
      const next: ReportSnapshot = {
        reportId,
        capturedAt: merged.get(reportId)?.capturedAt ?? now,
        reportTime: typeof m?.timestamp === "string" && m.timestamp ? m.timestamp : null,
        status,
        complete,
        completenessSource: meta.truncated
          ? "Import was capped: results may be missing, so the report cannot be called complete"
          : complete ? "Greenbone reports this scan as Done" : m ? `Greenbone reports status "${status}"` : "No completeness metadata from the bridge",
        scannedHosts: hosts,
        taskName: g.taskName,
        findings: [...g.findings.values()]
      };
      const existing = merged.get(reportId);
      if (existing?.complete && !next.complete) continue; // a finished report is frozen
      merged.set(reportId, next);
      captured++;
    }
    let items = [...merged.values()].sort((a, b) => a.capturedAt.localeCompare(b.capturedAt));
    if (items.length > MAX_SNAPSHOTS) items = items.slice(items.length - MAX_SNAPSHOTS);
    return { items, result: { captured } };
  });
}

export async function clearSnapshots(): Promise<number> {
  return withStore<number>(async (items) => ({ items: [], result: items.length }));
}

/** Pure comparison (no storage), so every rule can be tested directly. */
export function compareSnapshots(baseline: ReportSnapshot, retest: ReportSnapshot): Comparison {
  const retestById = new Map(retest.findings.map((f) => [f.id, f]));
  const baselineIds = new Set(baseline.findings.map((f) => f.id));
  const scanned = retest.scannedHosts ? new Set(retest.scannedHosts.map(lc)) : null;

  const results: ComparedFinding[] = baseline.findings.map((finding) => {
    const present = retestById.get(finding.id);
    if (present) {
      return { finding, outcome: "STILL_PRESENT", reason: "present-in-retest", explanation: "The same finding (host, port and vulnerability test) appears in the retest report.", retestSeverityScore: present.severityScore };
    }
    if (!retest.complete) {
      const truncated = retest.completenessSource.startsWith("Import was capped");
      return {
        finding, outcome: "INCONCLUSIVE", reason: truncated ? "import-truncated" : "report-not-complete", retestSeverityScore: null,
        explanation: `Not found in the retest report, but that report is not confirmed complete (${retest.completenessSource}). Absence is not evidence of a fix.`
      };
    }
    if (!scanned || !scanned.has(lc(finding.host))) {
      return {
        finding, outcome: "INCONCLUSIVE", reason: "host-not-confirmed-scanned", retestSeverityScore: null,
        explanation: scanned
          ? `Not found, but ${finding.host} is not among the hosts this report actually scanned (it may have been down or unreachable). A finished scan that never reached a host reports nothing for it.`
          : "Not found, but this report does not say which hosts it scanned, so a host that was down cannot be ruled out."
      };
    }
    return { finding, outcome: "FIXED", reason: "complete-and-host-scanned", retestSeverityScore: null, explanation: "Absent from a report Greenbone marked Done, and the report shows this host was scanned." };
  });

  const newInRetest = retest.findings.filter((f) => !baselineIds.has(f.id));
  const warnings: string[] = [];
  const t = (s: ReportSnapshot) => Date.parse(s.reportTime ?? s.capturedAt);
  if (Number.isFinite(t(baseline)) && Number.isFinite(t(retest)) && t(retest) < t(baseline)) {
    warnings.push("The retest report is older than the baseline report. Check you picked them in the right order.");
  }
  if (!baseline.complete) warnings.push("The baseline report is not confirmed complete, so it may not list every finding that existed.");
  return {
    baselineReportId: baseline.reportId, retestReportId: retest.reportId,
    baselineCapturedAt: baseline.capturedAt, retestCapturedAt: retest.capturedAt,
    baselineComplete: baseline.complete, retestComplete: retest.complete,
    warnings, results, newInRetest,
    summary: {
      fixed: results.filter((r) => r.outcome === "FIXED").length,
      stillPresent: results.filter((r) => r.outcome === "STILL_PRESENT").length,
      inconclusive: results.filter((r) => r.outcome === "INCONCLUSIVE").length,
      new: newInRetest.length
    }
  };
}

export class CompareError extends Error {
  code: "INVALID" | "NOT_FOUND";
  constructor(message: string, code: "INVALID" | "NOT_FOUND") {
    super(message);
    this.code = code;
  }
}

export async function compareReports(baselineId: unknown, retestId: unknown): Promise<Comparison> {
  const a = String(baselineId ?? "").trim(), b = String(retestId ?? "").trim();
  if (!a || !b || a === b) throw new CompareError("Choose two different reports.", "INVALID");
  const snaps = await readSnapshots();
  const baseline = snaps.find((s) => s.reportId === a), retest = snaps.find((s) => s.reportId === b);
  if (!baseline || !retest) throw new CompareError("Both reports must have been imported. Sync Greenbone findings after each scan, then compare.", "NOT_FOUND");
  return compareSnapshots(baseline, retest);
}
