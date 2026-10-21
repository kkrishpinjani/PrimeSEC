import { promises as fs } from "fs";
import path from "path";

/**
 * Local JSON Lines audit trail (development MVP). Not tamper-proof: replace with a durable,
 * append-only store before production. The file lives in ./data, which is git-ignored.
 */
export type AuditActor = { name: string | null; email: string | null; roles: string[] };

type Base = { eventId: string; timestamp: string; actor: AuditActor };

export type InvestigationEvent = Base & {
  action: "alert_investigation_created";
  alert: { id: string; level: number; description: string; agent: string; timestamp: string | null; sourceIp: string };
  openCti: { connected: boolean; searched: number };
  correlation: { matchCount: number; matchedIndicators: { id: string; name: string; matchedValue: string }[] };
};

export type VaptScopeEvent = Base & {
  action: "vapt_scope_approved" | "vapt_scope_revoked";
  scope: { id: string; name: string; targets: string[]; authorizationReference: string; expiresAt: string; includesPublicRanges: boolean };
};

/**
 * A launch writes `requested` BEFORE Greenbone is called (the audit must exist even if the call
 * times out), then `started` or `failed`. `denied` is a refused attempt.
 */
export type VaptAssessmentEvent = Base & {
  action: "vapt_assessment_requested" | "vapt_assessment_started" | "vapt_assessment_failed" | "vapt_assessment_denied";
  target: string;
  /** Why a launch was refused or failed. */
  reason?: string;
  scopeId?: string;
  /** Set when the scan is a retest of a finding. */
  findingId?: string;
  assessment?: { taskId: string; targetId: string; targetName: string; status: string };
};

/** Findings workflow. Notes are never copied into the audit log: only which fields changed. */
export type VaptFindingEvent = Base & (
  | { action: "vapt_findings_synchronized"; imported: number; updated: number; missing: number; total: number; truncated: boolean }
  | { action: "vapt_finding_updated"; finding: { id: string; host: string; port: string; name: string; cves: string[] }; changes: string[]; status: { from: string; to: string } }
  | { action: "vapt_finding_retest_requested"; finding: { id: string; host: string; port: string; name: string }; target: string; taskId: string | null }
);

export type AuditEvent = InvestigationEvent | VaptScopeEvent | VaptAssessmentEvent | VaptFindingEvent;
export type AuditAction = AuditEvent["action"];

/** Input for writeAuditEvent: everything except the fields the writer assigns. */
// Distributes over the union so each event keeps its own shape (a plain Omit on a union would collapse it).
type Unwrap<T> = T extends unknown ? Omit<T, "eventId" | "timestamp"> : never;
export type AuditInput = Unwrap<AuditEvent>;

const auditPath = () => path.join(process.cwd(), "data", "audit-events.jsonl");

export async function writeAuditEvent(event: AuditInput): Promise<AuditEvent> {
  const record = {
    eventId: `audit_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date().toISOString(),
    ...event
  } as AuditEvent;
  await fs.mkdir(path.dirname(auditPath()), { recursive: true });
  await fs.appendFile(auditPath(), `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600 });
  return record;
}

/**
 * Newest first, optionally only the given actions. Reads the file from the end in chunks and stops as soon
 * as enough events are found, so cost does not grow with the size of the audit file.
 * Unparseable lines are skipped, never thrown.
 */
export async function readAuditEvents(limit = 25, actions?: AuditAction[]): Promise<AuditEvent[]> {
  const n = Math.min(Math.max(Math.floor(limit) || 25, 1), 100);
  let handle: import("fs").promises.FileHandle;
  try {
    handle = await fs.open(auditPath(), "r");
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return [];
    throw error;
  }
  const out: AuditEvent[] = [];
  const take = (line: string) => {
    if (!line.trim()) return;
    try {
      const e = JSON.parse(line) as AuditEvent;
      if (!actions || actions.includes(e.action)) out.push(e);
    } catch { /* skip a corrupt line */ }
  };
  try {
    const { size } = await handle.stat();
    const CHUNK = 64 * 1024;
    let pos = size;
    let carry: Buffer = Buffer.alloc(0); // bytes of a line that continues into the previous chunk
    while (pos > 0 && out.length < n) {
      const len = Math.min(CHUNK, pos);
      pos -= len;
      const chunk = Buffer.alloc(len);
      await handle.read(chunk, 0, len, pos);
      const data = Buffer.concat([chunk, carry]);
      let body: Buffer;
      if (pos > 0) {
        const firstNewline = data.indexOf(0x0a);
        if (firstNewline === -1) { carry = data; continue; }
        carry = data.subarray(0, firstNewline);
        body = data.subarray(firstNewline + 1);
      } else {
        carry = Buffer.alloc(0);
        body = data;
      }
      const lines = body.toString("utf8").split("\n");
      for (let i = lines.length - 1; i >= 0 && out.length < n; i--) take(lines[i]);
    }
  } finally {
    await handle.close();
  }
  return out.slice(0, n);
}
