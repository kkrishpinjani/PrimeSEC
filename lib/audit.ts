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

export type VaptAssessmentEvent = Base & {
  action: "vapt_assessment_started" | "vapt_assessment_denied";
  target: string;
  /** Why a launch was refused (denied events only). */
  reason?: string;
  scopeId?: string;
  assessment?: { taskId: string; targetId: string; targetName: string; status: string };
};

export type AuditEvent = InvestigationEvent | VaptScopeEvent | VaptAssessmentEvent;
export type AuditAction = AuditEvent["action"];

/** Input for writeAuditEvent: everything except the fields the writer assigns. */
export type AuditInput =
  | Omit<InvestigationEvent, "eventId" | "timestamp">
  | Omit<VaptScopeEvent, "eventId" | "timestamp">
  | Omit<VaptAssessmentEvent, "eventId" | "timestamp">;

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

/** Newest first, optionally only the given actions. Unparseable lines are skipped, never thrown. */
export async function readAuditEvents(limit = 25, actions?: AuditAction[]): Promise<AuditEvent[]> {
  const n = Math.min(Math.max(Math.floor(limit) || 25, 1), 100);
  try {
    const content = await fs.readFile(auditPath(), "utf8");
    const events = content
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        try { return JSON.parse(line) as AuditEvent; } catch { return null; }
      })
      .filter((e): e is AuditEvent => e !== null && (!actions || actions.includes(e.action)));
    return events.slice(-n).reverse();
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return [];
    throw error;
  }
}
