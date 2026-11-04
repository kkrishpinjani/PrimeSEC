/**
 * Read-only Wazuh explorer: manager and cluster state, agents and their file-integrity / rootcheck / configuration-assessment
 * results, vulnerabilities, alerts, rules, decoders, groups and MITRE reference data. Port of the Phase II Wazuh connectivity packages.
 *
 * This is NOT a proxy. Each resource is a fixed entry below; the upstream path is built here from validated values and never from
 * caller text, every request is a GET (or an Indexer search), and there is no resource that changes Wazuh or runs active response.
 * An optional WAZUH_AGENT_ALLOWLIST (comma-separated agent ids) restricts every agent-scoped resource, the way the package's
 * tenant-to-agent mapping did; unset means all agents.
 */

export const RESOURCES = [
  "overview", "manager-info", "manager-status", "manager-stats", "cluster-status", "cluster-nodes",
  "agents", "agent", "agent-os", "syscheck", "rootcheck", "sca", "vulnerabilities", "all-vulnerabilities", "alerts",
  "rules", "decoders", "groups", "group-agents", "mitre-techniques", "mitre-groups"
] as const;
export type Resource = (typeof RESOURCES)[number];
const RESOURCE_SET = new Set<string>(RESOURCES);

export class WazuhError extends Error {
  code: "INVALID" | "FORBIDDEN" | "NOT_CONFIGURED" | "UPSTREAM";
  constructor(message: string, code: WazuhError["code"]) {
    super(message);
    this.code = code;
  }
}

export type Args = Record<string, unknown>;
export type Deps = {
  api: (path: string) => Promise<any>;
  indexer: (index: string, body: unknown) => Promise<any>;
  apiConfigured: () => boolean;
  indexerConfigured: () => boolean;
  safeError: (e: unknown) => string;
  env: Record<string, string | undefined>;
};

/* ------------------------------ validation ------------------------------ */

const CONTROL = /[\u0000-\u001f\u007f]/;
const AGENT_STATUS = ["active", "pending", "never_connected", "disconnected"];
const VULN_SEVERITY = ["Critical", "High", "Medium", "Low"];

const int = (v: unknown, label: string, min: number, max: number, dflt: number): number => {
  if (v === undefined || v === null || v === "") return dflt;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new WazuhError(`${label} must be a whole number from ${min} to ${max}.`, "INVALID");
  return n;
};
const str = (v: unknown, label: string, max = 200): string | undefined => {
  if (v === undefined || v === null || v === "") return undefined;
  if (typeof v !== "string" || v.length > max || CONTROL.test(v)) throw new WazuhError(`${label} must be plain text up to ${max} characters.`, "INVALID");
  return v.trim() || undefined;
};
const oneOf = (v: unknown, label: string, allowed: string[]): string | undefined => {
  const s = str(v, label, 40);
  if (s === undefined) return undefined;
  const hit = allowed.find((a) => a.toLowerCase() === s.toLowerCase());
  if (!hit) throw new WazuhError(`${label} must be one of ${allowed.join(", ")}.`, "INVALID");
  return hit;
};
export function agentId(v: unknown): string {
  if (typeof v !== "string" || !/^\d{1,10}$/.test(v)) throw new WazuhError("agent must be a numeric Wazuh agent id such as 001.", "INVALID");
  return v;
}
const groupId = (v: unknown): string => {
  if (typeof v !== "string" || !/^[A-Za-z0-9_.-]{1,128}$/.test(v)) throw new WazuhError("group must be a Wazuh group name (letters, digits, . _ -).", "INVALID");
  return v;
};
const isoTime = (v: unknown, label: string): string | undefined => {
  const s = str(v, label, 40);
  if (s === undefined) return undefined;
  if (Number.isNaN(Date.parse(s))) throw new WazuhError(`${label} must be a date such as 2026-11-01T00:00:00Z.`, "INVALID");
  return new Date(s).toISOString();
};

/** WAZUH_AGENT_ALLOWLIST="001,002" restricts agent-scoped data to those agents. Unset or empty = unrestricted. Agent 000 (the manager) must be listed explicitly. */
export function agentAllowlist(env: Record<string, string | undefined>): Set<string> | null {
  const ids = (env.WAZUH_AGENT_ALLOWLIST ?? "").split(",").map((x) => x.trim()).filter(Boolean);
  return ids.length ? new Set(ids) : null;
}
const inScope = (allow: Set<string> | null, id: unknown) => allow === null || allow.has(String(id));
const q = (params: Record<string, string | number | undefined>) => {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined) u.set(k, String(v));
  const s = u.toString();
  return s ? `?${s}` : "";
};

/* ------------------------------ request building ------------------------------ */

type ApiPlan = { kind: "api"; path: string; scopeItems?: boolean; agentFirst?: boolean };
type IndexerPlan = { kind: "indexer"; index: string; body: unknown; map: "alerts" | "vulns" };
export type Plan = ApiPlan | IndexerPlan | { kind: "overview" };

export function buildPlan(resource: unknown, a: Args, env: Record<string, string | undefined> = {}): Plan {
  if (typeof resource !== "string" || !RESOURCE_SET.has(resource)) throw new WazuhError(`resource must be one of ${RESOURCES.join(", ")}.`, "INVALID");
  const allow = agentAllowlist(env);
  const limit = int(a.limit, "limit", 1, 500, 100);
  const offset = int(a.offset, "offset", 0, 1_000_000, 0);
  const search = str(a.search, "search");
  const agentScoped = () => {
    const id = agentId(a.agent);
    if (!inScope(allow, id)) throw new WazuhError("That agent is outside the configured scope.", "FORBIDDEN");
    return id;
  };
  switch (resource as Resource) {
    case "overview": return { kind: "overview" };
    case "manager-info": return { kind: "api", path: "/manager/info" };
    case "manager-status": return { kind: "api", path: "/manager/status" };
    case "manager-stats": return { kind: "api", path: "/manager/stats" };
    case "cluster-status": return { kind: "api", path: "/cluster/status" };
    case "cluster-nodes": return { kind: "api", path: "/cluster/nodes" };
    case "agents": return { kind: "api", scopeItems: true, path: `/agents${q({ limit, offset, status: oneOf(a.status, "status", AGENT_STATUS), q: str(a.q, "q"), search, sort: "id" })}` };
    case "agent": return { kind: "api", path: `/agents${q({ agents_list: agentScoped(), limit: 1 })}` };
    case "agent-os": return { kind: "api", path: `/syscollector/${agentScoped()}/os` };
    case "syscheck": return { kind: "api", path: `/syscheck/${agentScoped()}${q({ limit, offset, file: str(a.path, "path", 500) })}` };
    case "rootcheck": return { kind: "api", path: `/rootcheck/${agentScoped()}${q({ limit, offset })}` };
    case "sca": return { kind: "api", path: `/sca/${agentScoped()}${q({ limit, offset })}` };
    case "rules": return { kind: "api", path: `/rules${q({ limit, offset, search, q: str(a.q, "q") })}` };
    case "decoders": return { kind: "api", path: `/decoders${q({ limit, offset, search })}` };
    case "groups": return { kind: "api", path: `/groups${q({ limit, offset, search })}` };
    case "group-agents": return { kind: "api", scopeItems: true, path: `/groups/${groupId(a.group)}/agents${q({ limit, offset })}` };
    case "mitre-techniques": return { kind: "api", path: `/mitre/techniques${q({ limit, offset, search })}` };
    case "mitre-groups": return { kind: "api", path: `/mitre/groups${q({ limit, offset, search })}` };
    case "vulnerabilities":
    case "all-vulnerabilities": {
      // Wazuh 4.8+ removed the Manager API vulnerability endpoints; the data lives in the Indexer.
      const filters: unknown[] = [];
      if (resource === "vulnerabilities") filters.push({ term: { "agent.id": agentScoped() } });
      else if (allow) filters.push({ terms: { "agent.id": [...allow] } });
      const severity = oneOf(a.severity, "severity", VULN_SEVERITY);
      if (severity) filters.push({ term: { "vulnerability.severity": severity } });
      return {
        kind: "indexer", map: "vulns", index: env.WAZUH_VULN_INDEX_PATTERN || "wazuh-states-vulnerabilities-*",
        body: { size: limit, from: offset, track_total_hits: true, sort: [{ "vulnerability.score.base": { order: "desc", unmapped_type: "float" } }], query: { bool: { filter: filters.length ? filters : [{ match_all: {} }] } } }
      };
    }
    case "alerts": {
      const filters: unknown[] = [{ range: { "rule.level": { gte: int(a.severityMin, "severityMin", 0, 15, 0) } } }];
      if (allow) filters.push({ terms: { "agent.id": [...allow] } });
      if (a.agent !== undefined && a.agent !== "") filters.push({ term: { "agent.id": agentScoped() } });
      const start = isoTime(a.start, "start"), end = isoTime(a.end, "end");
      if (start || end) filters.push({ range: { timestamp: { ...(start ? { gte: start } : {}), ...(end ? { lte: end } : {}) } } });
      const bool: Record<string, unknown> = { filter: filters };
      if (search) // lenient: a text search across fields of different types (text, keyword, ip) otherwise fails with a 400 on the first mismatch.
      bool.must = [{ simple_query_string: { query: search, fields: ["full_log", "rule.description", "agent.name", "data.*"], lenient: true } }];
      return {
        kind: "indexer", map: "alerts", index: env.WAZUH_ALERT_INDEX_PATTERN || "wazuh-alerts-4.x-*",
        body: { size: limit, from: offset, track_total_hits: true, sort: [{ timestamp: { order: "desc", unmapped_type: "date" } }], query: { bool } }
      };
    }
  }
}

/* ------------------------------ execution ------------------------------ */

export type Result = { resource: string; source: "manager" | "indexer"; readOnly: true; items?: unknown[]; total?: number; data?: unknown; note?: string };
const unwrap = (body: any) => body?.data ?? body;

function mapIndexer(plan: IndexerPlan, body: any): { items: unknown[]; total: number } {
  const hits: any[] = body?.hits?.hits ?? [];
  const total = Number(body?.hits?.total?.value ?? body?.hits?.total ?? hits.length);
  if (plan.map === "alerts") {
    return { total, items: hits.map((h) => { const s = h._source ?? {}; return { id: h._id, timestamp: s.timestamp ?? null, level: s.rule?.level ?? null, ruleId: s.rule?.id ?? null, description: s.rule?.description ?? "", groups: s.rule?.groups ?? [], mitre: s.rule?.mitre?.id ?? [], agent: { id: s.agent?.id ?? null, name: s.agent?.name ?? null }, sourceIp: s.data?.srcip ?? null }; }) };
  }
  return { total, items: hits.map((h) => { const s = h._source ?? {}; const v = s.vulnerability ?? {}; return { cve: v.id ?? null, severity: v.severity ?? null, score: v.score?.base ?? null, status: v.status ?? null, package: s.package?.name ?? null, version: s.package?.version ?? null, detectedAt: v.detected_at ?? null, agent: { id: s.agent?.id ?? null, name: s.agent?.name ?? null } }; }) };
}

export async function explore(resource: unknown, args: Args, deps: Deps): Promise<Result> {
  const plan = buildPlan(resource, args, deps.env);
  const allow = agentAllowlist(deps.env);
  const name = String(resource);
  try {
    if (plan.kind === "overview") {
      if (!deps.apiConfigured()) throw new WazuhError("The Wazuh Manager API is not configured (WAZUH_API_URL and credentials).", "NOT_CONFIGURED");
      const [info, summary, agents] = await Promise.allSettled([deps.api("/manager/info"), deps.api("/agents/summary/status"), deps.api("/agents?limit=500&sort=id")]);
      const list = agents.status === "fulfilled" ? ((unwrap(agents.value)?.affected_items ?? []) as any[]).filter((x) => inScope(allow, x.id)) : [];
      return {
        resource: name, source: "manager", readOnly: true,
        data: { manager: info.status === "fulfilled" ? unwrap(info.value)?.affected_items?.[0] ?? null : null, agentSummary: summary.status === "fulfilled" ? unwrap(summary.value) : null, agentCount: list.length, scopeRestricted: allow !== null },
        items: list.map((x) => ({ id: x.id, name: x.name, status: x.status, ip: x.ip ?? null, os: x.os?.name ?? null, version: x.version ?? null, groups: x.group ?? [] })), total: list.length,
        note: [info, summary, agents].some((r) => r.status === "rejected") ? "Part of the overview could not be read." : undefined
      };
    }
    if (plan.kind === "indexer") {
      if (!deps.indexerConfigured()) throw new WazuhError("The Wazuh Indexer is not configured (WAZUH_INDEXER_URL and credentials).", "NOT_CONFIGURED");
      const { items, total } = mapIndexer(plan, await deps.indexer(plan.index, plan.body));
      return { resource: name, source: "indexer", readOnly: true, items, total };
    }
    if (!deps.apiConfigured()) throw new WazuhError("The Wazuh Manager API is not configured (WAZUH_API_URL and credentials).", "NOT_CONFIGURED");
    let data: any;
    try {
      data = unwrap(await deps.api(plan.path));
    } catch (error) {
      // A standalone manager answers cluster node queries with 400: that means "no cluster", not "broken".
      if (name === "cluster-nodes" && /\(400\)/.test(String((error as Error)?.message))) return { resource: name, source: "manager", readOnly: true, items: [], total: 0, note: "This Wazuh manager is not part of a cluster." };
      throw error;
    }
    if (Array.isArray(data?.affected_items)) {
      let items: any[] = data.affected_items;
      if (plan.scopeItems && allow) items = items.filter((x) => inScope(allow, x.id));
      // A single-agent lookup must come back as that agent or nothing.
      return { resource: name, source: "manager", readOnly: true, items, total: plan.scopeItems && allow ? items.length : Number(data.total_affected_items ?? items.length) };
    }
    return { resource: name, source: "manager", readOnly: true, data };
  } catch (error) {
    if (error instanceof WazuhError) throw error;
    throw new WazuhError(deps.safeError(error), "UPSTREAM");
  }
}
