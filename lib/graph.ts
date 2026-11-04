/**
 * Security knowledge graph on Neo4j: assets, vulnerabilities, alerts, indicators and how they connect, for attack-path and
 * exposure questions. Port of the Phase II "Neo4j graph" package, over Neo4j's HTTP transactional API (no driver needed).
 *
 * Safety rules, all enforced in code and covered by tests:
 *  - labels and relationship types are chosen ONLY from the allow-lists below, so a caller can never inject Cypher through them;
 *  - every value travels as a query parameter, never inside the query text;
 *  - every node and every query is constrained by a namespace (`tenant_id`), so one PrimeSEC deployment cannot read another's nodes
 *    in a shared database, and callers cannot overwrite the namespace or identity keys through "properties";
 *  - an upsert is ONE transaction: all of it applies or none of it does.
 * The graph is read-only analysis: nothing here scans, changes a host or triggers a response.
 */
import type { InventoryStore } from "./inventory.ts";
import { CLOSED_STATUSES } from "./inventory.ts";

export const NODE_TYPES = ["Asset", "Vulnerability", "Alert", "Indicator", "ThreatActor", "Technique", "Software", "BusinessApplication", "Identity"] as const;
export const REL_TYPES = ["HAS_VULNERABILITY", "GENERATED_ALERT", "MATCHES_INDICATOR", "ATTRIBUTED_TO", "USES_TECHNIQUE", "RUNS_SOFTWARE", "SUPPORTS_APPLICATION", "HAS_IDENTITY", "CONNECTED_TO", "EXPLOITS"] as const;
export type NodeType = (typeof NODE_TYPES)[number];
export type RelType = (typeof REL_TYPES)[number];
const NODE_SET = new Set<string>(NODE_TYPES);
const REL_SET = new Set<string>(REL_TYPES);

export const MAX_NODES = 1000;
export const MAX_RELS = 3000;
const MAX_ID = 256;
const MAX_STRING = 1000;
const RESERVED_KEYS = new Set(["tenant_id", "external_id", "id"]);

export type GraphNode = { type: string; id: string; properties?: Record<string, unknown> };
export type GraphRel = { sourceType: string; sourceId: string; targetType: string; targetId: string; type: string; properties?: Record<string, unknown> };
export type GraphBatch = { nodes: GraphNode[]; relationships: GraphRel[] };
type Scalar = string | number | boolean | null;

export class GraphError extends Error {
  code: "INVALID" | "NOT_CONFIGURED" | "UNAVAILABLE";
  constructor(message: string, code: GraphError["code"]) {
    super(message);
    this.code = code;
  }
}

/* ------------------------------ validation ------------------------------ */

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isScalar = (v: unknown): v is Scalar => v === null || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v)) || typeof v === "string";
const clip = (v: Scalar): Scalar => (typeof v === "string" ? v.slice(0, MAX_STRING) : v);

/**
 * Neo4j properties must be scalars or flat lists of scalars. Anything else is dropped, as are the reserved identity keys,
 * so a caller cannot reassign a node's namespace or id, and key names are restricted to letters, digits and underscores.
 */
export function safeProperties(props: unknown): Record<string, Scalar | Scalar[]> {
  const out: Record<string, Scalar | Scalar[]> = {};
  if (!isObj(props)) return out;
  for (const [k, v] of Object.entries(props)) {
    if (RESERVED_KEYS.has(k) || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(k)) continue;
    if (isScalar(v)) out[k] = clip(v);
    else if (Array.isArray(v) && v.length <= 100 && v.every((x) => x !== null && isScalar(x))) out[k] = v.map(clip);
  }
  return out;
}

export function validateBatch(raw: unknown): GraphBatch {
  if (!isObj(raw)) throw new GraphError("The request must be an object with nodes and relationships.", "INVALID");
  const nodes = raw.nodes ?? [];
  const rels = raw.relationships ?? [];
  if (!Array.isArray(nodes) || nodes.length > MAX_NODES) throw new GraphError(`nodes must be a list of at most ${MAX_NODES}.`, "INVALID");
  if (!Array.isArray(rels) || rels.length > MAX_RELS) throw new GraphError(`relationships must be a list of at most ${MAX_RELS}.`, "INVALID");
  if (nodes.length === 0 && rels.length === 0) throw new GraphError("Send at least one node or relationship.", "INVALID");
  const idOk = (v: unknown, at: string): string => {
    if (typeof v !== "string" || !v.trim() || v.length > MAX_ID) throw new GraphError(`${at} must be text of 1 to ${MAX_ID} characters.`, "INVALID");
    return v;
  };
  return {
    nodes: nodes.map((n, i) => {
      if (!isObj(n)) throw new GraphError(`nodes[${i}] must be an object.`, "INVALID");
      if (typeof n.type !== "string" || !NODE_SET.has(n.type)) throw new GraphError(`nodes[${i}]: unsupported node type. Allowed: ${NODE_TYPES.join(", ")}.`, "INVALID");
      return { type: n.type, id: idOk(n.id, `nodes[${i}].id`), properties: safeProperties(n.properties) };
    }),
    relationships: rels.map((r, i) => {
      if (!isObj(r)) throw new GraphError(`relationships[${i}] must be an object.`, "INVALID");
      for (const k of ["sourceType", "targetType"] as const) if (typeof r[k] !== "string" || !NODE_SET.has(r[k] as string)) throw new GraphError(`relationships[${i}].${k}: unsupported node type.`, "INVALID");
      if (typeof r.type !== "string" || !REL_SET.has(r.type)) throw new GraphError(`relationships[${i}]: unsupported relationship type. Allowed: ${REL_TYPES.join(", ")}.`, "INVALID");
      return { sourceType: r.sourceType as string, sourceId: idOk(r.sourceId, `relationships[${i}].sourceId`), targetType: r.targetType as string, targetId: idOk(r.targetId, `relationships[${i}].targetId`), type: r.type, properties: safeProperties(r.properties) };
    })
  };
}

/* ------------------------------ client ------------------------------ */

export type GraphConfig = { url: string; username: string; password: string; database: string; namespace: string; timeoutMs: number };
export function graphConfig(env: Record<string, string | undefined> = process.env): GraphConfig | null {
  const url = (env.NEO4J_HTTP_URL ?? "").trim().replace(/\/+$/, "");
  const username = env.NEO4J_USERNAME ?? "";
  const password = env.NEO4J_PASSWORD ?? "";
  if (!url || !username || !password) return null;
  const database = (env.NEO4J_DATABASE ?? "neo4j").trim() || "neo4j";
  if (!/^[A-Za-z0-9._-]{1,63}$/.test(database)) return null;
  return { url, username, password, database, namespace: (env.NEO4J_NAMESPACE ?? "primesec").trim() || "primesec", timeoutMs: Number(env.INTEGRATION_TIMEOUT_MS) > 0 ? Number(env.INTEGRATION_TIMEOUT_MS) : 10000 };
}

type Statement = { statement: string; parameters: Record<string, unknown> };
type Fetch = typeof fetch;

export class GraphClient {
  cfg: GraphConfig | null;
  private fetchImpl: Fetch;
  constructor(cfg: GraphConfig | null = graphConfig(), fetchImpl: Fetch = fetch) {
    this.cfg = cfg;
    this.fetchImpl = fetchImpl;
  }
  get configured(): boolean { return this.cfg !== null; }

  /** Runs statements in ONE transaction (all or nothing). Returns each statement's rows. */
  async run(statements: Statement[]): Promise<unknown[][][]> {
    const cfg = this.cfg;
    if (!cfg) throw new GraphError("Set NEO4J_HTTP_URL, NEO4J_USERNAME and NEO4J_PASSWORD in .env to enable the security graph.", "NOT_CONFIGURED");
    let response: Response;
    try {
      response = await this.fetchImpl(`${cfg.url}/db/${cfg.database}/tx/commit`, {
        method: "POST",
        headers: { Authorization: `Basic ${Buffer.from(`${cfg.username}:${cfg.password}`).toString("base64")}`, "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ statements }),
        signal: AbortSignal.timeout(cfg.timeoutMs)
      });
    } catch {
      throw new GraphError("Neo4j could not be reached.", "UNAVAILABLE");
    }
    if (response.status === 401 || response.status === 403) throw new GraphError("Neo4j rejected the credentials.", "UNAVAILABLE");
    let body: { results?: { data?: { row: unknown[] }[] }[]; errors?: { code?: string }[] } = {};
    try { body = await response.json(); } catch { /* handled below */ }
    // Neo4j reports Cypher errors with a 200 status, so look at the body. Only the error CODE is surfaced, never the message.
    if (body.errors?.length) throw new GraphError(`Neo4j rejected the request (${String(body.errors[0].code ?? "error").slice(0, 80)}).`, "UNAVAILABLE");
    if (!response.ok || !Array.isArray(body.results)) throw new GraphError(`Neo4j answered unexpectedly (${response.status}).`, "UNAVAILABLE");
    return body.results.map((r) => (r.data ?? []).map((d) => d.row));
  }

  async health(): Promise<boolean> {
    const [rows] = await this.run([{ statement: "RETURN 1 AS ok", parameters: {} }]);
    return rows?.[0]?.[0] === 1;
  }

  async ensureSchema(): Promise<number> {
    // Labels come from the constant allow-list only.
    await this.run(NODE_TYPES.map((label) => ({ statement: `CREATE INDEX IF NOT EXISTS FOR (n:${label}) ON (n.tenant_id, n.external_id)`, parameters: {} })));
    return NODE_TYPES.length;
  }

  /** Builds the upsert statements (exposed for tests). Labels and types are re-checked here as the last line of defence. */
  upsertStatements(batch: GraphBatch): Statement[] {
    const ns = this.cfg?.namespace ?? "primesec";
    const out: Statement[] = [];
    for (const n of batch.nodes) {
      if (!NODE_SET.has(n.type)) throw new GraphError("Unsupported node type.", "INVALID");
      out.push({ statement: `MERGE (n:${n.type} {tenant_id:$tenant, external_id:$id}) SET n += $props`, parameters: { tenant: ns, id: n.id, props: safeProperties(n.properties) } });
    }
    for (const r of batch.relationships) {
      if (!NODE_SET.has(r.sourceType) || !NODE_SET.has(r.targetType) || !REL_SET.has(r.type)) throw new GraphError("Unsupported node or relationship type.", "INVALID");
      out.push({
        statement: `MATCH (a:${r.sourceType} {tenant_id:$tenant, external_id:$sid}) MATCH (b:${r.targetType} {tenant_id:$tenant, external_id:$tid}) MERGE (a)-[r:${r.type}]->(b) SET r += $props RETURN 1`,
        parameters: { tenant: ns, sid: r.sourceId, tid: r.targetId, props: safeProperties(r.properties) }
      });
    }
    return out;
  }

  /** Applies a batch atomically. `linked` is how many relationships actually found both ends; the rest were skipped. */
  async upsert(batch: GraphBatch): Promise<{ nodes: number; relationships: number; linked: number; skipped: number }> {
    const statements = this.upsertStatements(batch);
    const results = await this.run(statements);
    const relResults = results.slice(batch.nodes.length);
    const linked = relResults.filter((rows) => rows.length > 0).length;
    return { nodes: batch.nodes.length, relationships: batch.relationships.length, linked, skipped: batch.relationships.length - linked };
  }

  /**
   * Removes what a PREVIOUS projection created and the inventory no longer has: links for findings that are closed or gone, assets that were
   * merged away or deleted, and projected vulnerabilities left with no link. Only objects stamped origin:"inventory" are touched, so nodes
   * added through the ingest API are never deleted. One transaction.
   */
  async pruneProjection(assetIds: string[], pairs: string[]): Promise<{ links: number; assets: number; vulnerabilities: number }> {
    const ns = this.cfg?.namespace ?? "primesec";
    const results = await this.run([
      { statement: "MATCH (a:Asset {tenant_id:$tenant})-[r:HAS_VULNERABILITY {origin:'inventory'}]->(v:Vulnerability {tenant_id:$tenant}) WHERE NOT (a.external_id + '|' + v.external_id) IN $pairs DELETE r RETURN count(r) AS n", parameters: { tenant: ns, pairs } },
      { statement: "MATCH (a:Asset {tenant_id:$tenant, origin:'inventory'}) WHERE NOT a.external_id IN $ids DETACH DELETE a RETURN count(a) AS n", parameters: { tenant: ns, ids: assetIds } },
      { statement: "MATCH (v:Vulnerability {tenant_id:$tenant, origin:'inventory'}) WHERE NOT (v)<-[:HAS_VULNERABILITY]-() DELETE v RETURN count(v) AS n", parameters: { tenant: ns } }
    ]);
    const n = (i: number) => Number(results[i]?.[0]?.[0] ?? 0);
    return { links: n(0), assets: n(1), vulnerabilities: n(2) };
  }

  async attackPaths(assetId: string, limit = 25): Promise<{ nodes: { type: string; id: string; name: string }[]; relationships: string[] }[]> {
    if (typeof assetId !== "string" || !assetId || assetId.length > MAX_ID) throw new GraphError("An asset id is required.", "INVALID");
    const ns = this.cfg?.namespace ?? "primesec";
    const [rows] = await this.run([{
      statement: "MATCH p=(a:Asset {tenant_id:$tenant, external_id:$asset})-[*1..5]-(n) WHERE all(x IN nodes(p) WHERE x.tenant_id=$tenant) " +
        "RETURN [x IN nodes(p) | {type:labels(x)[0], id:x.external_id, name:coalesce(x.name, x.external_id)}] AS nodes, [x IN relationships(p) | type(x)] AS relationships LIMIT $limit",
      parameters: { tenant: ns, asset: assetId, limit: Math.max(1, Math.min(Math.floor(limit) || 25, 100)) }
    }]);
    return (rows ?? []).map(([nodes, relationships]) => ({ nodes: nodes as never, relationships: relationships as never }));
  }

  async assetExposure(limit = 100): Promise<{ assetId: string; name: string; vulnerabilityCount: number; vulnerabilities: { id: string; severity: string | null; cve: string | null }[] }[]> {
    const ns = this.cfg?.namespace ?? "primesec";
    const [rows] = await this.run([{
      statement: "MATCH (a:Asset {tenant_id:$tenant}) OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability {tenant_id:$tenant}) WITH a, collect(DISTINCT v) AS vulns " +
        "RETURN a.external_id AS asset_id, coalesce(a.name, a.external_id) AS name, size(vulns) AS vulnerability_count, [v IN vulns | {id:v.external_id, severity:v.severity, cve:v.cve}] AS vulnerabilities ORDER BY vulnerability_count DESC LIMIT $limit",
      parameters: { tenant: ns, limit: Math.max(1, Math.min(Math.floor(limit) || 100, 500)) }
    }]);
    return (rows ?? []).map(([assetId, name, count, vulns]) => ({ assetId: String(assetId), name: String(name), vulnerabilityCount: Number(count), vulnerabilities: vulns as never }));
  }
}

/* ------------------------------ projection from the inventory ------------------------------ */

/**
 * Turns the unified inventory into graph nodes and edges: an Asset per inventory asset, a Vulnerability per distinct CVE/key,
 * and HAS_VULNERABILITY for each OPEN finding (a closed one is not exposure). Asset ids are the inventory ids, so repeating the
 * projection updates in place rather than duplicating.
 */
export function projectInventory(inv: InventoryStore): GraphBatch {
  const nodes: GraphNode[] = [];
  const relationships: GraphRel[] = [];
  const seen = new Set<string>();
  const open = inv.vulns.filter((v) => !CLOSED_STATUSES.has(v.status));
  for (const a of inv.assets) {
    nodes.push({ type: "Asset", id: a.id, properties: { origin: "inventory", name: a.name, assetType: a.assetType, hostname: a.hostname, ip: a.primaryIp, environment: a.environment, criticality: a.criticality, internetFacing: a.internetFacing, riskScore: a.riskScore, riskLevel: a.riskLevel, sources: Object.keys(a.sources) } });
  }
  for (const v of open) {
    if (!seen.has(v.key)) {
      seen.add(v.key);
      nodes.push({ type: "Vulnerability", id: v.key, properties: { origin: "inventory", cve: v.cve, title: v.title, severity: v.severity, cvss: v.cvss } });
    }
    relationships.push({ sourceType: "Asset", sourceId: v.assetId, targetType: "Vulnerability", targetId: v.key, type: "HAS_VULNERABILITY", properties: { origin: "inventory", source: v.source, lastSeen: v.lastSeen } });
  }
  return { nodes, relationships };
}

/** Splits a large projection into batches within the API limits, nodes first so every edge finds both ends. */
/** The identifiers the current projection contains, used to decide what a previous projection left behind. */
export function projectionKeys(batch: GraphBatch): { assetIds: string[]; pairs: string[] } {
  return {
    assetIds: batch.nodes.filter((n) => n.type === "Asset").map((n) => n.id),
    pairs: batch.relationships.filter((r) => r.type === "HAS_VULNERABILITY").map((r) => `${r.sourceId}|${r.targetId}`)
  };
}

export function chunkBatch(batch: GraphBatch): GraphBatch[] {
  const out: GraphBatch[] = [];
  for (let i = 0; i < batch.nodes.length; i += MAX_NODES) out.push({ nodes: batch.nodes.slice(i, i + MAX_NODES), relationships: [] });
  for (let i = 0; i < batch.relationships.length; i += MAX_RELS) out.push({ nodes: [], relationships: batch.relationships.slice(i, i + MAX_RELS) });
  return out;
}
