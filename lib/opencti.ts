/**
 * Read-only OpenCTI explorer: browse indicators, reports, threat actors, vulnerabilities and malware, search observables, and read one
 * entity. Port of the Phase II OpenCTI connectivity package.
 *
 * Every query is assembled here from fixed fragments chosen from the tables below; caller text only ever travels as a GraphQL variable.
 * Marking policy (OPENCTI_ALLOWED_MARKINGS) is applied to every returned object with the STRICT rule: an object carrying any marking
 * outside the allow-list, or no marking at all, comes back as its id only. (The package showed an object if ANY of its markings was
 * allowed, which would reveal something marked both TLP:CLEAR and TLP:RED.)
 */
import { allowedMarkings, isRestricted } from "./sync.ts";

export const BROWSE_TYPES = ["indicators", "reports", "threat_actors", "vulnerabilities", "malwares"] as const;
export type BrowseType = (typeof BROWSE_TYPES)[number];

type Spec = { field: string; root: string; scalars: string[]; lists: string[] };
const SPEC: Record<BrowseType, Spec> = {
  indicators: { field: "indicators", root: "indicator", scalars: ["description", "pattern", "pattern_type", "valid_from", "valid_until", "created", "modified", "x_opencti_score"], lists: ["indicator_types"] },
  reports: { field: "reports", root: "report", scalars: ["description", "published", "created", "modified"], lists: ["report_types"] },
  threat_actors: { field: "threatActors", root: "threatActor", scalars: ["description", "first_seen", "last_seen", "created", "modified"], lists: ["aliases"] },
  vulnerabilities: { field: "vulnerabilities", root: "vulnerability", scalars: ["description", "created", "modified", "x_opencti_cvss_base_score", "x_opencti_cwe", "x_opencti_cisa_kev"], lists: [] },
  malwares: { field: "malwares", root: "malware", scalars: ["description", "is_family", "first_seen", "last_seen", "created", "modified"], lists: ["malware_types"] }
};
const DETAIL_ROOT: Record<string, BrowseType> = { indicator: "indicators", report: "reports", threat_actor: "threat_actors", vulnerability: "vulnerabilities", malware: "malwares" };

export class OpenCtiError extends Error {
  code: "INVALID" | "NOT_FOUND" | "NOT_CONFIGURED" | "UPSTREAM";
  constructor(message: string, code: OpenCtiError["code"]) {
    super(message);
    this.code = code;
  }
}
export type Deps = { query: (q: string, v?: Record<string, unknown>) => Promise<any>; configured: () => boolean; safeError: (e: unknown) => string; env: Record<string, string | undefined> };

const CONTROL = /[\u0000-\u001f\u007f]/;
const text = (v: unknown, label: string, min: number, max: number): string | undefined => {
  if (v === undefined || v === null || v === "") { if (min > 0) throw new OpenCtiError(`${label} is required.`, "INVALID"); return undefined; }
  if (typeof v !== "string" || v.trim().length < min || v.length > max || CONTROL.test(v)) throw new OpenCtiError(`${label} must be plain text of ${min} to ${max} characters.`, "INVALID");
  return v.trim();
};
const first = (v: unknown): number => {
  if (v === undefined || v === "") return 25;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 100) throw new OpenCtiError("first must be a whole number from 1 to 100.", "INVALID");
  return n;
};
const cursor = (v: unknown): string | null => {
  if (v === undefined || v === null || v === "") return null;
  if (typeof v !== "string" || !/^[A-Za-z0-9+/=_-]{1,500}$/.test(v)) throw new OpenCtiError("after is not a valid cursor.", "INVALID");
  return v;
};

/* ------------------------------ query building ------------------------------ */

// OpenCTI 5+ returns labels and markings as plain lists; some older releases return paged connections. Try the list form first.
const SHAPES = [
  { labels: "objectLabel { value }", markings: "objectMarking { definition }" },
  { labels: "objectLabel { edges { node { value } } }", markings: "objectMarking { edges { node { definition } } }" }
] as const;

export function listQuery(type: BrowseType, shape: 0 | 1): string {
  const s = SPEC[type];
  return `query PrimeSecBrowse($first: Int!, $after: ID, $search: String) { ${s.field}(first: $first, after: $after, search: $search) { pageInfo { endCursor hasNextPage globalCount } edges { node { id name ${[...s.scalars, ...s.lists].join(" ")} ${SHAPES[shape].labels} ${SHAPES[shape].markings} } } } }`;
}
export function detailQuery(type: BrowseType, shape: 0 | 1): string {
  const s = SPEC[type];
  return `query PrimeSecEntity($id: String!) { ${s.root}(id: $id) { id name ${[...s.scalars, ...s.lists].join(" ")} ${SHAPES[shape].labels} ${SHAPES[shape].markings} } }`;
}
export function observableQuery(shape: 0 | 1): string {
  return `query PrimeSecObservables($first: Int!, $search: String) { stixCyberObservables(first: $first, search: $search) { pageInfo { endCursor hasNextPage globalCount } edges { node { id entity_type observable_value created_at updated_at ${SHAPES[shape].markings} } } } }`;
}

async function withShapes(deps: Deps, build: (shape: 0 | 1) => string, vars: Record<string, unknown>): Promise<any> {
  if (!deps.configured()) throw new OpenCtiError("OpenCTI is not configured (OPENCTI_URL and OPENCTI_API_TOKEN).", "NOT_CONFIGURED");
  try {
    try {
      return await deps.query(build(0), vars);
    } catch (error) {
      if ((error as { code?: string })?.code === "NOT_CONFIGURED") throw error;
      return await deps.query(build(1), vars);
    }
  } catch (error) {
    if (error instanceof OpenCtiError) throw error;
    if ((error as { code?: string })?.code === "NOT_CONFIGURED") throw new OpenCtiError("OpenCTI is not configured (OPENCTI_URL and OPENCTI_API_TOKEN).", "NOT_CONFIGURED");
    throw new OpenCtiError(deps.safeError(error), "UPSTREAM");
  }
}

/* ------------------------------ normalisation ------------------------------ */

const listOrEdges = (v: any): any[] => (Array.isArray(v) ? v : Array.isArray(v?.edges) ? v.edges.map((e: any) => e?.node).filter(Boolean) : []);
const clip = (v: unknown, n = 600): string | number | boolean | null => (typeof v === "string" ? v.slice(0, n) : typeof v === "number" || typeof v === "boolean" ? v : null);

export type Entity = { id: string; name: string; restricted: boolean; markings: string[]; labels: string[]; fields: Record<string, string | number | boolean | string[] | null> };

export function normalize(type: BrowseType, node: any, allow: Set<string> | null): Entity {
  const markings = listOrEdges(node?.objectMarking).map((m: any) => String(m?.definition || "")).filter(Boolean);
  if (isRestricted(markings, allow)) return { id: String(node?.id ?? ""), name: "", restricted: true, markings, labels: [], fields: {} };
  const s = SPEC[type];
  const fields: Entity["fields"] = {};
  for (const k of s.scalars) fields[k] = clip(node?.[k]);
  for (const k of s.lists) fields[k] = Array.isArray(node?.[k]) ? node[k].map((x: unknown) => String(x).slice(0, 120)).slice(0, 50) : [];
  return { id: String(node?.id ?? ""), name: String(node?.name ?? "").slice(0, 300), restricted: false, markings, labels: listOrEdges(node?.objectLabel).map((l: any) => String(l?.value || "")).filter(Boolean).slice(0, 30), fields };
}

/* ------------------------------ operations ------------------------------ */

export type Page<T> = { items: T[]; total: number | null; endCursor: string | null; hasNextPage: boolean; restrictedCount: number; markingPolicy: string[] | null };
const policy = (allow: Set<string> | null) => (allow ? [...allow] : null);

export async function browse(typeIn: unknown, args: { first?: unknown; after?: unknown; search?: unknown }, deps: Deps): Promise<Page<Entity>> {
  if (typeof typeIn !== "string" || !(BROWSE_TYPES as readonly string[]).includes(typeIn)) throw new OpenCtiError(`type must be one of ${BROWSE_TYPES.join(", ")}.`, "INVALID");
  const type = typeIn as BrowseType;
  const vars = { first: first(args.first), after: cursor(args.after), search: text(args.search, "search", 0, 200) ?? null };
  const data = await withShapes(deps, (shape) => listQuery(type, shape), vars);
  const conn = data?.[SPEC[type].field];
  const allow = allowedMarkings(deps.env.OPENCTI_ALLOWED_MARKINGS);
  const items = listOrEdges(conn).map((n) => normalize(type, n, allow));
  const total = Number(conn?.pageInfo?.globalCount);
  return { items, total: Number.isFinite(total) ? total : null, endCursor: conn?.pageInfo?.endCursor ?? null, hasNextPage: conn?.pageInfo?.hasNextPage === true, restrictedCount: items.filter((i) => i.restricted).length, markingPolicy: policy(allow) };
}

export async function getEntity(typeIn: unknown, idIn: unknown, deps: Deps): Promise<{ type: BrowseType; item: Entity }> {
  if (typeof typeIn !== "string" || !(typeIn in DETAIL_ROOT)) throw new OpenCtiError(`type must be one of ${Object.keys(DETAIL_ROOT).join(", ")}.`, "INVALID");
  if (typeof idIn !== "string" || !/^[A-Za-z0-9-]{1,64}$/.test(idIn)) throw new OpenCtiError("id must be an OpenCTI entity id.", "INVALID");
  const type = DETAIL_ROOT[typeIn];
  const data = await withShapes(deps, (shape) => detailQuery(type, shape), { id: idIn });
  const node = data?.[SPEC[type].root];
  if (!node) throw new OpenCtiError("OpenCTI entity not found (or not visible to this account).", "NOT_FOUND");
  return { type, item: normalize(type, node, allowedMarkings(deps.env.OPENCTI_ALLOWED_MARKINGS)) };
}

export type Observable = { id: string; type: string; value: string; restricted: boolean; markings: string[]; created: string | null };
export async function searchObservables(valueIn: unknown, firstIn: unknown, deps: Deps): Promise<Page<Observable>> {
  const value = text(valueIn, "value", 1, 255)!;
  const data = await withShapes(deps, observableQuery, { first: first(firstIn), search: value });
  const conn = data?.stixCyberObservables;
  const allow = allowedMarkings(deps.env.OPENCTI_ALLOWED_MARKINGS);
  const items: Observable[] = listOrEdges(conn).map((n) => {
    const markings = listOrEdges(n.objectMarking).map((m: any) => String(m?.definition || "")).filter(Boolean);
    const restricted = isRestricted(markings, allow);
    return { id: String(n.id), type: String(n.entity_type ?? ""), value: restricted ? "" : String(n.observable_value ?? "").slice(0, 500), restricted, markings, created: restricted ? null : (clip(n.created_at) as string | null) };
  });
  const total = Number(conn?.pageInfo?.globalCount);
  return { items, total: Number.isFinite(total) ? total : null, endCursor: conn?.pageInfo?.endCursor ?? null, hasNextPage: conn?.pageInfo?.hasNextPage === true, restrictedCount: items.filter((i) => i.restricted).length, markingPolicy: policy(allow) };
}
