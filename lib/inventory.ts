/**
 * Unified asset inventory: one canonical record per asset, built from observations that Wazuh, Greenbone,
 * a CMDB or a cloud inventory report. Port of the Phase II "Unified Asset Intelligence v1.4" package.
 *
 * Identity policy: only durable identifiers (cloud instance id, agent id, CMDB id, ...) merge two observations.
 * IP and hostname are kept as attributes and NEVER used as a merge key, because DHCP reuse, NAT, cloning and
 * naming collisions would create false joins. Without a durable id the key is `source:<source>:<source asset id>`.
 *
 * The exposure score is a transparent heuristic for prioritisation, not a probability. Nothing here scans,
 * changes a host or triggers a response.
 */
import { promises as fs } from "fs";
import path from "path";

export const ASSET_FIELDS = ["source", "sourceAssetId", "assetType", "name", "hostname", "primaryIp", "operatingSystem", "environment", "businessUnit", "criticality", "internetFacing", "tags", "identifiers", "vulnerabilities"] as const;
const VULN_FIELDS = ["cve", "key", "title", "severity", "cvss", "status"] as const;
/** Checked in this order: the first one present decides the identity. */
export const DURABLE_ID_KEYS = ["cloud_instance_id", "instance_id", "device_id", "agent_id", "openvas_host_id", "cmdb_id", "serial_number"] as const;
export const CLOSED_STATUSES = new Set(["closed", "resolved", "fixed", "false_positive"]);
export const RISK_LEVELS = ["critical", "high", "medium", "low"] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const MAX_BATCH = 1000;
const MAX_TEXT = 300;
const MAX_VULNS_PER_ITEM = 500;
const MAX_TAGS = 50;
const MAX_IDENTIFIERS = 20;
const MAX_OBSERVATIONS_PER_ASSET = 20;

export type VulnInput = { cve?: string | null; key?: string | null; title?: string; severity?: string; cvss?: number | null; status?: string };
export type AssetInput = {
  source: string;
  sourceAssetId: string;
  assetType?: string;
  name?: string;
  hostname?: string | null;
  primaryIp?: string | null;
  operatingSystem?: string | null;
  environment?: string | null;
  businessUnit?: string | null;
  /** 1 (low) to 5 (business critical). Omit when the source does not know: an unknown value never overwrites a known one. */
  criticality?: number | null;
  internetFacing?: boolean;
  tags?: string[];
  identifiers?: Record<string, string>;
  vulnerabilities?: VulnInput[];
};

export type InventoryAsset = {
  id: string;
  canonicalKey: string;
  assetType: string;
  name: string;
  hostname: string | null;
  primaryIp: string | null;
  operatingSystem: string | null;
  environment: string | null;
  businessUnit: string | null;
  /** null = no source has said. Scoring then assumes 3 (medium) and says so. */
  criticality: number | null;
  internetFacing: boolean;
  /** What each source last said. The asset's value is the highest across sources, so a source can lower only its own claim. */
  criticalityBySource: Record<string, number>;
  internetFacingBySource: Record<string, boolean>;
  tags: string[];
  identifiers: Record<string, string>;
  /** source -> last time that source reported this asset */
  sources: Record<string, string>;
  riskScore: number;
  riskLevel: RiskLevel;
  createdAt: string;
  updatedAt: string;
  /** The source that owns the display name. Another source never renames the asset (otherwise the last sync to run would win). */
  nameSource?: string;
  /** Assets an analyst merged into this one, with who, when and why. */
  mergedFrom?: { id: string; canonicalKey: string; name: string; sources: string[]; at: string; by: string; note: string }[];
};
export type InventoryVuln = {
  assetId: string;
  key: string;
  cve: string | null;
  title: string;
  severity: string;
  cvss: number | null;
  status: string;
  source: string;
  firstSeen: string;
  lastSeen: string;
};
export type Observation = { assetId: string; source: string; sourceAssetId: string; observedAt: string };
/** `aliases` maps the canonical key of a merged-away asset to the survivor, so a later report of the old identity lands on the merged asset. `dismissed` holds pairs an analyst said are NOT the same machine. */
export type InventoryStore = { assets: InventoryAsset[]; vulns: InventoryVuln[]; observations: Observation[]; aliases: Record<string, string>; dismissed: string[] };

export class InventoryError extends Error {
  code: "INVALID" | "NOT_FOUND" | "CONFLICT";
  constructor(message: string, code: "INVALID" | "NOT_FOUND" | "CONFLICT" = "INVALID") {
    super(message);
    this.code = code;
  }
}

/* ------------------------------ validation ------------------------------ */

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown, label: string, max = MAX_TEXT): string => {
  if (typeof v !== "string") throw new InventoryError(`${label} must be text.`);
  if (v.length > max) throw new InventoryError(`${label} is longer than ${max} characters.`);
  return v.trim();
};
const optStr = (v: unknown, label: string): string | null => (v === undefined || v === null || v === "" ? null : str(v, label) || null);

export function norm(v: unknown): string {
  return String(v ?? "").trim().toLowerCase().replace(/[^a-z0-9._:-]+/g, "");
}

function validateVuln(raw: unknown, at: string): VulnInput {
  if (!isObj(raw)) throw new InventoryError(`${at}: a vulnerability must be an object.`);
  for (const k of Object.keys(raw)) if (!(VULN_FIELDS as readonly string[]).includes(k)) throw new InventoryError(`${at}: unknown field "${k}".`);
  let cvss: number | null = null;
  if (raw.cvss !== undefined && raw.cvss !== null) {
    if (typeof raw.cvss !== "number" || !Number.isFinite(raw.cvss) || raw.cvss < 0 || raw.cvss > 10) throw new InventoryError(`${at}: cvss must be a number from 0 to 10.`);
    cvss = raw.cvss;
  }
  const cve = optStr(raw.cve, `${at}: cve`);
  const key = optStr(raw.key, `${at}: key`);
  const title = raw.title === undefined ? "" : str(raw.title, `${at}: title`);
  if (!cve && !key && !title) throw new InventoryError(`${at}: a vulnerability needs a cve, key or title.`);
  return { cve, key, title, severity: raw.severity === undefined ? "unknown" : str(raw.severity, `${at}: severity`, 20).toLowerCase(), cvss, status: raw.status === undefined ? "open" : str(raw.status, `${at}: status`, 30).toLowerCase() };
}

export function validateAssetInput(raw: unknown, index = 0): AssetInput {
  const at = `items[${index}]`;
  if (!isObj(raw)) throw new InventoryError(`${at} must be an object.`);
  for (const k of Object.keys(raw)) if (!(ASSET_FIELDS as readonly string[]).includes(k)) throw new InventoryError(`${at}: unknown field "${k}".`);
  const source = str(raw.source, `${at}.source`, 80);
  if (source.length < 2) throw new InventoryError(`${at}.source needs at least 2 characters.`);
  const sourceAssetId = str(raw.sourceAssetId, `${at}.sourceAssetId`);
  if (!sourceAssetId) throw new InventoryError(`${at}.sourceAssetId is required.`);
  let criticality: number | null = null;
  if (raw.criticality !== undefined && raw.criticality !== null) {
    if (typeof raw.criticality !== "number" || !Number.isInteger(raw.criticality) || raw.criticality < 1 || raw.criticality > 5) throw new InventoryError(`${at}.criticality must be a whole number from 1 to 5.`);
    criticality = raw.criticality;
  }
  if (raw.internetFacing !== undefined && typeof raw.internetFacing !== "boolean") throw new InventoryError(`${at}.internetFacing must be true or false.`);
  let tags: string[] = [];
  if (raw.tags !== undefined) {
    if (!Array.isArray(raw.tags) || raw.tags.length > MAX_TAGS) throw new InventoryError(`${at}.tags must be a list of at most ${MAX_TAGS} entries.`);
    tags = raw.tags.map((t, i) => str(t, `${at}.tags[${i}]`, 80)).filter(Boolean);
  }
  const identifiers: Record<string, string> = {};
  if (raw.identifiers !== undefined) {
    if (!isObj(raw.identifiers) || Object.keys(raw.identifiers).length > MAX_IDENTIFIERS) throw new InventoryError(`${at}.identifiers must be an object with at most ${MAX_IDENTIFIERS} entries.`);
    for (const [k, v] of Object.entries(raw.identifiers)) {
      const value = str(v, `${at}.identifiers.${k}`, 200);
      if (value) identifiers[k] = value;
    }
  }
  let vulnerabilities: VulnInput[] = [];
  if (raw.vulnerabilities !== undefined) {
    if (!Array.isArray(raw.vulnerabilities) || raw.vulnerabilities.length > MAX_VULNS_PER_ITEM) throw new InventoryError(`${at}.vulnerabilities must be a list of at most ${MAX_VULNS_PER_ITEM}.`);
    vulnerabilities = raw.vulnerabilities.map((v, i) => validateVuln(v, `${at}.vulnerabilities[${i}]`));
  }
  return {
    source, sourceAssetId, criticality, tags, identifiers, vulnerabilities,
    assetType: raw.assetType === undefined ? "unknown" : str(raw.assetType, `${at}.assetType`, 40),
    name: raw.name === undefined ? "" : str(raw.name, `${at}.name`),
    hostname: optStr(raw.hostname, `${at}.hostname`),
    primaryIp: optStr(raw.primaryIp, `${at}.primaryIp`),
    operatingSystem: optStr(raw.operatingSystem, `${at}.operatingSystem`),
    environment: optStr(raw.environment, `${at}.environment`),
    businessUnit: optStr(raw.businessUnit, `${at}.businessUnit`),
    internetFacing: raw.internetFacing === true
  };
}

/* ------------------------------ identity and scoring ------------------------------ */

export function canonicalKey(item: Pick<AssetInput, "source" | "sourceAssetId" | "identifiers">): string {
  const ids = new Map<string, string>();
  for (const [k, v] of Object.entries(item.identifiers ?? {})) if (v) ids.set(norm(k), norm(v));
  for (const key of DURABLE_ID_KEYS) {
    const value = ids.get(key);
    if (value) return `${key}:${value}`;
  }
  return `source:${norm(item.source)}:${norm(item.sourceAssetId)}`;
}

const SEVERITY_VALUE: Record<string, number> = { critical: 10, high: 7.5, medium: 4.5, low: 2, info: 0.5, unknown: 1 };
export const ASSUMED_CRITICALITY = 3;

/**
 * min(100, worst open severity (CVSS, else a severity default) * 6 + min(open count, 10) * 2 + criticality * 5 + 12 if internet-facing).
 * Bands: critical >= 80, high >= 60, medium >= 35, otherwise low. Tune the weights with your risk owners before relying on them.
 */
export function exposure(asset: Pick<InventoryAsset, "criticality" | "internetFacing">, vulns: Pick<InventoryVuln, "status" | "severity" | "cvss">[]): { score: number; level: RiskLevel } {
  const values: number[] = [];
  for (const v of vulns) {
    if (CLOSED_STATUSES.has(v.status.toLowerCase())) continue;
    values.push(v.cvss !== null && v.cvss !== undefined ? v.cvss : SEVERITY_VALUE[v.severity.toLowerCase()] ?? 1);
  }
  const worst = values.length ? Math.max(...values) : 0;
  const raw = worst * 6 + Math.min(values.length, 10) * 2 + (asset.criticality ?? ASSUMED_CRITICALITY) * 5 + (asset.internetFacing ? 12 : 0);
  const score = Math.round(Math.min(100, raw) * 10) / 10;
  return { score, level: score >= 80 ? "critical" : score >= 60 ? "high" : score >= 35 ? "medium" : "low" };
}

/* ------------------------------ storage ------------------------------ */

const storePath = () => path.join(process.cwd(), "data", "inventory.json");
const EMPTY = (): InventoryStore => ({ assets: [], vulns: [], observations: [], aliases: {}, dismissed: [] });

export async function readInventory(): Promise<InventoryStore> {
  try {
    const value = JSON.parse(await fs.readFile(storePath(), "utf8"));
    if (!isObj(value)) return EMPTY();
    return { assets: Array.isArray(value.assets) ? (value.assets as InventoryAsset[]) : [], vulns: Array.isArray(value.vulns) ? (value.vulns as InventoryVuln[]) : [], observations: Array.isArray(value.observations) ? (value.observations as Observation[]) : [], aliases: isObj(value.aliases) ? (value.aliases as Record<string, string>) : {}, dismissed: Array.isArray(value.dismissed) ? (value.dismissed as string[]) : [] };
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return EMPTY();
    throw error;
  }
}

let chain: Promise<unknown> = Promise.resolve();
/** Serialises writers and replaces the file atomically, so a crash never leaves half a write. */
function withStore<T>(fn: (store: InventoryStore) => { store: InventoryStore; result: T }): Promise<T> {
  const run = chain.then(async () => {
    const { store, result } = fn(await readInventory());
    await fs.mkdir(path.dirname(storePath()), { recursive: true });
    const temp = `${storePath()}.${process.pid}.tmp`;
    await fs.writeFile(temp, JSON.stringify(store), { mode: 0o600 });
    await fs.rename(temp, storePath());
    return result;
  });
  chain = run.catch(() => undefined);
  return run;
}

export async function clearInventory(): Promise<number> {
  return withStore((s) => ({ store: EMPTY(), result: s.assets.length }));
}

/* ------------------------------ ingest ------------------------------ */

let counter = 0;
const newId = () => `ast_${Date.now().toString(36)}${(counter++).toString(36)}${Math.random().toString(36).slice(2, 6)}`;

function applyItem(store: InventoryStore, item: AssetInput, now: string): InventoryAsset {
  const key = canonicalKey(item);
  // A key that was merged away still resolves to the asset it was merged into.
  let asset = store.assets.find((a) => a.canonicalKey === key) ?? store.assets.find((a) => a.id === store.aliases[key]);
  if (!asset) {
    asset = {
      id: newId(), canonicalKey: key, nameSource: item.source, assetType: "unknown", name: item.name || item.hostname || item.sourceAssetId, hostname: null, primaryIp: null, operatingSystem: null,
      environment: null, businessUnit: null, criticality: null, internetFacing: false, criticalityBySource: {}, internetFacingBySource: {}, tags: [], identifiers: {}, sources: {}, riskScore: 0, riskLevel: "low", createdAt: now, updatedAt: now
    };
    store.assets.push(asset);
  }
  if (item.assetType && item.assetType !== "unknown") asset.assetType = item.assetType;
  // Only the source that owns the name may change it. (Assets stored before this rule have no owner: the next source to report claims it.)
  if (item.name && (asset.nameSource === undefined || asset.nameSource === item.source)) { asset.name = item.name; asset.nameSource = item.source; }
  asset.hostname = item.hostname || asset.hostname;
  asset.primaryIp = item.primaryIp || asset.primaryIp;
  asset.operatingSystem = item.operatingSystem || asset.operatingSystem;
  asset.environment = item.environment || asset.environment;
  asset.businessUnit = item.businessUnit || asset.businessUnit;
  asset.criticalityBySource = { ...asset.criticalityBySource };
  if (item.criticality !== null && item.criticality !== undefined) asset.criticalityBySource[item.source] = item.criticality;
  const claims = Object.values(asset.criticalityBySource);
  asset.criticality = claims.length ? Math.max(...claims) : null;
  asset.internetFacingBySource = { ...asset.internetFacingBySource, [item.source]: item.internetFacing === true };
  asset.internetFacing = Object.values(asset.internetFacingBySource).some(Boolean);
  asset.tags = [...new Set([...asset.tags, ...(item.tags ?? [])])].sort();
  asset.identifiers = { ...asset.identifiers, ...(item.identifiers ?? {}) };
  asset.sources = { ...asset.sources, [item.source]: now };
  asset.updatedAt = now;

  store.observations.push({ assetId: asset.id, source: item.source, sourceAssetId: item.sourceAssetId, observedAt: now });
  for (const v of item.vulnerabilities ?? []) {
    const vkey = (v.cve || v.key || v.title || "unknown").toUpperCase();
    let row = store.vulns.find((x) => x.assetId === asset!.id && x.key === vkey);
    if (!row) {
      row = { assetId: asset.id, key: vkey, cve: null, title: "", severity: "unknown", cvss: null, status: "open", source: item.source, firstSeen: now, lastSeen: now };
      store.vulns.push(row);
    }
    row.cve = v.cve ?? row.cve;
    row.title = v.title || row.title;
    row.severity = v.severity ?? "unknown";
    row.cvss = v.cvss ?? null;
    row.status = v.status ?? "open";
    row.source = item.source;
    row.lastSeen = now;
  }
  const mine = store.vulns.filter((x) => x.assetId === asset!.id);
  const { score, level } = exposure(asset, mine);
  asset.riskScore = score;
  asset.riskLevel = level;
  return asset;
}

/** Keeps the newest observations per asset, so the file does not grow with every sync. */
function trimObservations(store: InventoryStore): void {
  const seen = new Map<string, number>();
  const kept: Observation[] = [];
  for (let i = store.observations.length - 1; i >= 0; i--) {
    const o = store.observations[i];
    const n = (seen.get(o.assetId) ?? 0) + 1;
    seen.set(o.assetId, n);
    if (n <= MAX_OBSERVATIONS_PER_ASSET) kept.push(o);
  }
  store.observations = kept.reverse();
}

export type IngestResult = { accepted: number; created: number; updated: number; assets: InventoryAsset[] };

/** Validates every item first; one bad item rejects the whole batch so a partial import is never silently stored. */
export function validateBatch(items: unknown): AssetInput[] {
  if (!Array.isArray(items) || items.length < 1 || items.length > MAX_BATCH) throw new InventoryError(`items must be a list of 1 to ${MAX_BATCH} assets.`);
  return items.map((raw, i) => validateAssetInput(raw, i));
}

export async function ingestAssets(inputs: AssetInput[], now = new Date().toISOString()): Promise<IngestResult> {
  return withStore((store) => {
    const before = new Set(store.assets.map((a) => a.canonicalKey));
    const touched = new Map<string, InventoryAsset>();
    for (const item of inputs) {
      const asset = applyItem(store, item, now);
      touched.set(asset.id, asset);
    }
    trimObservations(store);
    const created = [...touched.values()].filter((a) => !before.has(a.canonicalKey)).length;
    return { store, result: { accepted: inputs.length, created, updated: touched.size - created, assets: [...touched.values()] } };
  });
}

/* ------------------------------ reconciliation (analyst-approved merge) ------------------------------ */

const pairKey = (x: string, y: string) => [x, y].sort().join("|");
const shortName = (h: string) => h.toLowerCase().split(".")[0];

export type MergeCandidate = { a: AssetRow; b: AssetRow; reasons: string[]; strength: "strong" | "medium" | "weak" };

/**
 * Pairs that MIGHT be one machine seen by two tools: same IP, same host name, or same short host name. Pairs where both assets are
 * reported by a common source are never suggested (that source already lists them as separate machines), and dismissed pairs stay hidden.
 * A suggestion is only a lead: a person decides. Two networks (an agent address and a scanner view) often share nothing, so the
 * screen also allows choosing any two assets by hand.
 */
export async function mergeCandidates(limit = 50): Promise<MergeCandidate[]> {
  const store = await readInventory();
  const dismissed = new Set(store.dismissed);
  const rows = (a: InventoryAsset): AssetRow => ({ ...a, openVulnerabilities: openCount(store, a.id), staleSources: staleSourcesOf(a) });
  const out: MergeCandidate[] = [];
  for (let i = 0; i < store.assets.length; i++) {
    for (let j = i + 1; j < store.assets.length; j++) {
      const a = store.assets[i], b = store.assets[j];
      if (dismissed.has(pairKey(a.id, b.id)) || Object.keys(a.sources).some((s) => s in b.sources)) continue;
      const reasons: string[] = [];
      const sameIp = Boolean(a.primaryIp) && a.primaryIp === b.primaryIp;
      const sameHost = Boolean(a.hostname && b.hostname) && a.hostname!.toLowerCase() === b.hostname!.toLowerCase();
      if (sameIp) reasons.push(`Same IP ${a.primaryIp}`);
      if (sameHost) reasons.push(`Same host name ${a.hostname!.toLowerCase()}`);
      else if (a.hostname && b.hostname && shortName(a.hostname) === shortName(b.hostname)) reasons.push(`Same short host name ${shortName(a.hostname)}`);
      if (!reasons.length) continue;
      const strength = sameIp && (sameHost || reasons.length > 1) ? "strong" : sameIp || sameHost ? "medium" : "weak";
      out.push({ a: rows(a), b: rows(b), reasons, strength });
    }
  }
  const rank = { strong: 0, medium: 1, weak: 2 };
  return out.sort((x, y) => rank[x.strength] - rank[y.strength]).slice(0, Math.min(Math.max(limit, 1), 200));
}

const reason = (note: unknown): string => {
  if (typeof note !== "string" || note.trim().length < 10 || note.length > 1000) throw new InventoryError("Say why (10 to 1000 characters): this decision is recorded.", "INVALID");
  return note.trim();
};

/** Records that two assets are NOT the same machine, so they stop being suggested. */
export async function dismissPair(idA: unknown, idB: unknown): Promise<void> {
  if (typeof idA !== "string" || typeof idB !== "string" || idA === idB) throw new InventoryError("Two different asset ids are required.", "INVALID");
  await withStore((store) => {
    if (!store.assets.some((a) => a.id === idA) || !store.assets.some((a) => a.id === idB)) throw new InventoryError("Asset not found.", "NOT_FOUND");
    const k = pairKey(idA, idB);
    if (!store.dismissed.includes(k)) store.dismissed.push(k);
    return { store, result: undefined };
  });
}

/**
 * Merges `absorbedId` into `survivorId`. The survivor keeps its name and wins any conflict; gaps are filled from the absorbed asset;
 * vulnerabilities and observations move across (a vulnerability both had keeps the newer record); the old canonical key becomes an alias
 * so later reports of it land on the survivor; the merge, its reason and who did it stay on the asset. Refused when both assets are
 * reported by the same source. There is no automatic undo.
 */
export async function mergeAssets(survivorId: unknown, absorbedId: unknown, note: unknown, actor: string, now = new Date().toISOString()): Promise<InventoryAsset> {
  const why = reason(note);
  if (typeof survivorId !== "string" || typeof absorbedId !== "string" || survivorId === absorbedId) throw new InventoryError("Two different asset ids are required.", "INVALID");
  return withStore((store) => {
    const s = store.assets.find((x) => x.id === survivorId);
    const a = store.assets.find((x) => x.id === absorbedId);
    if (!s || !a) throw new InventoryError("Asset not found.", "NOT_FOUND");
    const shared = Object.keys(a.sources).filter((k) => k in s.sources);
    if (shared.length) throw new InventoryError(`Both assets are reported by ${shared.join(", ")}, and that source lists them as separate machines. They are probably not the same.`, "CONFLICT");

    for (const k of ["hostname", "primaryIp", "operatingSystem", "environment", "businessUnit"] as const) s[k] = s[k] || a[k];
    if (s.assetType === "unknown") s.assetType = a.assetType;
    s.tags = [...new Set([...s.tags, ...a.tags])].sort();
    s.identifiers = { ...a.identifiers, ...s.identifiers };
    s.sources = { ...a.sources, ...s.sources };
    s.criticalityBySource = { ...a.criticalityBySource, ...s.criticalityBySource };
    s.internetFacingBySource = { ...a.internetFacingBySource, ...s.internetFacingBySource };
    const claims = Object.values(s.criticalityBySource);
    s.criticality = claims.length ? Math.max(...claims) : null;
    s.internetFacing = Object.values(s.internetFacingBySource).some(Boolean);

    for (const v of store.vulns.filter((x) => x.assetId === a.id)) {
      const twin = store.vulns.find((x) => x.assetId === s.id && x.key === v.key);
      if (twin) {
        const newer = v.lastSeen > twin.lastSeen ? v : twin;
        Object.assign(twin, { ...newer, assetId: s.id, firstSeen: v.firstSeen < twin.firstSeen ? v.firstSeen : twin.firstSeen });
        store.vulns.splice(store.vulns.indexOf(v), 1);
      } else v.assetId = s.id;
    }
    for (const o of store.observations) if (o.assetId === a.id) o.assetId = s.id;
    for (const [k, target] of Object.entries(store.aliases)) if (target === a.id) store.aliases[k] = s.id;
    store.aliases[a.canonicalKey] = s.id;
    s.mergedFrom = [...(s.mergedFrom ?? []), ...(a.mergedFrom ?? []), { id: a.id, canonicalKey: a.canonicalKey, name: a.name, sources: Object.keys(a.sources), at: now, by: actor, note: why }];
    store.assets.splice(store.assets.indexOf(a), 1);
    store.dismissed = store.dismissed.filter((k) => !k.split("|").includes(a.id));
    const { score, level } = exposure(s, store.vulns.filter((x) => x.assetId === s.id));
    s.riskScore = score;
    s.riskLevel = level;
    s.updatedAt = now;
    return { store, result: { ...s } };
  });
}

/* ------------------------------ queries ------------------------------ */

export type AssetQuery = { q?: string; riskLevel?: string; environment?: string; limit?: number; offset?: number };
/** A source that has not reported this asset for `days` days (it may be gone, renamed, or the source may be failing). Nothing is changed by this. */
export type StaleSource = { source: string; days: number };
export type AssetRow = InventoryAsset & { openVulnerabilities: number; staleSources: StaleSource[] };

export const DEFAULT_STALE_DAYS = 7;
export function staleDays(env: Record<string, string | undefined> = process.env): number {
  const n = Number(env.INVENTORY_STALE_DAYS);
  return Number.isFinite(n) && n >= 1 && n <= 365 ? Math.floor(n) : DEFAULT_STALE_DAYS;
}
export function staleSourcesOf(a: Pick<InventoryAsset, "sources">, nowMs = Date.now(), limitDays = staleDays()): StaleSource[] {
  return Object.entries(a.sources)
    .map(([source, at]) => ({ source, days: Math.floor((nowMs - Date.parse(at)) / 86_400_000) }))
    .filter((x) => Number.isFinite(x.days) && x.days >= limitDays)
    .sort((x, y) => y.days - x.days);
}

const openCount = (store: InventoryStore, id: string) => store.vulns.filter((v) => v.assetId === id && !CLOSED_STATUSES.has(v.status)).length;

export async function listAssets(query: AssetQuery = {}, nowMs = Date.now()): Promise<{ items: AssetRow[]; total: number; limit: number; offset: number }> {
  const store = await readInventory();
  const limit = Math.min(Math.max(Math.floor(query.limit ?? 100) || 100, 1), 500);
  const offset = Math.max(Math.floor(query.offset ?? 0) || 0, 0);
  const q = (query.q ?? "").trim().toLowerCase().slice(0, 100);
  let rows = store.assets.slice();
  if (q) rows = rows.filter((a) => [a.name, a.hostname, a.primaryIp, a.canonicalKey].some((f) => (f ?? "").toLowerCase().includes(q)));
  if (query.riskLevel) rows = rows.filter((a) => a.riskLevel === query.riskLevel!.toLowerCase());
  if (query.environment) rows = rows.filter((a) => a.environment === query.environment);
  rows.sort((a, b) => b.riskScore - a.riskScore || a.name.localeCompare(b.name));
  return { items: rows.slice(offset, offset + limit).map((a) => ({ ...a, openVulnerabilities: openCount(store, a.id), staleSources: staleSourcesOf(a, nowMs) })), total: rows.length, limit, offset };
}

export async function inventorySummary() {
  const { assets } = await readInventory();
  const by = (level: RiskLevel) => assets.filter((a) => a.riskLevel === level).length;
  const sources: Record<string, number> = {};
  for (const a of assets) for (const s of Object.keys(a.sources)) sources[s] = (sources[s] ?? 0) + 1;
  return {
    totalAssets: assets.length,
    byRisk: { critical: by("critical"), high: by("high"), medium: by("medium"), low: by("low") },
    internetFacing: assets.filter((a) => a.internetFacing).length,
    highCriticality: assets.filter((a) => (a.criticality ?? 0) >= 4).length,
    criticalityUnknown: assets.filter((a) => a.criticality === null).length,
    staleAssets: assets.filter((a) => staleSourcesOf(a).length > 0).length,
    bySource: sources
  };
}

export type DetailVuln = InventoryVuln & {
  /** The source that reported this finding has since reported the asset WITHOUT it. It may be fixed: an analyst verifies and closes it. Never closed automatically. */
  notInLatestSync: boolean;
};

export async function assetDetail(id: string, nowMs = Date.now()) {
  const store = await readInventory();
  const asset = store.assets.find((a) => a.id === id);
  if (!asset) throw new InventoryError("Asset not found.", "NOT_FOUND");
  const vulnerabilities: DetailVuln[] = store.vulns.filter((v) => v.assetId === id)
    .sort((a, b) => (b.cvss ?? SEVERITY_VALUE[b.severity] ?? 0) - (a.cvss ?? SEVERITY_VALUE[a.severity] ?? 0))
    .map((v) => ({ ...v, notInLatestSync: Boolean(asset.sources[v.source]) && v.lastSeen < asset.sources[v.source] && !CLOSED_STATUSES.has(v.status) }));
  const observations = store.observations.filter((o) => o.assetId === id).sort((a, b) => b.observedAt.localeCompare(a.observedAt));
  return { ...asset, openVulnerabilities: vulnerabilities.filter((v) => !CLOSED_STATUSES.has(v.status)).length, staleSources: staleSourcesOf(asset, nowMs), vulnerabilities, observations };
}

export async function topExposure(limit = 50) {
  const { items } = await listAssets({ limit: Math.min(Math.max(limit, 1), 200) });
  return items;
}
