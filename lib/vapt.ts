/**
 * Greenbone (VAPT) integration: authorised scope registry + client for the Greenbone bridge.
 *
 * SAFETY MODEL. A scan can only start when its target lies inside a scope that (a) a SOC_Admin
 * approved with a written authorisation reference, (b) has not expired or been revoked. Scope
 * rules are enforced here, on the server, before the bridge is ever called. Never scan systems
 * you are not explicitly authorised to assess.
 */
import { promises as fs } from "fs";
import path from "path";

export type VaptScope = {
  id: string;
  name: string;
  authorizationReference: string;
  targets: string[];
  expiresAt: string;
  status: "Approved" | "Revoked";
  createdAt: string;
  createdBy: string;
  includesPublicRanges: boolean;
  revokedAt?: string;
  revokedBy?: string;
};

export type VaptTask = { id: string; name: string; status: string; progress: string; target: string; lastReportId: string };
export type VaptTarget = { id: string; name: string; hosts: string; comment: string };
export type VaptOverview = {
  status: { configured: boolean; connected: boolean; message: string; checkedAt: string };
  version: string | null;
  targets: VaptTarget[];
  tasks: VaptTask[];
};
export type VaptAssessment = {
  targetId: string; targetName: string; taskId: string; reportId: string | null; target: string; status: string; message: string;
};

export const MAX_SCOPE_DAYS = 90;
export const MAX_TARGETS_PER_SCOPE = 10;
export const MIN_REFERENCE_LENGTH = 8;

const scopesPath = () => path.join(process.cwd(), "data", "vapt-scopes.json");

/* ------------------------------ IPv4 / CIDR rules ------------------------------ */

export type Cidr = { network: string; prefix: number; start: number; end: number; public: boolean };

const toNum = (a: number, b: number, c: number, d: number) => a * 16777216 + b * 65536 + c * 256 + d;
const toIp = (n: number) => [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256].join(".");

type Range = [start: number, end: number];
const range = (a: number, b: number, c: number, d: number, prefix: number): Range => {
  const start = toNum(a, b, c, d);
  return [start, start + 2 ** (32 - prefix) - 1];
};
/** Never scannable, even with an approval: scanning these hits the scanner host or infrastructure, not a customer asset. */
const RESERVED: { label: string; r: Range }[] = [
  { label: "0.0.0.0/8 (unspecified)", r: range(0, 0, 0, 0, 8) },
  { label: "127.0.0.0/8 (loopback)", r: range(127, 0, 0, 0, 8) },
  { label: "169.254.0.0/16 (link-local, includes cloud metadata)", r: range(169, 254, 0, 0, 16) },
  { label: "224.0.0.0/4 (multicast)", r: range(224, 0, 0, 0, 4) },
  { label: "240.0.0.0/4 (reserved/broadcast)", r: range(240, 0, 0, 0, 4) }
];
const PRIVATE: Range[] = [range(10, 0, 0, 0, 8), range(172, 16, 0, 0, 12), range(192, 168, 0, 0, 16), range(100, 64, 0, 0, 10)];

/**
 * Parses an IPv4 address or CIDR. Strict: host bits must not be set (`10.0.0.5/24` is rejected,
 * not silently widened to the whole /24). Throws a readable Error.
 */
export function parseCidr(value: unknown): Cidr {
  const raw = String(value ?? "").trim();
  const m = raw.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (!m) throw new Error(`Invalid IPv4 address or CIDR: ${raw || "(empty)"}`);
  const octets = m.slice(1, 5).map(Number);
  if (octets.some((n) => n > 255)) throw new Error(`Invalid IPv4 address: ${raw}`);
  const prefix = m[5] === undefined ? 32 : Number(m[5]);
  if (prefix < 24 || prefix > 32) throw new Error(`${raw}: each target must be /24 or narrower in this MVP.`);
  const ip = toNum(octets[0], octets[1], octets[2], octets[3]);
  const size = 2 ** (32 - prefix);
  const start = Math.floor(ip / size) * size;
  if (start !== ip) throw new Error(`${raw} has host bits set. Use ${toIp(start)}/${prefix} for the whole range, or a single address.`);
  const end = start + size - 1;
  const blocked = RESERVED.find(({ r }) => start <= r[1] && end >= r[0]);
  if (blocked) throw new Error(`${raw} is in a range that can never be scanned: ${blocked.label}.`);
  const isPrivate = PRIVATE.some((r) => start >= r[0] && end <= r[1]);
  return { network: prefix === 32 ? toIp(start) : `${toIp(start)}/${prefix}`, prefix, start, end, public: !isPrivate };
}

export const normalizeTarget = (value: unknown) => parseCidr(value).network;

/** True only if the target is wholly inside an Approved, unexpired, unrevoked scope. */
export function targetAllowed(target: string, scopes: VaptScope[], now = Date.now()): VaptScope | null {
  let candidate: Cidr;
  try { candidate = parseCidr(target); } catch { return null; }
  for (const scope of scopes) {
    // Fail closed: an unparseable expiry (NaN) must never count as "not yet expired".
    const expires = Date.parse(scope.expiresAt);
    if (scope.status !== "Approved" || !Number.isFinite(expires) || expires <= now) continue;
    for (const approved of scope.targets) {
      try {
        const p = parseCidr(approved);
        if (candidate.start >= p.start && candidate.end <= p.end) return scope;
      } catch { /* a corrupt stored target never grants access */ }
    }
  }
  return null;
}

/* ------------------------------- scope storage -------------------------------- */

let writeChain: Promise<unknown> = Promise.resolve();
/** Serialises read-modify-write cycles so two concurrent approvals cannot lose an update. */
function withScopes<T>(fn: (scopes: VaptScope[]) => Promise<{ scopes: VaptScope[]; result: T }>): Promise<T> {
  const run = writeChain.then(async () => {
    const { scopes, result } = await fn(await readScopes());
    await fs.mkdir(path.dirname(scopesPath()), { recursive: true });
    const temp = `${scopesPath()}.${process.pid}.tmp`;
    await fs.writeFile(temp, JSON.stringify(scopes, null, 2), { mode: 0o600 });
    await fs.rename(temp, scopesPath());
    return result;
  });
  writeChain = run.catch(() => undefined);
  return run;
}

export async function readScopes(): Promise<VaptScope[]> {
  try {
    const value = JSON.parse(await fs.readFile(scopesPath(), "utf8"));
    return Array.isArray(value) ? (value as VaptScope[]) : [];
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return [];
    throw error;
  }
}

export type ScopeInput = {
  name?: unknown; authorizationReference?: unknown; targets?: unknown; expiresAt?: unknown; acknowledgePublic?: unknown;
};

export async function createScope(input: ScopeInput, actor: { email?: string | null; name?: string | null }): Promise<VaptScope> {
  const name = String(input.name ?? "").trim().slice(0, 100);
  const authorizationReference = String(input.authorizationReference ?? "").trim().slice(0, 120);
  const rawTargets = Array.isArray(input.targets) ? input.targets : String(input.targets ?? "").split(/[\n,;]+/);
  const cidrs = [...new Map(rawTargets.map((t) => String(t).trim()).filter(Boolean).map((t) => parseCidr(t)).map((c) => [c.network, c])).values()];
  const expires = Date.parse(String(input.expiresAt ?? ""));

  if (!name) throw new Error("A scope name is required.");
  if (authorizationReference.length < MIN_REFERENCE_LENGTH) {
    throw new Error(`The authorization reference must identify the written authorization (at least ${MIN_REFERENCE_LENGTH} characters, e.g. a contract or ticket number).`);
  }
  if (!cidrs.length) throw new Error("At least one target is required.");
  if (cidrs.length > MAX_TARGETS_PER_SCOPE) throw new Error(`At most ${MAX_TARGETS_PER_SCOPE} targets per scope.`);
  if (!Number.isFinite(expires) || expires <= Date.now()) throw new Error("A future expiry is required.");
  if (expires > Date.now() + MAX_SCOPE_DAYS * 86_400_000) throw new Error(`An authorization can last at most ${MAX_SCOPE_DAYS} days. Register a new scope to extend.`);
  const includesPublicRanges = cidrs.some((c) => c.public);
  if (includesPublicRanges && input.acknowledgePublic !== true) {
    throw new Error("This scope includes publicly routable addresses. Confirm you hold written authorization from the asset owner for them.");
  }

  const scope: VaptScope = {
    id: `scope_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    name, authorizationReference,
    targets: cidrs.map((c) => c.network),
    expiresAt: new Date(expires).toISOString(),
    status: "Approved",
    createdAt: new Date().toISOString(),
    createdBy: actor.email || actor.name || "unknown",
    includesPublicRanges
  };
  return withScopes(async (scopes) => ({ scopes: [...scopes, scope], result: scope }));
}

/** `changed` is false when the scope was already revoked, so callers audit real changes only. */
export async function revokeScope(
  id: string,
  actor: { email?: string | null; name?: string | null }
): Promise<{ scope: VaptScope; changed: boolean } | null> {
  return withScopes<{ scope: VaptScope; changed: boolean } | null>(async (scopes) => {
    const found = scopes.find((s) => s.id === id);
    if (!found) return { scopes, result: null };
    if (found.status === "Revoked") return { scopes, result: { scope: found, changed: false } };
    const revoked: VaptScope = { ...found, status: "Revoked", revokedAt: new Date().toISOString(), revokedBy: actor.email || actor.name || "unknown" };
    return { scopes: scopes.map((s) => (s.id === id ? revoked : s)), result: { scope: revoked, changed: true } };
  });
}

/* ---------------------------------- bridge ------------------------------------ */

const bridgeTimeout = () => Number(process.env.GREENBONE_TIMEOUT_MS || 15000);

type CodedError = Error & { code?: string };
const coded = (message: string, code: string): CodedError => Object.assign(new Error(message), { code });

async function bridgeFetch(pathname: string, options: RequestInit = {}): Promise<any> {
  const base = String(process.env.GREENBONE_BRIDGE_URL || "").trim().replace(/\/+$/, "");
  const token = String(process.env.GREENBONE_BRIDGE_TOKEN || "");
  if (!base || !token) throw coded("Configure GREENBONE_BRIDGE_URL and GREENBONE_BRIDGE_TOKEN in .env.", "NOT_CONFIGURED");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), bridgeTimeout());
  try {
    const response = await fetch(`${base}${pathname}`, {
      ...options,
      signal: controller.signal,
      cache: "no-store",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
        ...(options.body ? { "Content-Type": "application/json" } : {})
      }
    });
    let body: any = {};
    try { body = await response.json(); } catch { body = {}; }
    if (!response.ok) throw coded(String(body?.error || `Greenbone bridge request failed (${response.status}).`).slice(0, 240), "BRIDGE_REQUEST");
    return body;
  } catch (error) {
    if ((error as Error).name === "AbortError") throw coded("Greenbone bridge timed out.", "TIMEOUT");
    if ((error as CodedError).code) throw error;
    throw coded("Could not reach the Greenbone bridge. Check GREENBONE_BRIDGE_URL and that the bridge is running.", "UNREACHABLE");
  } finally {
    clearTimeout(timer);
  }
}

export async function getVaptOverview(): Promise<VaptOverview> {
  const checkedAt = new Date().toISOString();
  try {
    const data = await bridgeFetch("/v1/overview");
    return {
      status: { configured: true, connected: true, message: data.message || "Greenbone connected.", checkedAt },
      version: data.version || "Unknown",
      targets: Array.isArray(data.targets) ? data.targets : [],
      tasks: Array.isArray(data.tasks) ? data.tasks : []
    };
  } catch (error) {
    return {
      status: { configured: (error as CodedError).code !== "NOT_CONFIGURED", connected: false, message: (error as Error).message || "Greenbone unavailable.", checkedAt },
      version: null, targets: [], tasks: []
    };
  }
}

/** Calls the bridge. Callers MUST have passed targetAllowed() first. */
export async function launchVaptAssessment(input: { target: string; name?: unknown }): Promise<VaptAssessment> {
  const name = String(input.name || "PrimeSEC assessment").slice(0, 80);
  return bridgeFetch("/v1/assessments", { method: "POST", body: JSON.stringify({ target: normalizeTarget(input.target), name }) });
}
