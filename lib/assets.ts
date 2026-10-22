/**
 * Asset context for risk scoring: how critical a host is to the business and how exposed it is.
 * This is a property of the HOST, not of each finding, so it is stored once per host and applies to every
 * finding on it. It is an input to prioritisation only: it never changes a scan or a host.
 */
import { promises as fs } from "fs";
import path from "path";

export const CRITICALITIES = ["Unknown", "Low", "Medium", "High", "Critical"] as const;
export const EXPOSURES = ["Unknown", "Internal", "Internet-facing"] as const;
export type Criticality = (typeof CRITICALITIES)[number];
export type Exposure = (typeof EXPOSURES)[number];

export type Asset = {
  host: string;
  criticality: Criticality;
  exposure: Exposure;
  updatedAt: string | null;
  updatedBy: string | null;
};

export type AssetPatch = { criticality?: unknown; exposure?: unknown; expectedUpdatedAt?: unknown };
export class AssetError extends Error {
  code: "INVALID" | "CONFLICT";
  constructor(message: string, code: "INVALID" | "CONFLICT") {
    super(message);
    this.code = code;
  }
}

const storePath = () => path.join(process.cwd(), "data", "vapt-assets.json");
export const hostKey = (host: string) => host.trim().toLowerCase();

let chain: Promise<unknown> = Promise.resolve();
function withStore<T>(fn: (items: Asset[]) => Promise<{ items: Asset[]; result: T }>): Promise<T> {
  const run = chain.then(async () => {
    const { items, result } = await fn(await readAssets());
    await fs.mkdir(path.dirname(storePath()), { recursive: true });
    const temp = `${storePath()}.${process.pid}.tmp`;
    await fs.writeFile(temp, JSON.stringify(items, null, 2), { mode: 0o600 });
    await fs.rename(temp, storePath());
    return result;
  });
  chain = run.catch(() => undefined);
  return run;
}

export async function readAssets(): Promise<Asset[]> {
  try {
    const value = JSON.parse(await fs.readFile(storePath(), "utf8"));
    return Array.isArray(value) ? (value as Asset[]) : [];
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return [];
    throw error;
  }
}

export async function assetMap(): Promise<Map<string, Asset>> {
  return new Map((await readAssets()).map((a) => [hostKey(a.host), a]));
}

/**
 * Sets a host's criticality and/or exposure. Only the fields present change. `expectedUpdatedAt` is optimistic
 * concurrency (null = "I expect no record yet"): if someone else edited the host first, the update is refused.
 */
export async function updateAsset(host: string, patch: AssetPatch, actor: { email?: string | null; name?: string | null }): Promise<{ asset: Asset; before: Asset | null }> {
  const key = hostKey(host);
  if (!key || key.length > 255) throw new AssetError("A host is required.", "INVALID");
  if (patch.criticality !== undefined && !CRITICALITIES.includes(patch.criticality as Criticality)) {
    throw new AssetError(`Invalid criticality. Allowed: ${CRITICALITIES.join(", ")}.`, "INVALID");
  }
  if (patch.exposure !== undefined && !EXPOSURES.includes(patch.exposure as Exposure)) {
    throw new AssetError(`Invalid exposure. Allowed: ${EXPOSURES.join(", ")}.`, "INVALID");
  }
  return withStore(async (items) => {
    const index = items.findIndex((a) => hostKey(a.host) === key);
    const before = index >= 0 ? items[index] : null;
    if ("expectedUpdatedAt" in patch && (patch.expectedUpdatedAt ?? null) !== (before?.updatedAt ?? null)) {
      throw new AssetError("This asset was changed by someone else. Reload it and try again.", "CONFLICT");
    }
    const asset: Asset = {
      host: before?.host ?? host.trim(),
      criticality: (patch.criticality as Criticality | undefined) ?? before?.criticality ?? "Unknown",
      exposure: (patch.exposure as Exposure | undefined) ?? before?.exposure ?? "Unknown",
      updatedAt: new Date().toISOString(),
      updatedBy: actor.email || actor.name || "unknown"
    };
    const next = items.slice();
    if (index >= 0) next[index] = asset; else next.push(asset);
    return { items: next, result: { asset, before } };
  });
}
