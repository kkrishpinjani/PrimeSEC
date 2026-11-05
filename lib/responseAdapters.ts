/**
 * The one response adapter that ships: it acts only inside PrimeSEC and touches no other system.
 *
 *   watch_asset  puts the tag "watchlist" on an inventory asset so analysts see it flagged. Rollback removes the tag again,
 *                but only if this execution is the one that added it.
 *
 * It is registered on first use but stays inert unless an administrator turns execution on (RESPONSE_EXECUTION_ENABLED=true)
 * and lists "watch_asset" in RESPONSE_ALLOWED_ACTIONS. Acting on real systems (blocking an address, isolating a host)
 * still needs its own, narrowly scoped adapter.
 */
import { readInventory, setAssetTag } from "./inventory.ts";
import { registry, registerAdapter, ResponseError, type ResponseAdapter } from "./response.ts";

export const WATCH_TAG = "watchlist";

export const inventoryWatchAdapter: ResponseAdapter = {
  name: "inventory-watch",
  supportedActions: ["watch_asset"],
  async execute(_action, target) {
    const r = await setAssetTag(target, WATCH_TAG, true);
    if (!r.found) throw new ResponseError(`No inventory asset has the id "${target}".`, "NOT_FOUND");
    // A second run with the same key finds the tag already there: say so, so rollback never removes a tag this run did not add.
    return { tag: WATCH_TAG, added: r.changed };
  },
  async verify(execution) {
    const asset = (await readInventory()).assets.find((a) => a.id === execution.target);
    return { verified: Boolean(asset?.tags.includes(WATCH_TAG)), assetFound: Boolean(asset) };
  },
  async rollback(execution) {
    if (execution.result?.added !== true) return { rolledBack: true, note: "The tag was already present before this action, so it was left in place." };
    const r = await setAssetTag(execution.target, WATCH_TAG, false);
    return { rolledBack: r.found, removed: r.changed };
  }
};

/** Safe to call on every request. */
export function ensureAdapters(): void {
  if (!registry.byName(inventoryWatchAdapter.name)) registerAdapter(inventoryWatchAdapter);
}
