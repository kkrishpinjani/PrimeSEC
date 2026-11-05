// Tests for the one adapter that ships (inventory-watch): idempotent execute, verify, and a rollback that only undoes its own work.
// Run: npm run test:response-adapter
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const root = process.cwd();
process.chdir(mkdtempSync(path.join(tmpdir(), "primesec-radapter-")));
const url = (f) => path.join(root, "lib", f).replace(/\\/g, "/").replace(/^([A-Za-z]):/, "file:///$1:");
const I = await import(url("inventory.ts"));
const R = await import(url("response.ts"));
const A = await import(url("responseAdapters.ts"));

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const code = async (fn) => { try { await fn(); return null; } catch (e) { return e.code ?? `UNEXPECTED:${e.message}`; } };

ok("nothing is registered until the API asks for it", R.registry.adapters.length === 0);
A.ensureAdapters(); A.ensureAdapters();
ok("ensureAdapters registers once", R.registry.adapters.length === 1 && R.registry.byName("inventory-watch") !== undefined);

await I.ingestAssets([{ source: "manual", sourceAssetId: "srv-1", name: "srv-1", identifiers: { cmdb_id: "C1" } }].map((x) => I.validateAssetInput(x)));
const asset = (await I.listAssets()).items[0];
const tags = async () => (await I.readInventory()).assets.find((a) => a.id === asset.id).tags;

const r1 = await A.inventoryWatchAdapter.execute("watch_asset", asset.id, "k1");
ok("execute adds the tag", r1.added === true && (await tags()).includes("watchlist"));
const r2 = await A.inventoryWatchAdapter.execute("watch_asset", asset.id, "k1");
ok("running it again changes nothing and says so", r2.added === false && (await tags()).filter((t) => t === "watchlist").length === 1);
ok("an unknown asset is refused", await code(() => A.inventoryWatchAdapter.execute("watch_asset", "nope", "k2")) === "NOT_FOUND");
ok("verify sees the tag", (await A.inventoryWatchAdapter.verify({ id: "e", actionType: "watch_asset", target: asset.id, result: r1 })).verified === true);
const undoSecond = await A.inventoryWatchAdapter.rollback({ id: "e", actionType: "watch_asset", target: asset.id, result: r2 });
ok("rolling back a run that added nothing leaves the tag", undoSecond.rolledBack === true && (await tags()).includes("watchlist"));
const undo = await A.inventoryWatchAdapter.rollback({ id: "e", actionType: "watch_asset", target: asset.id, result: r1 });
ok("rolling back the run that added it removes the tag", undo.rolledBack === true && !(await tags()).includes("watchlist"));
ok("verify fails once the tag is gone", (await A.inventoryWatchAdapter.verify({ id: "e", actionType: "watch_asset", target: asset.id, result: r1 })).verified === false);

// the whole governed path, with the policy gates on
const ON = { ...R.responseConfig({}), enabled: true, allowedActions: new Set(["watch_asset"]) };
const alice = { email: "alice@x" }, bob = { email: "bob@x" };
const p = await R.createProposal({ actionType: "watch_asset", target: asset.id, rationale: "Repeated failed SSH logins from a listed address" }, alice, ON);
ok("the proposer cannot approve their own proposal", await code(() => R.reviewProposal(p.id, "approve", "ok", alice, ON)) === "FORBIDDEN");
await R.reviewProposal(p.id, "approve", "ok", bob, ON);
const done = await R.executeProposal(p.id, "idem-key-12345678", bob, undefined, ON);
ok("an approved proposal executes through the registry", done.execution.status === "executed" && (await tags()).includes("watchlist"), JSON.stringify(done.execution));
const v = await R.verifyExecution(done.execution.id);
ok("and verifies", v.status === "verified");
const rb = await R.rollbackExecution(done.execution.id);
ok("and rolls back", rb.status === "rolled_back" && !(await tags()).includes("watchlist"));
const off = await code(() => R.executeProposal(p.id, "idem-key-87654321", bob, undefined, { ...ON, enabled: false }));
ok("with execution switched off nothing runs", off !== null);

console.log(`response adapter: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
