// Tests for the Neo4j security graph: allow-lists, injection resistance, property sanitising, namespace constraints,
// atomic upsert, error handling and the inventory projection. Uses a fake Neo4j HTTP endpoint; no database needed.
// Run: npm run test:graph (Node 22.6+; TypeScript is type-stripped).
import path from "node:path";

const root = process.cwd();
const url = (f) => path.join(root, "lib", f).replace(/\\/g, "/").replace(/^([A-Za-z]):/, "file:///$1:");
const G = await import(url("graph.ts"));

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const bad = (name, fn) => { try { fn(); fail++; console.log("FAIL (no error):", name); } catch (e) { (e.code === "INVALID") ? pass++ : (fail++, console.log("FAIL (wrong error):", name, e.message)); } };

const cfg = { url: "http://neo4j.test:7474", username: "neo4j", password: "pw-secret", database: "neo4j", namespace: "ns-A", timeoutMs: 1000 };
let requests = [];
let reply = (statements) => ({ status: 200, body: { results: statements.map(() => ({ data: [] })), errors: [] } });
const fakeFetch = async (u, init) => {
  const body = JSON.parse(init.body);
  requests.push({ url: u, headers: init.headers, body });
  const r = reply(body.statements);
  return new Response(JSON.stringify(r.body), { status: r.status });
};
const client = () => new G.GraphClient(cfg, fakeFetch);

// ---- configuration ----
ok("unconfigured when any setting is missing", G.graphConfig({}) === null && G.graphConfig({ NEO4J_HTTP_URL: "http://x", NEO4J_USERNAME: "u" }) === null);
ok("configured reads URL, database and namespace", (() => { const c = G.graphConfig({ NEO4J_HTTP_URL: "http://x:7474/", NEO4J_USERNAME: "u", NEO4J_PASSWORD: "p", NEO4J_NAMESPACE: "acme" }); return c.url === "http://x:7474" && c.database === "neo4j" && c.namespace === "acme"; })());
ok("a database name with odd characters is refused", G.graphConfig({ NEO4J_HTTP_URL: "http://x", NEO4J_USERNAME: "u", NEO4J_PASSWORD: "p", NEO4J_DATABASE: "a/b?x=1" }) === null);
let nc = null;
try { await new G.GraphClient(null, fakeFetch).health(); } catch (e) { nc = e.code; }
ok("an unconfigured client says so and makes no request", nc === "NOT_CONFIGURED" && requests.length === 0);

// ---- validation: allow-lists ----
bad("node label injection rejected", () => G.validateBatch({ nodes: [{ type: "Asset) DETACH DELETE n //", id: "x" }] }));
bad("unknown node type rejected", () => G.validateBatch({ nodes: [{ type: "Secret", id: "x" }] }));
bad("relationship type injection rejected", () => G.validateBatch({ relationships: [{ sourceType: "Asset", sourceId: "a", targetType: "Vulnerability", targetId: "b", type: "HAS_VULNERABILITY]->() DETACH DELETE a //" }] }));
bad("relationship endpoint type rejected", () => G.validateBatch({ relationships: [{ sourceType: "Nope", sourceId: "a", targetType: "Asset", targetId: "b", type: "CONNECTED_TO" }] }));
bad("empty batch rejected", () => G.validateBatch({}));
bad("missing id rejected", () => G.validateBatch({ nodes: [{ type: "Asset" }] }));
bad("overlong id rejected", () => G.validateBatch({ nodes: [{ type: "Asset", id: "x".repeat(257) }] }));
bad("too many nodes rejected", () => G.validateBatch({ nodes: Array.from({ length: 1001 }, (_, i) => ({ type: "Asset", id: String(i) })) }));
bad("not an object rejected", () => G.validateBatch("hello"));
const good = G.validateBatch({ nodes: [{ type: "Asset", id: "asset-1", properties: { name: "ERP" } }], relationships: [{ sourceType: "Asset", sourceId: "asset-1", targetType: "Vulnerability", targetId: "CVE-1", type: "HAS_VULNERABILITY" }] });
ok("a valid batch is accepted", good.nodes[0].type === "Asset" && good.relationships[0].type === "HAS_VULNERABILITY");

// ---- property sanitising ----
const sp = G.safeProperties({ tenant_id: "attacker", external_id: "override", id: "x", name: "host", labels: ["prod", "critical"], nested: { x: 1 }, "bad key": 1, "a;b": 2, n: null, big: Infinity, mixed: ["a", { x: 1 }], withNull: ["a", null] });
ok("reserved keys, nested maps, odd names and non-finite numbers are dropped", JSON.stringify(sp) === JSON.stringify({ name: "host", labels: ["prod", "critical"], n: null }), JSON.stringify(sp));
ok("long strings are clipped", G.safeProperties({ s: "x".repeat(5000) }).s.length === 1000);
ok("a non-object is an empty set of properties", Object.keys(G.safeProperties("x")).length === 0 && Object.keys(G.safeProperties([1])).length === 0);

// ---- statements ----
const stmts = client().upsertStatements(good);
ok("every statement is constrained by the namespace and passes values as parameters", stmts.every((s) => s.statement.includes("tenant_id:$tenant") && s.parameters.tenant === "ns-A"));
ok("no value ever appears inside query text", stmts.every((s) => !s.statement.includes("asset-1") && !s.statement.includes("ERP") && !s.statement.includes("CVE-1")));
ok("a caller's property cannot override the namespace", (() => { const s = client().upsertStatements(G.validateBatch({ nodes: [{ type: "Asset", id: "a", properties: { tenant_id: "other" } }] })); return !("tenant_id" in s[0].parameters.props) && s[0].parameters.tenant === "ns-A"; })());
ok("the last line of defence rejects a forged batch", (() => { try { client().upsertStatements({ nodes: [{ type: "Asset) DETACH DELETE n //", id: "x" }], relationships: [] }); return false; } catch (e) { return e.code === "INVALID"; } })());

// ---- upsert: one transaction, auth header, counts ----
requests = [];
reply = (s) => ({ status: 200, body: { results: s.map((st, i) => ({ data: st.statement.startsWith("MATCH") ? [{ row: [1] }] : [] })), errors: [] } });
const up = await client().upsert(good);
ok("a batch is sent as exactly one transaction", requests.length === 1 && requests[0].body.statements.length === 2 && requests[0].url === "http://neo4j.test:7474/db/neo4j/tx/commit");
ok("basic auth is sent, and only in the header", requests[0].headers.Authorization === `Basic ${Buffer.from("neo4j:pw-secret").toString("base64")}` && !JSON.stringify(requests[0].body).includes("pw-secret"));
ok("counts report linked relationships", up.nodes === 1 && up.relationships === 1 && up.linked === 1 && up.skipped === 0);
reply = (s) => ({ status: 200, body: { results: s.map(() => ({ data: [] })), errors: [] } });
const up2 = await client().upsert(good);
ok("a relationship whose end nodes are missing is counted as skipped", up2.linked === 0 && up2.skipped === 1);

// ---- errors ----
reply = () => ({ status: 200, body: { results: [], errors: [{ code: "Neo.ClientError.Statement.SyntaxError", message: "Invalid input near password pw-secret at host neo4j.test" }] } });
let msg = "";
try { await client().health(); } catch (e) { msg = e.message; }
ok("a Cypher error surfaces only its code, never the message", msg.includes("Neo.ClientError.Statement.SyntaxError") && !msg.includes("pw-secret") && !msg.includes("neo4j.test"), msg);
reply = () => ({ status: 401, body: {} });
let m401 = "";
try { await client().health(); } catch (e) { m401 = e.message; }
ok("bad credentials are reported plainly", /credentials/.test(m401));
const down = new G.GraphClient(cfg, async () => { throw new Error("connect ECONNREFUSED 10.0.0.5:7474"); });
let mdown = "";
try { await down.health(); } catch (e) { mdown = e.message; }
ok("an unreachable server does not leak its address", mdown === "Neo4j could not be reached." && !mdown.includes("10.0.0.5"));
reply = () => ({ status: 200, body: { results: [{ data: [{ row: [1] }] }], errors: [] } });
ok("health is true on RETURN 1", (await client().health()) === true);

// ---- read queries ----
requests = [];
reply = () => ({ status: 200, body: { results: [{ data: [{ row: [[{ type: "Asset", id: "a", name: "A" }, { type: "Vulnerability", id: "CVE-1", name: "CVE-1" }], ["HAS_VULNERABILITY"]] }] }], errors: [] } });
const paths = await client().attackPaths("a", 9999);
ok("attack paths are parsed", paths.length === 1 && paths[0].nodes.length === 2 && paths[0].relationships[0] === "HAS_VULNERABILITY");
ok("path queries are namespace-constrained, parameterised and capped", requests[0].body.statements[0].statement.includes("tenant_id:$tenant") && requests[0].body.statements[0].parameters.tenant === "ns-A" && requests[0].body.statements[0].parameters.asset === "a" && requests[0].body.statements[0].parameters.limit === 100);
ok("a path query for an empty asset id is refused", await (async () => { try { await client().attackPaths("", 5); return false; } catch (e) { return e.code === "INVALID"; } })());
requests = [];
reply = () => ({ status: 200, body: { results: [{ data: [{ row: ["a", "A", 2, [{ id: "CVE-1", severity: "high", cve: "CVE-1" }]] }] }], errors: [] } });
const exp = await client().assetExposure(5);
ok("exposure rows are parsed", exp[0].assetId === "a" && exp[0].vulnerabilityCount === 2);
ok("the exposure query constrains both assets and vulnerabilities by namespace", (requests[0].body.statements[0].statement.match(/tenant_id:\$tenant/g) ?? []).length === 2);

// ---- projection from the inventory ----
const now = "2026-01-01T00:00:00Z";
const inv = {
  assets: [
    { id: "ast_1", name: "web-01", assetType: "endpoint", hostname: "web-01", primaryIp: "10.0.0.1", environment: "prod", criticality: 5, internetFacing: true, riskScore: 90, riskLevel: "critical", sources: { wazuh: now } },
    { id: "ast_2", name: "db-01", assetType: "host", hostname: null, primaryIp: null, environment: null, criticality: null, internetFacing: false, riskScore: 15, riskLevel: "low", sources: { greenbone: now } }
  ],
  vulns: [
    { assetId: "ast_1", key: "CVE-2025-1", cve: "CVE-2025-1", title: "RCE", severity: "critical", cvss: 9.8, status: "open", source: "greenbone", firstSeen: now, lastSeen: now },
    { assetId: "ast_2", key: "CVE-2025-1", cve: "CVE-2025-1", title: "RCE", severity: "critical", cvss: 9.8, status: "open", source: "greenbone", firstSeen: now, lastSeen: now },
    { assetId: "ast_2", key: "CVE-2020-9", cve: "CVE-2020-9", title: "Old", severity: "high", cvss: 7, status: "fixed", source: "greenbone", firstSeen: now, lastSeen: now }
  ],
  observations: []
};
const proj = G.projectInventory(inv);
ok("one Asset node per inventory asset, one Vulnerability per distinct open key", proj.nodes.filter((n) => n.type === "Asset").length === 2 && proj.nodes.filter((n) => n.type === "Vulnerability").length === 1);
ok("each open finding becomes an edge; a fixed one does not", proj.relationships.length === 2 && !proj.relationships.some((r) => r.targetId === "CVE-2020-9"));
ok("the projection passes the same validation as an API batch", (() => { try { G.validateBatch(proj); return true; } catch { return false; } })());
const chunks = G.chunkBatch({ nodes: Array.from({ length: 2500 }, (_, i) => ({ type: "Asset", id: String(i) })), relationships: Array.from({ length: 3100 }, () => ({ sourceType: "Asset", sourceId: "1", targetType: "Asset", targetId: "2", type: "CONNECTED_TO" })) });
ok("large projections are split within limits, nodes before relationships", chunks.length === 5 && chunks.slice(0, 3).every((c) => c.relationships.length === 0 && c.nodes.length <= 1000) && chunks.slice(3).every((c) => c.nodes.length === 0 && c.relationships.length <= 3000));

// ---- pruning what an earlier projection left behind ----
ok("everything the projection creates is stamped origin:inventory", proj.nodes.every((n) => n.properties.origin === "inventory") && proj.relationships.every((r) => r.properties.origin === "inventory"));
const keys = G.projectionKeys(proj);
ok("the projection's identifiers are listed for the prune", keys.assetIds.length === 2 && keys.pairs.sort().join() === "ast_1|CVE-2025-1,ast_2|CVE-2025-1");
requests = [];
reply = () => ({ status: 200, body: { results: [{ data: [{ row: [3] }] }, { data: [{ row: [1] }] }, { data: [{ row: [2] }] }], errors: [] } });
const pr = await client().pruneProjection(keys.assetIds, keys.pairs);
ok("prune runs as ONE transaction of three statements and reports each count", requests.length === 1 && requests[0].body.statements.length === 3 && pr.links === 3 && pr.assets === 1 && pr.vulnerabilities === 2);
ok("every prune statement is namespace-constrained and passes values as parameters", requests[0].body.statements.every((s) => s.statement.includes("tenant_id:$tenant") && s.parameters.tenant === "ns-A") && !requests[0].body.statements.some((s) => s.statement.includes("ast_1") || s.statement.includes("CVE-2025-1")));
ok("prune can only delete objects stamped origin:inventory (never ones added through ingest)", requests[0].body.statements.every((s) => s.statement.includes("origin:'inventory'")));
ok("the prune keeps exactly the identifiers it was given", JSON.stringify(requests[0].body.statements[1].parameters.ids) === JSON.stringify(keys.assetIds) && requests[0].body.statements[0].parameters.pairs.length === 2);
reply = () => ({ status: 200, body: { results: [], errors: [{ code: "Neo.ClientError.Statement.SyntaxError", message: "boom" }] } });
ok("a failed prune surfaces an error and deletes nothing it was not asked to", await (async () => { try { await client().pruneProjection([], []); return false; } catch (e) { return e.code === "UNAVAILABLE"; } })());

console.log(`graph: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
