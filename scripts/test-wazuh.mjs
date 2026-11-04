// Tests for the read-only Wazuh explorer: fixed resources, validation, path building, agent scope, mapping, error handling.
// Run: npm run test:wazuh (Node 22.6+; TypeScript is type-stripped).
import path from "node:path";

const root = process.cwd();
const W = await import(path.join(root, "lib", "wazuh.ts").replace(/\\/g, "/").replace(/^([A-Za-z]):/, "file:///$1:"));

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const code = async (fn) => { try { await fn(); return null; } catch (e) { return e.code ?? `UNEXPECTED:${e.message}`; } };
const sync = (fn) => { try { fn(); return null; } catch (e) { return e.code ?? `UNEXPECTED:${e.message}`; } };

let apiCalls = [], idxCalls = [];
let apiReply = (p) => ({ data: { affected_items: [], total_affected_items: 0 } });
let idxReply = () => ({ hits: { total: { value: 0 }, hits: [] } });
const deps = (env = {}, over = {}) => ({
  api: async (p) => { apiCalls.push(p); return apiReply(p); },
  indexer: async (i, b) => { idxCalls.push({ i, b }); return idxReply(); },
  apiConfigured: () => true, indexerConfigured: () => true, safeError: () => "Could not reach the upstream platform.", env, ...over
});
const P = (r, a = {}, env = {}) => W.buildPlan(r, a, env);

// ---- the resource list is closed ----
ok("21 fixed resources, none of which writes", W.RESOURCES.length === 21 && !W.RESOURCES.some((r) => /restart|delete|active|command|update|put|post/i.test(r)));
ok("an unknown resource is rejected", sync(() => P("agents/../manager/configuration")) === "INVALID" && sync(() => P("active-response")) === "INVALID" && sync(() => P(undefined)) === "INVALID" && sync(() => P(["agents"])) === "INVALID");

// ---- path building ----
ok("fixed manager paths", P("manager-info").path === "/manager/info" && P("manager-status").path === "/manager/status" && P("cluster-nodes").path === "/cluster/nodes");
ok("agents: limit, offset, status and search are encoded", P("agents", { limit: "50", offset: "10", status: "ACTIVE", search: "web 01&x=1" }).path === "/agents?limit=50&offset=10&status=active&search=web+01%26x%3D1&sort=id");
ok("agent-scoped paths put only a validated numeric id in the path", P("syscheck", { agent: "001", path: "/etc/passwd" }).path === "/syscheck/001?limit=100&offset=0&file=%2Fetc%2Fpasswd" && P("sca", { agent: "12" }).path === "/sca/12?limit=100&offset=0" && P("rootcheck", { agent: "003" }).path.startsWith("/rootcheck/003"));
ok("agent ids cannot smuggle a path", ["../000", "001/../../x", "001?x=1", "00 1", "", "abc", "1".repeat(11)].every((bad) => sync(() => P("syscheck", { agent: bad })) === "INVALID"));
ok("a missing agent is rejected for agent resources", sync(() => P("agent-os", {})) === "INVALID");
ok("group names are validated", P("group-agents", { group: "default" }).path.startsWith("/groups/default/agents") && sync(() => P("group-agents", { group: "../agents" })) === "INVALID" && sync(() => P("group-agents", { group: "a/b" })) === "INVALID");
ok("mitre and rules paths", P("mitre-techniques", { search: "T1110" }).path === "/mitre/techniques?limit=100&offset=0&search=T1110" && P("rules", { q: "level>10" }).path.includes("q=level%3E10"));

// ---- validation ----
ok("limit is bounded 1-500 and a whole number", sync(() => P("agents", { limit: 0 })) === "INVALID" && sync(() => P("agents", { limit: 501 })) === "INVALID" && sync(() => P("agents", { limit: "5.5" })) === "INVALID" && sync(() => P("agents", { limit: "abc" })) === "INVALID" && P("agents", { limit: 500 }).path.includes("limit=500"));
ok("offset cannot be negative", sync(() => P("agents", { offset: -1 })) === "INVALID");
ok("status must be a known value", sync(() => P("agents", { status: "deleted" })) === "INVALID");
ok("control characters and overlong text are rejected", sync(() => P("rules", { search: "a\nb" })) === "INVALID" && sync(() => P("rules", { search: "x".repeat(201) })) === "INVALID" && sync(() => P("rules", { search: { a: 1 } })) === "INVALID");
ok("severity must be a known value", sync(() => P("vulnerabilities", { agent: "001", severity: "Extreme" })) === "INVALID");

// ---- alerts and vulnerabilities go to the Indexer with parameters, not text ----
const al = P("alerts", { severityMin: "7", start: "2026-11-01T00:00:00Z", search: "ssh failed" }, {});
ok("alerts: level, time range and search are structured filters", al.kind === "indexer" && al.index === "wazuh-alerts-4.x-*" && al.body.query.bool.filter[0].range["rule.level"].gte === 7 && al.body.query.bool.filter.some((f) => f.range?.timestamp?.gte === "2026-11-01T00:00:00.000Z") && al.body.query.bool.must[0].simple_query_string.query === "ssh failed");
ok("alerts: the text search is lenient about field types (OpenSearch returns 400 otherwise)", al.body.query.bool.must[0].simple_query_string.lenient === true);
ok("alerts: an invalid date or level is rejected", sync(() => P("alerts", { start: "yesterday" })) === "INVALID" && sync(() => P("alerts", { severityMin: 16 })) === "INVALID");
ok("alerts: the index pattern comes from config", P("alerts", {}, { WAZUH_ALERT_INDEX_PATTERN: "custom-*" }).index === "custom-*");
const vu = P("vulnerabilities", { agent: "001", severity: "critical" }, {});
ok("vulnerabilities: Manager API is NOT used (removed in Wazuh 4.8); the Indexer is", vu.kind === "indexer" && vu.index === "wazuh-states-vulnerabilities-*" && vu.body.query.bool.filter[0].term["agent.id"] === "001" && vu.body.query.bool.filter[1].term["vulnerability.severity"] === "Critical");

// ---- agent scope ----
const SC = { WAZUH_AGENT_ALLOWLIST: "001, 002" };
ok("the allow-list parses and ignores blanks", W.agentAllowlist(SC).size === 2 && W.agentAllowlist({}) === null && W.agentAllowlist({ WAZUH_AGENT_ALLOWLIST: " , " }) === null);
ok("an out-of-scope agent is FORBIDDEN on every agent resource", ["agent", "agent-os", "syscheck", "rootcheck", "sca", "vulnerabilities"].every((r) => sync(() => P(r, { agent: "003" }, SC)) === "FORBIDDEN"));
ok("an in-scope agent is allowed", sync(() => P("sca", { agent: "002" }, SC)) === null);
ok("the manager (000) is out of scope unless listed", sync(() => P("agent", { agent: "000" }, SC)) === "FORBIDDEN" && sync(() => P("agent", { agent: "000" }, { WAZUH_AGENT_ALLOWLIST: "000" })) === null);
ok("alerts are restricted to the allow-list even with no agent given", P("alerts", {}, SC).body.query.bool.filter.some((f) => f.terms?.["agent.id"]?.join() === "001,002"));
ok("an alert query for an out-of-scope agent is refused", sync(() => P("alerts", { agent: "003" }, SC)) === "FORBIDDEN");
ok("all-vulnerabilities is restricted to the allow-list", P("all-vulnerabilities", {}, SC).body.query.bool.filter[0].terms["agent.id"].join() === "001,002");

// ---- execution ----
apiCalls = [];
apiReply = () => ({ data: { affected_items: [{ id: "000", name: "mgr" }, { id: "001", name: "a" }, { id: "003", name: "c" }], total_affected_items: 3 } });
const scoped = await W.explore("agents", {}, deps(SC));
ok("agent lists are filtered to the allow-list and the total is corrected", scoped.items.length === 1 && scoped.items[0].id === "001" && scoped.total === 1);
const open = await W.explore("agents", {}, deps({}));
ok("with no allow-list, all agents come back", open.items.length === 3 && open.total === 3 && open.readOnly === true && open.source === "manager");
ok("the upstream path that was called is exactly the built one", apiCalls.at(-1) === "/agents?limit=100&offset=0&sort=id");
apiReply = () => ({ data: { affected_items: [{ id: "001" }, { id: "009" }], total_affected_items: 2 } });
const ga = await W.explore("group-agents", { group: "default" }, deps(SC));
ok("group membership is filtered to the allow-list", ga.items.length === 1 && ga.items[0].id === "001");
apiReply = () => ({ data: { rootcheck_enabled: true } });
ok("a non-list response is returned as data", (await W.explore("manager-status", {}, deps())).data.rootcheck_enabled === true);

apiReply = (p) => p.startsWith("/manager/info") ? { data: { affected_items: [{ version: "v4.14.9" }] } } : p.startsWith("/agents/summary") ? { data: { connection: { active: 1 } } } : { data: { affected_items: [{ id: "000", name: "m", status: "active", os: { name: "Amazon Linux" }, group: [] }, { id: "001", name: "a", status: "active", os: { name: "Ubuntu" }, group: ["default"] }], total_affected_items: 2 } };
const ov = await W.explore("overview", {}, deps());
ok("overview combines manager, summary and agents", ov.data.manager.version === "v4.14.9" && ov.data.agentSummary.connection.active === 1 && ov.items.length === 2 && ov.items[1].os === "Ubuntu" && ov.data.scopeRestricted === false);
ok("overview respects the allow-list", (await W.explore("overview", {}, deps(SC))).items.length === 1);
const ovPartial = await W.explore("overview", {}, deps({}, { api: async (p) => { if (p.startsWith("/manager/info")) throw new Error("boom"); return apiReply(p); } }));
ok("overview survives one failing call and says so", ovPartial.items.length === 2 && /could not be read/.test(ovPartial.note));

// ---- a standalone manager has no cluster ----
const nc = await W.explore("cluster-nodes", {}, deps({}, { api: async () => { throw new Error("Wazuh API request failed (400)."); } }));
ok("cluster-nodes on a standalone manager says so instead of failing", nc.items.length === 0 && /not part of a cluster/.test(nc.note));
ok("a 400 on any other resource is still an error", await code(() => W.explore("rules", {}, deps({}, { api: async () => { throw new Error("Wazuh API request failed (400)."); } }))) === "UPSTREAM");

// ---- indexer mapping ----
idxReply = () => ({ hits: { total: { value: 2 }, hits: [{ _id: "A1", _source: { timestamp: "2026-11-02T00:00:00Z", rule: { level: 7, id: "5503", description: "login failed", groups: ["pam"], mitre: { id: ["T1110"] } }, agent: { id: "001", name: "a" }, data: { srcip: "203.0.113.5" } } }] } });
const alr = await W.explore("alerts", {}, deps());
ok("alerts are mapped to a small, stable shape", alr.source === "indexer" && alr.items[0].id === "A1" && alr.items[0].level === 7 && alr.items[0].mitre[0] === "T1110" && alr.items[0].sourceIp === "203.0.113.5" && alr.total === 2);
idxReply = () => ({ hits: { total: { value: 1 }, hits: [{ _source: { vulnerability: { id: "CVE-1", severity: "High", score: { base: 7.5 }, status: "Active" }, package: { name: "openssl", version: "3.0" }, agent: { id: "001", name: "a" } } }] } });
const vr = await W.explore("vulnerabilities", { agent: "001" }, deps());
ok("vulnerabilities are mapped", vr.items[0].cve === "CVE-1" && vr.items[0].score === 7.5 && vr.items[0].package === "openssl");
ok("the request sent to the Indexer is the built one", idxCalls.at(-1).i === "wazuh-states-vulnerabilities-*" && idxCalls.at(-1).b.size === 100);

// ---- errors ----
ok("an unconfigured Manager API is NOT_CONFIGURED", await code(() => W.explore("agents", {}, deps({}, { apiConfigured: () => false }))) === "NOT_CONFIGURED");
ok("an unconfigured Indexer is NOT_CONFIGURED", await code(() => W.explore("alerts", {}, deps({}, { indexerConfigured: () => false }))) === "NOT_CONFIGURED");
const upstream = await W.explore("agents", {}, deps({}, { api: async () => { throw new Error("connect ECONNREFUSED 10.0.0.9:55000 password=abc"); } })).catch((e) => e);
ok("an upstream failure is reported through the safe formatter, never the raw error", upstream.code === "UPSTREAM" && upstream.message === "Could not reach the upstream platform." && !/10\.0\.0\.9|abc/.test(upstream.message));
ok("invalid input never reaches an upstream", await (async () => { const before = apiCalls.length; await code(() => W.explore("syscheck", { agent: "../x" }, deps())); return apiCalls.length === before; })());

console.log(`wazuh: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
