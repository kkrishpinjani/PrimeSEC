// Tests for the OpenCTI explorer: closed type list, variables-only values, marking enforcement (strict), shape fallback, errors.
// Run: npm run test:opencti (Node 22.6+; TypeScript is type-stripped).
import path from "node:path";

const root = process.cwd();
const url = (f) => path.join(root, "lib", f).replace(/\\/g, "/").replace(/^([A-Za-z]):/, "file:///$1:");
const O = await import(url("opencti.ts"));

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const code = async (fn) => { try { await fn(); return null; } catch (e) { return e.code ?? `UNEXPECTED:${e.message}`; } };

let calls = [];
let reply = () => ({});
const deps = (env = {}, over = {}) => ({ query: async (q, v) => { calls.push({ q, v }); return reply(q, v); }, configured: () => true, safeError: () => "Could not reach the upstream platform.", env, ...over });
const node = (over = {}) => ({ id: "i-1", name: "bad ip", description: "d".repeat(900), pattern: "[ipv4-addr:value = '1.2.3.4']", pattern_type: "stix", x_opencti_score: 80, indicator_types: ["malicious-activity"], objectLabel: [{ value: "c2" }], objectMarking: [{ definition: "TLP:CLEAR" }], ...over });
const page = (nodes) => ({ indicators: { pageInfo: { endCursor: "c1", hasNextPage: true, globalCount: 42 }, edges: nodes.map((n) => ({ node: n })) } });

// ---- the type list is closed ----
ok("five browse types", O.BROWSE_TYPES.length === 5);
ok("an unknown type is rejected before any call", await code(() => O.browse("users", {}, deps())) === "INVALID" && await code(() => O.browse("indicators) { id } } mutation { x", {}, deps())) === "INVALID" && await code(() => O.browse(undefined, {}, deps())) === "INVALID" && calls.length === 0);
ok("detail types are closed too", await code(() => O.getEntity("user", "abc", deps())) === "INVALID" && calls.length === 0);

// ---- query text is fixed; values travel as variables ----
const q = O.listQuery("indicators", 0);
ok("the list query contains only fixed fragments and variables", /^query PrimeSecBrowse\(\$first: Int!, \$after: ID, \$search: String\) \{ indicators\(first: \$first, after: \$after, search: \$search\)/.test(q) && q.includes("objectMarking { definition }"));
reply = () => page([node()]);
await O.browse("indicators", { search: '") { id } } mutation { indicatorAdd', first: "10", after: "abc==" }, deps());
ok("search text is passed only as a variable, never in the query", calls.at(-1).v.search.includes("mutation") && !calls.at(-1).q.includes("mutation") && calls.at(-1).v.first === 10 && calls.at(-1).v.after === "abc==");
ok("an invalid cursor, page size or search is rejected", await code(() => O.browse("indicators", { after: "a b;" }, deps())) === "INVALID" && await code(() => O.browse("indicators", { first: 101 }, deps())) === "INVALID" && await code(() => O.browse("indicators", { first: 0 }, deps())) === "INVALID" && await code(() => O.browse("indicators", { search: "x".repeat(201) }, deps())) === "INVALID" && await code(() => O.browse("indicators", { search: "a\nb" }, deps())) === "INVALID");
ok("entity ids are validated", await code(() => O.getEntity("indicator", "../x", deps())) === "INVALID" && await code(() => O.getEntity("indicator", "a".repeat(65), deps())) === "INVALID" && await code(() => O.getEntity("indicator", undefined, deps())) === "INVALID");
ok("the observable search needs a value", await code(() => O.searchObservables("", 5, deps())) === "INVALID" && await code(() => O.searchObservables("x".repeat(256), 5, deps())) === "INVALID");

// ---- browse results ----
calls = [];
const r = await O.browse("indicators", {}, deps());
ok("a page is normalised with total, cursor and paging flag", r.items.length === 1 && r.total === 42 && r.endCursor === "c1" && r.hasNextPage === true && r.markingPolicy === null);
ok("fields are picked from a fixed list, long text is clipped, lists are kept", r.items[0].fields.description.length === 600 && r.items[0].fields.indicator_types[0] === "malicious-activity" && r.items[0].fields.x_opencti_score === 80 && r.items[0].labels[0] === "c2");
ok("unexpected fields from upstream are not passed through", !("secret" in O.normalize("indicators", node({ secret: "x" }), null).fields));

// ---- marking policy ----
const allow = { OPENCTI_ALLOWED_MARKINGS: "TLP:CLEAR,TLP:GREEN" };
reply = () => page([node({ id: "a", objectMarking: [{ definition: "TLP:CLEAR" }] }), node({ id: "b", objectMarking: [{ definition: "TLP:RED" }] }), node({ id: "c", objectMarking: [{ definition: "TLP:CLEAR" }, { definition: "TLP:RED" }] }), node({ id: "d", objectMarking: [] })]);
const rp = await O.browse("indicators", {}, deps(allow));
const by = Object.fromEntries(rp.items.map((i) => [i.id, i]));
ok("an allowed marking shows content", !by.a.restricted && by.a.name === "bad ip");
ok("a disallowed marking hides name and content", by.b.restricted && by.b.name === "" && Object.keys(by.b.fields).length === 0 && by.b.labels.length === 0);
ok("one disallowed marking among allowed ones hides it (stricter than the package)", by.c.restricted);
ok("an unmarked object is hidden when a policy is set", by.d.restricted);
ok("the page reports how many were hidden and which policy applied", rp.restrictedCount === 3 && rp.markingPolicy.length === 2);
ok("a restricted object still shows its markings so an analyst knows why", by.b.markings[0] === "TLP:RED");

// ---- shape fallback: list form first, connection form for older OpenCTI ----
calls = [];
reply = (qq) => { if (qq.includes("objectMarking { definition }")) throw Object.assign(new Error("OpenCTI GraphQL request failed (200)."), { code: "OPENCTI_REQUEST" }); return page([{ id: "o", name: "old", objectMarking: { edges: [{ node: { definition: "TLP:CLEAR" } }] }, objectLabel: { edges: [{ node: { value: "x" } }] } }]); };
const old = await O.browse("indicators", {}, deps());
ok("an older OpenCTI that rejects the list form is retried with the connection form", calls.length === 2 && old.items[0].markings[0] === "TLP:CLEAR" && old.items[0].labels[0] === "x");
reply = () => { throw Object.assign(new Error("OpenCTI is not configured."), { code: "NOT_CONFIGURED" }); };
calls = [];
ok("not-configured is not retried", await code(() => O.browse("indicators", {}, deps())) === "NOT_CONFIGURED" && calls.length === 1);

// ---- detail ----
reply = () => ({ indicator: node({ id: "i-9" }) });
const d = await O.getEntity("indicator", "i-9", deps());
ok("one entity comes back normalised", d.type === "indicators" && d.item.id === "i-9" && d.item.fields.pattern_type === "stix");
reply = () => ({ indicator: null });
ok("a missing entity is NOT_FOUND", await code(() => O.getEntity("indicator", "nope", deps())) === "NOT_FOUND");
reply = () => ({ indicator: node({ objectMarking: [{ definition: "TLP:RED" }] }) });
ok("a restricted entity detail is also reduced", (await O.getEntity("indicator", "i", deps(allow))).item.restricted === true);

// ---- observables ----
reply = () => ({ stixCyberObservables: { pageInfo: { endCursor: null, hasNextPage: false, globalCount: 2 }, edges: [{ node: { id: "o1", entity_type: "IPv4-Addr", observable_value: "1.2.3.4", created_at: "2026-01-01", objectMarking: [{ definition: "TLP:CLEAR" }] } }, { node: { id: "o2", entity_type: "Domain-Name", observable_value: "evil.example", created_at: "2026-01-02", objectMarking: [{ definition: "TLP:RED" }] } }] } });
const ob = await O.searchObservables("1.2.3.4", 5, deps(allow));
ok("observables are normalised and the restricted one loses its value", ob.items[0].value === "1.2.3.4" && ob.items[1].restricted && ob.items[1].value === "" && ob.restrictedCount === 1 && ob.total === 2);
ok("observables use created_at (they have no created field in OpenCTI 7)", ob.items[0].created === "2026-01-01" && O.observableQuery(0).includes("created_at") && !/ created /.test(O.observableQuery(0)));
ok("the observable search value is a variable", calls.at(-1).v.search === "1.2.3.4" && !calls.at(-1).q.includes("1.2.3.4"));

// ---- errors ----
ok("unconfigured is reported before any call", await (async () => { const before = calls.length; const c = await code(() => O.browse("indicators", {}, deps({}, { configured: () => false }))); return c === "NOT_CONFIGURED" && calls.length === before; })());
reply = () => { throw new Error("connect ECONNREFUSED 10.0.0.7:8081 Bearer abc123"); };
const up = await O.browse("reports", {}, deps()).catch((e) => e);
ok("an upstream failure never leaks its address or token", up.code === "UPSTREAM" && up.message === "Could not reach the upstream platform." && !/10\.0\.0\.7|abc123/.test(up.message));

console.log(`opencti: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
