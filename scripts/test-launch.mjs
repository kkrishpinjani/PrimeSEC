// Tests for the one-click platform launcher: cookie handling, proof of login, handoff URLs, and that nothing secret leaks into them.
// Run: npm run test:launch
import path from "node:path";

const root = process.cwd();
const L = await import(path.join(root, "lib", "launch.ts").replace(/\\/g, "/").replace(/^([A-Za-z]):/, "file:///$1:"));

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const code = async (fn) => { try { await fn(); return null; } catch (e) { return e.code ?? `UNEXPECTED:${e.message}`; } };

const ENV = {
  OPENCTI_URL: "http://127.0.0.1:8081", OPENCTI_DASHBOARD_URL: "http://localhost:8081/", LAUNCH_OPENCTI_EMAIL: "a@b.c", LAUNCH_OPENCTI_PASSWORD: "S3cret-pass",
  WAZUH_DASHBOARD_URL: "https://localhost:8443", LAUNCH_WAZUH_USERNAME: "admin", LAUNCH_WAZUH_PASSWORD: "W4zuh-pass",
  GREENBONE_BRIDGE_URL: "http://127.0.0.1:8787", GREENBONE_BRIDGE_TOKEN: "bridge-token-value", GREENBONE_DASHBOARD_URL: "https://localhost",
  NEO4J_BROWSER_URL: "http://localhost:7474"
};

// ---- cookies ----
ok("the Domain attribute is dropped", L.reissueCookie("a=1; Domain=evil.example; Path=/x; HttpOnly") === "a=1; Path=/x; HttpOnly");
ok("a missing Path becomes /", L.reissueCookie("a=1; HttpOnly") === "a=1; Path=/; HttpOnly");
ok("unknown attributes are discarded", L.reissueCookie("a=1; Path=/; Priority=High; Foo=bar") === "a=1; Path=/");
ok("a line that is not a cookie is refused", L.reissueCookie("garbage") === null && L.reissueCookie("") === null);
ok("the Cookie header carries names and values only", L.cookieHeader(["a=1; Path=/; HttpOnly", "b=2; Path=/"]) === "a=1; b=2");

// ---- OpenCTI ----
let calls = [];
const octi = (over = {}) => async (url, init) => {
  calls.push({ url, init });
  if (/Login/.test(init.body ?? "")) return { status: 200, setCookie: over.cookies ?? ["opencti_session=abc; Path=/; HttpOnly; SameSite=Lax"], body: '{"data":{"token":null}}' };
  return { status: 200, setCookie: [], body: over.me ?? '{"data":{"me":{"id":"u1"}}}' };
};
let r = await L.launch("opencti", ENV, octi());
ok("OpenCTI hands over the session cookie", r.cookies.length === 1 && r.cookies[0].startsWith("opencti_session=abc"));
ok("and goes to the dashboard URL without a trailing slash", r.location === "http://localhost:8081");
ok("it proved the login by reading the user with that cookie", calls[1].init.cookie === "opencti_session=abc");
ok("OpenCTI refuses a session that is only anonymous", await code(() => L.launch("opencti", ENV, octi({ me: '{"data":{"me":null}}' }))) === "UPSTREAM");
ok("OpenCTI refuses when no cookie comes back", await code(() => L.launch("opencti", ENV, octi({ cookies: [] }))) === "UPSTREAM");
ok("OpenCTI without a stored login is 'not set up'", await code(() => L.launch("opencti", { ...ENV, LAUNCH_OPENCTI_PASSWORD: "" }, octi())) === "UNAVAILABLE");

// ---- Wazuh ----
let seen;
const wz = (status, cookies) => async (url, init) => { seen = { url, init }; return { status, setCookie: cookies, body: "{}" }; };
r = await L.launch("wazuh", ENV, wz(200, ["security_authentication=tok; HttpOnly; Path=/"]));
ok("Wazuh hands over the session cookie", r.cookies[0].startsWith("security_authentication=tok") && r.location === "https://localhost:8443");
ok("Wazuh's certificate name is checked, not skipped", seen.init.tlsName === "wazuh.dashboard" && seen.url === "https://localhost:8443/auth/login");
ok("Wazuh refuses a wrong login", await code(() => L.launch("wazuh", ENV, wz(401, []))) === "UPSTREAM");
ok("Wazuh refuses a 200 without its session cookie", await code(() => L.launch("wazuh", ENV, wz(200, ["other=1"]))) === "UPSTREAM");

// ---- Greenbone ----
const gb = (body, status = 200) => async (url, init) => { seen = { url, init }; return { status, setCookie: [], body: JSON.stringify(body) }; };
r = await L.launch("greenbone", ENV, gb({ token: "t-1", username: "primesec", sid: "s-1", expiresAt: 1800000000000 }));
const u = new URL(r.location);
ok("Greenbone goes to the handoff page on its own origin", u.origin === "https://localhost" && u.pathname === "/primesec-handoff.html");
const frag = new URLSearchParams(u.hash.slice(1));
ok("the session travels in the fragment, never the query", u.search === "" && frag.get("t") === "t-1" && frag.get("u") === "primesec" && frag.get("s") === "s-1" && frag.get("e") === "1800000000000");
ok("no cookie is set from PrimeSEC for Greenbone", r.cookies.length === 0);
ok("the bridge is called with its token", seen.init.headers.Authorization === "Bearer bridge-token-value" && seen.url.endsWith("/v1/session"));
ok("Greenbone refuses an empty session", await code(() => L.launch("greenbone", ENV, gb({}))) === "UPSTREAM");
ok("Greenbone refuses a bridge error", await code(() => L.launch("greenbone", ENV, gb({ error: "x" }, 502))) === "UPSTREAM");

// ---- Neo4j ----
r = await L.launch("neo4j", ENV, async () => { throw new Error("must not be called"); });
ok("Neo4j opens the browser pointed at the database, with no credentials", r.location.startsWith("http://localhost:7474/browser/?dbms=") && !/neo4j%3A%2F%2F[^%]*%40/.test(r.location) && r.cookies.length === 0);

// ---- nothing secret in any destination ----
const all = [];
for (const [p, tr] of [["opencti", octi()], ["wazuh", wz(200, ["security_authentication=tok; Path=/"])], ["greenbone", gb({ token: "t", username: "u", sid: "s" })], ["neo4j", async () => ({})]]) all.push((await L.launch(p, ENV, tr)).location);
ok("no stored password appears in any redirect", all.every((l) => !/S3cret-pass|W4zuh-pass|bridge-token-value/.test(l)));

// ---- platform names ----
ok("only the four known platforms are accepted", L.isLaunchPlatform("wazuh") && !L.isLaunchPlatform("../etc") && !L.isLaunchPlatform(undefined) && !L.isLaunchPlatform("OpenCTI"));

console.log(`launch: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
