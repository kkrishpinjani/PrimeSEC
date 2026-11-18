/**
 * One-click launch of the platforms' own web interfaces from the dashboard, without typing their passwords.
 *
 * PrimeSEC (after its own sign-in and an administrator check) logs into the platform ON THE SERVER with the account stored in
 * .env, then hands the browser the resulting session: as cookies on the PrimeSEC response (browsers share cookies between ports
 * of one host, so the platform sees them), or, for Greenbone, which keeps its token in browser storage, as a one-time page
 * served by Greenbone itself. Passwords never reach the browser. TLS is always verified; nothing here disables a check.
 *
 *   OpenCTI    GraphQL login            -> opencti_session cookie
 *   Wazuh      dashboard /auth/login    -> security_authentication cookie
 *   Greenbone  bridge /v1/session       -> token handed to /primesec-handoff.html (see infra/greenbone/primesec)
 *   Neo4j      its login is switched off (it only listens on 127.0.0.1), so this is just the browser link; one click on Connect
 */
import http from "node:http";
import https from "node:https";

export const LAUNCH_PLATFORMS = ["opencti", "wazuh", "greenbone", "neo4j"] as const;
export type LaunchPlatform = (typeof LAUNCH_PLATFORMS)[number];
export const isLaunchPlatform = (v: unknown): v is LaunchPlatform => typeof v === "string" && (LAUNCH_PLATFORMS as readonly string[]).includes(v);

export class LaunchError extends Error {
  code: "UNAVAILABLE" | "UPSTREAM";
  constructor(message: string, code: LaunchError["code"]) {
    super(message);
    this.code = code;
  }
}

export type Env = Record<string, string | undefined>;
export type HttpResult = { status: number; setCookie: string[]; body: string };
export type Transport = (url: string, init: { method: string; headers: Record<string, string>; body?: string; tlsName?: string; cookie?: string }) => Promise<HttpResult>;

/** The real transport: plain node http(s), with an optional certificate name to verify against (the local Wazuh certificate only names wazuh.dashboard). */
export const nodeTransport: Transport = (url, init) =>
  new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? https : http;
    const headers = { ...init.headers, ...(init.cookie ? { Cookie: init.cookie } : {}), ...(init.body ? { "Content-Length": String(Buffer.byteLength(init.body)) } : {}) };
    const req = lib.request(
      { protocol: u.protocol, hostname: u.hostname, port: u.port || undefined, path: `${u.pathname}${u.search}`, method: init.method, headers, timeout: 8000, ...(u.protocol === "https:" && init.tlsName ? { servername: init.tlsName } : {}) },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, setCookie: ([] as string[]).concat(res.headers["set-cookie"] ?? []), body: Buffer.concat(chunks).toString("utf8").slice(0, 200_000) }));
      }
    );
    req.on("timeout", () => req.destroy(new Error("timed out")));
    req.on("error", reject);
    if (init.body) req.write(init.body);
    req.end();
  });

/**
 * A Set-Cookie line from the platform, made safe to re-issue from the PrimeSEC origin: the Domain attribute is dropped (the
 * browser then keys it to the host the browser used) and anything we do not understand is discarded.
 */
export function reissueCookie(raw: string): string | null {
  const parts = raw.split(";").map((p) => p.trim()).filter(Boolean);
  const [pair, ...attrs] = parts;
  if (!pair || !/^[^=\s]+=/.test(pair)) return null;
  const keep = attrs.filter((a) => /^(path|expires|max-age|httponly|samesite|secure)\b/i.test(a));
  if (!keep.some((a) => /^path/i.test(a))) keep.unshift("Path=/");
  return [pair, ...keep].join("; ");
}
export const cookieHeader = (setCookies: string[]) => setCookies.map((c) => c.split(";")[0]).join("; ");

const need = (v: string | undefined, what: string) => {
  const t = (v ?? "").trim();
  if (!t) throw new LaunchError(`${what} is not set in .env.`, "UNAVAILABLE");
  return t;
};
const base = (v: string | undefined, what: string) => need(v, what).replace(/\/+$/, "");

export type Launch = { cookies: string[]; location: string };

export async function loginOpenCti(env: Env, t: Transport): Promise<string[]> {
  const root = base(env.OPENCTI_URL, "OPENCTI_URL");
  const email = need(env.LAUNCH_OPENCTI_EMAIL, "LAUNCH_OPENCTI_EMAIL"), password = need(env.LAUNCH_OPENCTI_PASSWORD, "LAUNCH_OPENCTI_PASSWORD");
  const json = { "Content-Type": "application/json" };
  const login = await t(`${root}/graphql`, { method: "POST", headers: json, body: JSON.stringify({ query: "mutation Login($input: UserLoginInput!){ token(input:$input) }", variables: { input: { email, password } } }) });
  const cookies = login.setCookie.map(reissueCookie).filter((c): c is string => c !== null);
  if (login.status !== 200 || cookies.length === 0) throw new LaunchError("OpenCTI did not accept the stored login.", "UPSTREAM");
  // A session cookie is also issued to anonymous visitors, so prove the login worked before handing it over.
  const me = await t(`${root}/graphql`, { method: "POST", headers: json, body: JSON.stringify({ query: "{ me { id } }" }), cookie: cookieHeader(cookies) });
  let ok = false;
  try { ok = Boolean(JSON.parse(me.body)?.data?.me?.id); } catch { /* not JSON */ }
  if (!ok) throw new LaunchError("OpenCTI did not accept the stored login.", "UPSTREAM");
  return cookies;
}

export async function loginWazuh(env: Env, t: Transport): Promise<string[]> {
  const root = base(env.WAZUH_DASHBOARD_URL, "WAZUH_DASHBOARD_URL");
  const username = need(env.LAUNCH_WAZUH_USERNAME, "LAUNCH_WAZUH_USERNAME"), password = need(env.LAUNCH_WAZUH_PASSWORD, "LAUNCH_WAZUH_PASSWORD");
  const r = await t(`${root}/auth/login`, { method: "POST", headers: { "Content-Type": "application/json", "osd-xsrf": "true" }, body: JSON.stringify({ username, password }), tlsName: (env.WAZUH_DASHBOARD_TLS_NAME ?? "wazuh.dashboard").trim() });
  const cookies = r.setCookie.map(reissueCookie).filter((c): c is string => c !== null);
  if (r.status !== 200 || !cookies.some((c) => /^security_authentication=/.test(c))) throw new LaunchError("The Wazuh dashboard did not accept the stored login.", "UPSTREAM");
  return cookies;
}

export type GreenboneSession = { token: string; username: string; expiresAt: number; sid: string };

/** The Greenbone bridge logs in on the Docker network, where gsad speaks plain HTTP, and returns what the web app keeps in the browser. */
export async function greenboneSession(env: Env, t: Transport): Promise<GreenboneSession> {
  const root = base(env.GREENBONE_BRIDGE_URL, "GREENBONE_BRIDGE_URL"), token = need(env.GREENBONE_BRIDGE_TOKEN, "GREENBONE_BRIDGE_TOKEN");
  const r = await t(`${root}/v1/session`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
  let v: Partial<GreenboneSession> = {};
  try { v = JSON.parse(r.body); } catch { /* not JSON */ }
  if (r.status !== 200 || !v.token || !v.username) throw new LaunchError("Greenbone did not accept the stored login.", "UPSTREAM");
  return { token: String(v.token), username: String(v.username), expiresAt: Number(v.expiresAt) || Date.now() + 25 * 60_000, sid: String(v.sid ?? "") };
}

/** Where the browser goes for a platform, and what to set first. */
export async function launch(platform: LaunchPlatform, env: Env = process.env, t: Transport = nodeTransport): Promise<Launch> {
  switch (platform) {
    case "opencti":
      return { cookies: await loginOpenCti(env, t), location: base(env.OPENCTI_DASHBOARD_URL, "OPENCTI_DASHBOARD_URL") };
    case "wazuh":
      return { cookies: await loginWazuh(env, t), location: base(env.WAZUH_DASHBOARD_URL, "WAZUH_DASHBOARD_URL") };
    case "greenbone": {
      const s = await greenboneSession(env, t);
      // The fragment never leaves the browser (it is not sent to a server or written to a log); the page clears it at once.
      const frag = new URLSearchParams({ t: s.token, u: s.username, e: String(s.expiresAt), s: s.sid });
      return { cookies: [], location: `${base(env.GREENBONE_DASHBOARD_URL, "GREENBONE_DASHBOARD_URL")}/primesec-handoff.html#${frag}` };
    }
    case "neo4j": {
      const url = base(env.NEO4J_BROWSER_URL, "NEO4J_BROWSER_URL");
      const bolt = (env.NEO4J_BOLT_URL ?? "neo4j://localhost:7687").trim();
      // The login is off, so the browser is opened already pointed at the database and nothing has to be typed. (Neo4j Browser cannot
      // connect by itself from a link: it still shows its connect box, and one click on Connect gets in.)
      return { cookies: [], location: `${url}/browser/?${new URLSearchParams({ dbms: bolt })}` };
    }
  }
}
