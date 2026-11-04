// Imports abuse.ch Feodo Tracker botnet C2 IPs (public, CC0, no key) into the LOCAL OpenCTI as TLP:CLEAR indicators.
// Why a script: OpenCTI ships no keyless connector for this list, and every other free IOC feed needs an account key.
// Idempotent: OpenCTI de-duplicates indicators by pattern, so running it again only refreshes them.
// Uses the OpenCTI ADMIN token from infra/opencti/.env (never printed). Run: node scripts/import-feodo-indicators.mjs
import { readFileSync } from "node:fs";
import path from "node:path";

const FEED = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";
const OPENCTI = process.env.OPENCTI_ADMIN_URL || "http://127.0.0.1:8081/graphql";
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

const env = Object.fromEntries(readFileSync(path.join(process.cwd(), "infra", "opencti", ".env"), "utf8").split(/\r?\n/).filter((l) => l.includes("=")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
const token = env.OPENCTI_ADMIN_TOKEN;
if (!token) { console.error("infra/opencti/.env has no OPENCTI_ADMIN_TOKEN."); process.exit(1); }

async function gql(query, variables = {}) {
  const r = await fetch(OPENCTI, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ query, variables }), signal: AbortSignal.timeout(60_000) });
  const body = await r.json().catch(() => ({}));
  if (body.errors?.length) throw new Error(String(body.errors[0].message).slice(0, 200));
  return body.data;
}

const res = await fetch(FEED, { signal: AbortSignal.timeout(30_000) });
if (!res.ok) { console.error(`Feed answered HTTP ${res.status}.`); process.exit(1); }
const rows = await res.json();
if (!Array.isArray(rows)) { console.error("Unexpected feed format."); process.exit(1); }

const marks = (await gql("{ markingDefinitions { edges { node { id definition } } } }")).markingDefinitions.edges.map((e) => e.node);
const clear = marks.find((m) => m.definition === "TLP:CLEAR");
if (!clear) { console.error("TLP:CLEAR marking not found in OpenCTI."); process.exit(1); }

const Q = `mutation($i: IndicatorAddInput!) { indicatorAdd(input: $i) { id name } }`;
let created = 0, skipped = 0, failed = 0;
for (const r of rows) {
  const ip = String(r.ip_address ?? "");
  // Values from a third-party feed are validated before they go anywhere near a STIX pattern.
  if (!IPV4.test(ip)) { skipped++; continue; }
  const family = String(r.malware ?? "unknown").replace(/[^A-Za-z0-9 ._-]/g, "").slice(0, 40) || "unknown";
  const seen = String(r.first_seen ?? "").replace(" ", "T");
  const validFrom = /^\d{4}-\d{2}-\d{2}T[\d:]{8}$/.test(seen) ? `${seen}Z` : new Date().toISOString();
  try {
    await gql(Q, { i: {
      name: `Feodo Tracker C2 ${ip}${r.port ? `:${Number(r.port) || ""}` : ""} (${family})`.replace(/:\)/, ")"),
      description: `Botnet command-and-control address listed by abuse.ch Feodo Tracker (${family}). Status when imported: ${String(r.status ?? "unknown").slice(0, 20)}; last online ${String(r.last_online ?? "unknown").slice(0, 10)}; ${String(r.country ?? "").slice(0, 2)} ${String(r.as_name ?? "").replace(/[^A-Za-z0-9 ._-]/g, "").slice(0, 60)}. Source: ${FEED}`,
      pattern: `[ipv4-addr:value = '${ip}']`, pattern_type: "stix", x_opencti_main_observable_type: "IPv4-Addr",
      valid_from: validFrom, x_opencti_score: String(r.status).toLowerCase() === "online" ? 80 : 50,
      objectMarking: [clear.id], objectLabel: ["feodo-tracker", `malware:${family.toLowerCase()}`, "c2"], createObservables: true, confidence: 70
    } });
    created++;
  } catch (e) { failed++; console.error(`  ${ip}: ${e.message}`); }
}
console.log(`Feodo Tracker: ${rows.length} entries read, ${created} indicators created or refreshed, ${skipped} skipped (invalid), ${failed} failed.`);
process.exit(failed ? 1 : 0);
