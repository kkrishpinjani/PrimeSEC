/**
 * Server-side Wazuh and OpenCTI adapters (Day 2). Credentials come from environment
 * variables and are never returned to the browser. Everything here is read-only.
 * Ported from the PrimeSOC Day 2 package, with types added.
 */

export type IntegrationStatus = {
  name: string;
  configured: boolean;
  connected: boolean;
  message: string;
  checkedAt: string;
  partial?: boolean;
};

export type WazuhAgent = { id: string; name: string; status: string; ip: string; version: string; os: string };
export type WazuhAlert = { id: string; timestamp: string | null; level: number; description: string; agent: string; sourceIp: string };
/** A geolocated alert source (srcip) with Wazuh's GeoIP enrichment. */
export type AlertSource = { ip: string; lat: number; lon: number; country: string; city: string; count: number; maxLevel: number };
export type SeverityCounts = { high: number; medium: number; low: number; info: number };
export type WazuhAlerts = {
  configured: boolean;
  available: boolean;
  total24h: number | null;
  critical24h: number | null;
  recent: WazuhAlert[];
  /** 24 hourly buckets, oldest first. */
  hourly: number[];
  /** Same buckets, only alerts of rule level 12+. */
  hourlyHigh: number[];
  severity: SeverityCounts | null;
  sources: AlertSource[];
  message: string;
};
export type VulnItem = { host: string; title: string; sev: "Critical" | "High" | "Medium" | "Low"; score: number };
export type WazuhVulns = {
  configured: boolean;
  available: boolean;
  total: number | null;
  critical: number | null;
  hosts: number | null;
  top: VulnItem[];
  message: string;
};
export type WazuhOverview = {
  status: IntegrationStatus;
  agents: { total: number | null; items: WazuhAgent[] };
  alerts: WazuhAlerts;
  vulns: WazuhVulns;
};

export type CtiIndicator = { id: string; name: string; pattern: string; patternType: string; createdAt: string | null; score: number | null };
export type CtiReport = { id: string; name: string; published: string | null; createdAt: string | null };
export type CtiActor = { id: string; name: string; description: string };
export type OpenCtiOverview = {
  status: IntegrationStatus;
  indicators: CtiIndicator[];
  reports: CtiReport[];
  threatActors: CtiActor[];
  /** Platform-wide totals (pageInfo.globalCount); null when OpenCTI did not report one. */
  totals: { indicators: number | null; reports: number | null; threatActors: number | null };
};

type CodedError = Error & { code?: string };

const timeoutMs = () => Number(process.env.INTEGRATION_TIMEOUT_MS || 10000);

function cleanBaseUrl(value: string | undefined): string {
  return String(value || "").trim().replace(/\/+$/, "");
}

async function fetchWithTimeout(url: string, options: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs());
  try {
    return await fetch(url, { ...options, signal: controller.signal, cache: "no-store" });
  } finally {
    clearTimeout(timer);
  }
}

async function readJson(response: Response): Promise<any> {
  const body = await response.text();
  try {
    return body ? JSON.parse(body) : {};
  } catch {
    return { message: body.slice(0, 500) };
  }
}

function safeError(error: unknown): string {
  if ((error as Error)?.name === "AbortError") return "The upstream platform timed out.";
  // Our own coded errors carry only a status line (e.g. "Wazuh authentication failed (401).").
  if ((error as CodedError)?.code && (error as CodedError).code !== "NOT_CONFIGURED") return (error as Error).message;
  return "Could not reach the upstream platform. Check its URL, TLS certificate, credentials and network access.";
}

function codedError(message: string, code: string): CodedError {
  const error: CodedError = new Error(message);
  error.code = code;
  return error;
}

function status(name: string, configured: boolean, connected: boolean, message: string, extra: Partial<IntegrationStatus> = {}): IntegrationStatus {
  return { name, configured, connected, message, checkedAt: new Date().toISOString(), ...extra };
}

const basic = (user: string, pass: string) => Buffer.from(`${user}:${pass}`).toString("base64");

/* ---------------------------------- Wazuh ---------------------------------- */

async function getWazuhToken(): Promise<{ baseUrl: string; token: string }> {
  const baseUrl = cleanBaseUrl(process.env.WAZUH_API_URL);
  const username = process.env.WAZUH_API_USERNAME;
  const password = process.env.WAZUH_API_PASSWORD;
  if (!baseUrl || !username || !password) {
    throw codedError("Wazuh API URL or credentials are not configured.", "NOT_CONFIGURED");
  }
  const response = await fetchWithTimeout(`${baseUrl}/security/user/authenticate?raw=true`, {
    method: "POST",
    headers: { Authorization: `Basic ${basic(username, password)}`, Accept: "application/json" }
  });
  const body = await readJson(response);
  if (!response.ok) throw codedError(`Wazuh authentication failed (${response.status}).`, "UPSTREAM_AUTH");
  const token = typeof body === "string" ? body : body?.data?.token || body?.token || body?.message || body?.data?.affected_items?.[0]?.token;
  if (!token) throw codedError("Wazuh API did not return an authentication token.", "UPSTREAM_RESPONSE");
  return { baseUrl, token };
}

async function wazuhApiGet(baseUrl: string, token: string, path: string) {
  const response = await fetchWithTimeout(`${baseUrl}${path}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" }
  });
  const body = await readJson(response);
  if (!response.ok) throw codedError(`Wazuh API request failed (${response.status}).`, "UPSTREAM_REQUEST");
  return body;
}

function unpackWazuhAgents(body: any): WazuhOverview["agents"] {
  const data = body?.data || body;
  const items: any[] = data?.affected_items || data?.items || [];
  return {
    total: Number(data?.total_affected_items ?? items.length ?? 0),
    items: items.map((agent) => ({
      id: agent.id || agent.agent_id || "—",
      name: agent.name || "Unknown endpoint",
      status: agent.status || "unknown",
      ip: agent.ip || "—",
      version: agent.version || "—",
      os: agent.os?.name || agent.os?.platform || "—"
    }))
  };
}

const NO_ALERTS = { hourly: [] as number[], hourlyHigh: [] as number[], severity: null, sources: [] as AlertSource[] };

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** Last 24 hourly buckets (oldest first); pads at the front if the index is younger than 24h. */
function last24(values: number[]): number[] {
  const tail = values.slice(-24);
  return [...Array(24 - tail.length).fill(0), ...tail];
}

async function indexerSearch(path: string, query: unknown): Promise<any> {
  const baseUrl = cleanBaseUrl(process.env.WAZUH_INDEXER_URL);
  const username = process.env.WAZUH_INDEXER_USERNAME as string;
  const password = process.env.WAZUH_INDEXER_PASSWORD as string;
  const response = await fetchWithTimeout(`${baseUrl}/${encodeURIComponent(path).replace(/%2A/g, "*")}/_search`, {
    method: "POST",
    headers: { Authorization: `Basic ${basic(username, password)}`, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(query)
  });
  const body = await readJson(response);
  if (!response.ok) throw codedError(`Wazuh Indexer query failed (${response.status}).`, "INDEXER_REQUEST");
  return body;
}

const indexerConfigured = () =>
  Boolean(cleanBaseUrl(process.env.WAZUH_INDEXER_URL) && process.env.WAZUH_INDEXER_USERNAME && process.env.WAZUH_INDEXER_PASSWORD);

async function getWazuhAlerts(): Promise<WazuhAlerts> {
  if (!indexerConfigured()) {
    return {
      configured: false, available: false, total24h: null, critical24h: null, recent: [], ...NO_ALERTS,
      message: "Indexer alert metrics are optional. Configure WAZUH_INDEXER_URL and its read-only credentials to enable them."
    };
  }
  const index = process.env.WAZUH_ALERT_INDEX_PATTERN || "wazuh-alerts-4.x-*";
  const body = await indexerSearch(index, {
    size: 5,
    track_total_hits: true,
    sort: [{ timestamp: { order: "desc", unmapped_type: "date" } }],
    query: { range: { timestamp: { gte: "now-24h" } } },
    aggs: {
      critical: { filter: { range: { "rule.level": { gte: 12 } } } },
      by_hour: {
        date_histogram: { field: "timestamp", fixed_interval: "1h", min_doc_count: 0, extended_bounds: { min: "now-24h", max: "now" } },
        aggs: { high: { filter: { range: { "rule.level": { gte: 12 } } } } }
      },
      by_level: {
        range: {
          field: "rule.level",
          ranges: [{ key: "info", to: 4 }, { key: "low", from: 4, to: 7 }, { key: "medium", from: 7, to: 12 }, { key: "high", from: 12 }]
        }
      },
      top_src: {
        terms: { field: "data.srcip", size: 25 },
        aggs: {
          max_level: { max: { field: "rule.level" } },
          geo: { top_hits: { size: 1, _source: ["GeoLocation.location", "GeoLocation.country_name", "GeoLocation.city_name"] } }
        }
      }
    },
    _source: ["timestamp", "rule.level", "rule.description", "agent.name", "agent.id", "data.srcip", "manager.name"]
  });

  const hits: any[] = body?.hits?.hits || [];
  const hourBuckets: any[] = body?.aggregations?.by_hour?.buckets || [];
  const levelBuckets: any[] = body?.aggregations?.by_level?.buckets || [];
  const level = (key: string) => Number(levelBuckets.find((b) => b.key === key)?.doc_count ?? 0);
  const sources: AlertSource[] = ((body?.aggregations?.top_src?.buckets || []) as any[])
    .map((b) => {
      const g = b?.geo?.hits?.hits?.[0]?._source?.GeoLocation;
      const lat = num(g?.location?.lat), lon = num(g?.location?.lon);
      if (lat == null || lon == null) return null;
      return {
        ip: String(b.key), lat, lon,
        country: g?.country_name || "", city: g?.city_name || "",
        count: Number(b.doc_count ?? 0), maxLevel: Number(b.max_level?.value ?? 0)
      };
    })
    .filter((x): x is AlertSource => x !== null);

  return {
    configured: true,
    available: true,
    total24h: Number(body?.hits?.total?.value ?? body?.hits?.total ?? 0),
    critical24h: Number(body?.aggregations?.critical?.doc_count ?? 0),
    recent: hits.map((hit) => {
      const source = hit?._source || {};
      return {
        id: hit?._id || "",
        timestamp: source.timestamp || null,
        level: Number(source.rule?.level ?? 0),
        description: source.rule?.description || "Alert description unavailable",
        agent: source.agent?.name || source.agent?.id || "Unknown agent",
        sourceIp: source.data?.srcip || "—"
      };
    }),
    hourly: last24(hourBuckets.map((b) => Number(b.doc_count ?? 0))),
    hourlyHigh: last24(hourBuckets.map((b) => Number(b.high?.doc_count ?? 0))),
    severity: { high: level("high"), medium: level("medium"), low: level("low"), info: level("info") },
    sources,
    message: "Connected to Wazuh Indexer."
  };
}

/** Wazuh Vulnerability Detector state index (Wazuh 4.8+). Optional: older versions simply report unavailable. */
async function getWazuhVulns(): Promise<WazuhVulns> {
  const none = { total: null, critical: null, hosts: null, top: [] as VulnItem[] };
  if (!indexerConfigured()) {
    return { configured: false, available: false, ...none, message: "Vulnerability data needs the Wazuh Indexer (WAZUH_INDEXER_URL and credentials)." };
  }
  try {
    const index = process.env.WAZUH_VULN_INDEX_PATTERN || "wazuh-states-vulnerabilities-*";
    const body = await indexerSearch(index, {
      size: 5,
      track_total_hits: true,
      sort: [{ "vulnerability.score.base": { order: "desc", unmapped_type: "float" } }],
      query: { match_all: {} },
      aggs: {
        by_sev: { terms: { field: "vulnerability.severity", size: 5 } },
        hosts: { cardinality: { field: "agent.name" } }
      },
      _source: ["vulnerability.id", "vulnerability.severity", "vulnerability.score.base", "package.name", "agent.name"]
    });
    const sevOf = (v: unknown): VulnItem["sev"] => {
      const x = String(v || "").toLowerCase();
      return x === "critical" ? "Critical" : x === "high" ? "High" : x === "low" ? "Low" : "Medium";
    };
    const buckets: any[] = body?.aggregations?.by_sev?.buckets || [];
    const hits: any[] = body?.hits?.hits || [];
    return {
      configured: true,
      available: true,
      total: Number(body?.hits?.total?.value ?? body?.hits?.total ?? 0),
      critical: Number(buckets.find((b) => String(b.key).toLowerCase() === "critical")?.doc_count ?? 0),
      hosts: Number(body?.aggregations?.hosts?.value ?? 0),
      top: hits.map((h) => {
        const v = h?._source?.vulnerability || {};
        const pkg = h?._source?.package?.name;
        return {
          host: h?._source?.agent?.name || "Unknown agent",
          title: [v.id, pkg].filter(Boolean).join(" · ") || "Vulnerability",
          sev: sevOf(v.severity),
          score: Math.round(Number(v.score?.base ?? 0) * 10)
        };
      }),
      message: "Connected to the Wazuh vulnerability index."
    };
  } catch (error) {
    return { configured: true, available: false, ...none, message: `Vulnerability index unavailable: ${safeError(error)}` };
  }
}

export async function getWazuhOverview(): Promise<WazuhOverview> {
  try {
    const { baseUrl, token } = await getWazuhToken();
    const [agentResult, alertResult, vulns] = await Promise.all([
      Promise.allSettled([wazuhApiGet(baseUrl, token, "/agents?limit=10&sort=-id")]).then((r) => r[0]),
      Promise.allSettled([getWazuhAlerts()]).then((r) => r[0]),
      getWazuhVulns()
    ]);
    if (agentResult.status === "rejected") throw agentResult.reason;
    const alerts: WazuhAlerts =
      alertResult.status === "fulfilled"
        ? alertResult.value
        : { configured: true, available: false, total24h: null, critical24h: null, recent: [], ...NO_ALERTS, message: safeError(alertResult.reason) };
    return {
      status: status("Wazuh", true, true, "Wazuh API connected."),
      agents: unpackWazuhAgents(agentResult.value),
      alerts,
      vulns
    };
  } catch (error) {
    const notConfigured = (error as CodedError)?.code === "NOT_CONFIGURED";
    return {
      status: status("Wazuh", !notConfigured, false, notConfigured ? (error as Error).message : safeError(error)),
      agents: { total: null, items: [] },
      alerts: { configured: Boolean(process.env.WAZUH_INDEXER_URL), available: false, total24h: null, critical24h: null, recent: [], ...NO_ALERTS, message: "Alert metrics unavailable." },
      vulns: { configured: Boolean(process.env.WAZUH_INDEXER_URL), available: false, total: null, critical: null, hosts: null, top: [], message: "Vulnerability data unavailable." }
    };
  }
}

/* --------------------------------- OpenCTI --------------------------------- */

async function openCtiGraphql(token: string, query: string, variables?: Record<string, unknown>): Promise<any> {
  const baseUrl = cleanBaseUrl(process.env.OPENCTI_URL);
  const response = await fetchWithTimeout(`${baseUrl}/graphql`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(variables ? { query, variables } : { query })
  });
  const body = await readJson(response);
  if (!response.ok || body?.errors?.length) {
    throw codedError(`OpenCTI GraphQL request failed (${response.status || "GraphQL error"}).`, "OPENCTI_REQUEST");
  }
  return body?.data || {};
}

function nodes(connection: any): any[] {
  if (Array.isArray(connection?.edges)) return connection.edges.map((edge: { node?: unknown }) => edge?.node).filter(Boolean);
  if (Array.isArray(connection?.nodes)) return connection.nodes;
  return [];
}

const EMPTY_TOTALS = { indicators: null, reports: null, threatActors: null };

/** Tries the richer query (scores, platform totals); falls back to the plain one if this OpenCTI version rejects it. */
async function openCtiQuery(token: string, rich: string, plain: string): Promise<any> {
  try {
    return await openCtiGraphql(token, rich);
  } catch {
    return openCtiGraphql(token, plain);
  }
}

const globalCount = (connection: any): number | null => num(connection?.pageInfo?.globalCount);

export async function getOpenCtiOverview(): Promise<OpenCtiOverview> {
  const baseUrl = cleanBaseUrl(process.env.OPENCTI_URL);
  const token = process.env.OPENCTI_API_TOKEN;
  if (!baseUrl || !token) {
    return {
      status: status("OpenCTI", false, false, "Set OPENCTI_URL and OPENCTI_API_TOKEN in .env to enable threat intelligence."),
      indicators: [], reports: [], threatActors: [], totals: EMPTY_TOTALS
    };
  }
  try {
    const results = await Promise.allSettled([
      openCtiQuery(
        token,
        "query PrimeSecIndicators { indicators(first: 8, orderBy: created_at, orderMode: desc) { pageInfo { globalCount } edges { node { id name pattern pattern_type created_at x_opencti_score } } } }",
        "query PrimeSecIndicatorsPlain { indicators(first: 8) { edges { node { id name pattern pattern_type created_at } } } }"
      ),
      openCtiQuery(
        token,
        "query PrimeSecReports { reports(first: 6, orderBy: published, orderMode: desc) { pageInfo { globalCount } edges { node { id name published created_at } } } }",
        "query PrimeSecReportsPlain { reports(first: 6) { edges { node { id name published created_at } } } }"
      ),
      openCtiQuery(
        token,
        "query PrimeSecThreatActors { threatActors(first: 6) { pageInfo { globalCount } edges { node { id name description } } } }",
        "query PrimeSecThreatActorsPlain { threatActors(first: 6) { edges { node { id name description } } } }"
      )
    ]);
    const failures = results.filter((r) => r.status === "rejected");
    if (failures.length === results.length) throw (failures[0] as PromiseRejectedResult).reason;
    const [ind, rep, act] = results.map((r) => (r.status === "fulfilled" ? r.value : {}));
    return {
      status: status("OpenCTI", true, true, failures.length ? "Connected, but one or more OpenCTI queries failed. Check entity permissions and schema compatibility." : "OpenCTI API connected.", { partial: failures.length > 0 }),
      indicators: nodes(ind.indicators).map((i) => ({
        id: i.id, name: i.name || "Unnamed indicator", pattern: i.pattern || "", patternType: i.pattern_type || "",
        createdAt: i.created_at || null, score: num(i.x_opencti_score)
      })),
      reports: nodes(rep.reports).map((r) => ({ id: r.id, name: r.name || "Untitled report", published: r.published || null, createdAt: r.created_at || null })),
      threatActors: nodes(act.threatActors).map((a) => ({ id: a.id, name: a.name || "Unnamed threat actor", description: a.description || "" })),
      totals: { indicators: globalCount(ind.indicators), reports: globalCount(rep.reports), threatActors: globalCount(act.threatActors) }
    };
  } catch (error) {
    return { status: status("OpenCTI", true, false, safeError(error)), indicators: [], reports: [], threatActors: [], totals: EMPTY_TOTALS };
  }
}

/* ------------------------- Day 3: investigation lookups ------------------------- */

export type WazuhAlertDetail = { alert: WazuhAlert; text: string };

/** Fetches one alert from the Wazuh Indexer by its document id. Returns null when it does not exist. */
export async function getWazuhAlertById(id: string): Promise<WazuhAlertDetail | null> {
  if (!indexerConfigured()) throw codedError("Wazuh Indexer is not configured.", "NOT_CONFIGURED");
  const index = process.env.WAZUH_ALERT_INDEX_PATTERN || "wazuh-alerts-4.x-*";
  const body = await indexerSearch(index, {
    size: 1,
    query: { ids: { values: [id] } },
    // threat-relevant fields only: never the monitored host's own agent/manager addresses
    _source: ["timestamp", "rule.level", "rule.description", "agent.name", "agent.id", "data", "syscheck", "full_log"]
  });
  const hit = body?.hits?.hits?.[0];
  if (!hit) return null;
  const src = hit._source || {};
  const alert: WazuhAlert = {
    id: hit._id || id,
    timestamp: src.timestamp || null,
    level: Number(src.rule?.level ?? 0),
    description: src.rule?.description || "Alert description unavailable",
    agent: src.agent?.name || src.agent?.id || "Unknown agent",
    sourceIp: src.data?.srcip || "—"
  };
  const text = [alert.description, src.full_log, src.data ? JSON.stringify(src.data) : "", src.syscheck ? JSON.stringify(src.syscheck) : ""]
    .filter(Boolean)
    .join(" ")
    .slice(0, 20000);
  return { alert, text };
}

export type CtiSearchResult = { configured: boolean; connected: boolean; indicators: CtiIndicator[]; failures: number; message: string };

/** Searches OpenCTI for indicators mentioning each observable (GraphQL variables, never string-built). */
export async function searchOpenCtiIndicators(values: string[]): Promise<CtiSearchResult> {
  const baseUrl = cleanBaseUrl(process.env.OPENCTI_URL);
  const token = process.env.OPENCTI_API_TOKEN;
  if (!baseUrl || !token) {
    return { configured: false, connected: false, indicators: [], failures: 0, message: "OpenCTI is not configured." };
  }
  const query =
    "query PrimeSecIndicatorSearch($s: String) { indicators(search: $s, first: 10) { edges { node { id name pattern pattern_type created_at x_opencti_score } } } }";
  const found = new Map<string, CtiIndicator>();
  let failures = 0;
  for (let i = 0; i < values.length; i += 5) {
    const batch = values.slice(i, i + 5);
    const results = await Promise.allSettled(batch.map((v) => openCtiGraphql(token, query, { s: v })));
    for (const r of results) {
      if (r.status === "rejected") { failures++; continue; }
      for (const n of nodes(r.value.indicators)) {
        found.set(n.id, {
          id: n.id, name: n.name || "Unnamed indicator", pattern: n.pattern || "", patternType: n.pattern_type || "",
          createdAt: n.created_at || null, score: num(n.x_opencti_score)
        });
      }
    }
  }
  const connected = values.length === 0 || failures < values.length;
  return {
    configured: true,
    connected,
    indicators: [...found.values()],
    failures,
    message: connected ? (failures ? "Some OpenCTI searches failed; results may be incomplete." : "OpenCTI searched.") : "OpenCTI could not be reached."
  };
}
