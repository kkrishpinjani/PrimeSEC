import {
  getOpenCtiOverview,
  getWazuhOverview,
  type IntegrationStatus,
  type OpenCtiOverview,
  type SeverityCounts,
  type WazuhOverview
} from "./integrations";

export type Stat = [label: string, value: string];
export type Indicator = { type: string; value: string; tag: string; conf: number | null };
export type Vulnerability = { host: string; title: string; sev: "Critical" | "High" | "Medium" | "Low"; score: number };
/** `id` is the Wazuh document id; only live alerts (investigable: true) can be sent to /api/investigations. */
export type Alert = { id: string; rule: string; agent: string; detail: string; level: number; investigable: boolean };
export type MapMarker = { lat: number; lon: number; label: string; count: number; severity: "high" | "normal" };
export type MapHome = { lat: number; lon: number; label: string };

/** live = real platform data, mixed = partly real, sample = placeholder data. */
export type SectionSource = "live" | "mixed" | "sample";
export type SectionId = "overview" | "intel" | "vulns" | "investigations";

export type DashboardData = {
  sources: Record<SectionId, SectionSource>;
  integrations: { wazuh: IntegrationStatus; opencti: IntegrationStatus };
  /** Team and region are configured labels (PRIMESEC_TEAM / PRIMESEC_REGION), hidden when unset. */
  scope: { team: string | null; region: string | null; range: string };
  /** Only real, geolocated alert sources are ever drawn on the globe. */
  map: { home: MapHome | null; markers: MapMarker[] };
  radar: { score: number; basis: string };
  /** 24 hourly alert counts, oldest first (the "attack volume trend"). */
  trend: number[];
  /** 24 hourly counts of level 12+ alerts (the "threat activity timeline"). */
  timeline: number[];
  severity: SeverityCounts;
  overview: { stats: Stat[] };
  intel: { indicators: Indicator[]; actors: [string, number | null][]; stats: Stat[] };
  vulns: { items: Vulnerability[]; stats: Stat[] };
  investigations: { alerts: Alert[]; stats: Stat[] };
  /** True when the connected platforms are the local fake demo servers (DEMO_INTEGRATIONS=true). */
  demo: boolean;
  /** Plain-language caveats shown under the dashboard. */
  notes: string[];
};

const fmt = (n: number | null | undefined) => (n == null ? "—" : n.toLocaleString("en-US"));
const day = (iso: string | null) => (iso ? new Date(iso).toISOString().slice(0, 10) : "");

/**
 * Documented, deterministic score from the last 24 h of alerts.
 * load = High×10 + Medium×2 + Low×0.5 + Info×0.1; level = 1000 × (1 − e^(−load / 2000)).
 * The curve rises smoothly with load and approaches, but never clips at, 1000.
 */
export function threatLevel(s: SeverityCounts): number {
  const load = s.high * 10 + s.medium * 2 + s.low * 0.5 + s.info * 0.1;
  return Math.round(1000 * (1 - Math.exp(-load / 2000)));
}
const RADAR_BASIS = "Weighted 24h alert load (High×10 + Medium×2 + Low×0.5 + Info×0.1), scaled to 0–1000 as 1000×(1−e^(−load/2000)).";

const SAMPLE = {
  trend: Array.from({ length: 24 }, (_, i) => 20 + ((i * 37) % 60)),
  timeline: Array.from({ length: 24 }, (_, i) => 10 + ((i * 53) % 70)),
  severity: { high: 93, medium: 215, low: 1203, info: 532 } as SeverityCounts,
  overview: [["Security score", "98%"], ["Threats blocked", "14,872"], ["Active incidents", "93"]] as Stat[],
  intel: {
    indicators: [
      { type: "IPv4", value: "203.0.113.45", tag: "C2 server", conf: 92 },
      { type: "Domain", value: "update-check.example", tag: "Phishing", conf: 85 },
      { type: "SHA-256", value: "9f2c…e41a", tag: "Ransomware", conf: 78 },
      { type: "IPv4", value: "198.51.100.17", tag: "Scanner", conf: 64 }
    ] as Indicator[],
    actors: [["APT-Alpha", 88], ["FIN-Delta", 61], ["Hacktivist-7", 37]] as [string, number | null][],
    stats: [["Indicators", "12,480"], ["Actors tracked", "214"], ["Reports", "3,092"]] as Stat[]
  },
  vulns: {
    items: [
      { host: "web-01", title: "Outdated TLS configuration", sev: "High", score: 87 },
      { host: "db-02", title: "Default service credentials", sev: "Critical", score: 96 },
      { host: "app-05", title: "Unpatched web framework", sev: "High", score: 81 },
      { host: "vpn-gw", title: "Weak cipher suite enabled", sev: "Medium", score: 52 }
    ] as Vulnerability[],
    stats: [["Open findings", "128"], ["Scans this week", "14"], ["Avg. time to fix", "6.2 d"]] as Stat[]
  },
  investigations: {
    alerts: [
      { id: "sample-0", rule: "Multiple failed SSH logins", agent: "web-01", detail: "Match: 203.0.113.45", level: 10, investigable: false },
      { id: "sample-1", rule: "Suspicious PowerShell execution", agent: "ws-114", detail: "Match: SHA-256 9f2c…e41a", level: 12, investigable: false },
      { id: "sample-2", rule: "Outbound beacon to rare domain", agent: "app-05", detail: "Match: update-check.example", level: 9, investigable: false }
    ] as Alert[],
    stats: [["Open alerts", "37"], ["Matched with intel", "9"], ["Avg. triage", "11 min"]] as Stat[]
  }
};

function homeFromEnv(): MapHome | null {
  const lat = Number(process.env.PRIMESEC_HOME_LAT), lon = Number(process.env.PRIMESEC_HOME_LON);
  if (!process.env.PRIMESEC_HOME_LAT || !process.env.PRIMESEC_HOME_LON) return null;
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
  return { lat, lon, label: process.env.PRIMESEC_HOME_LABEL || "SOC" };
}

type Overview = Pick<DashboardData, "radar" | "trend" | "timeline" | "severity" | "map"> & { source: SectionSource; stats: Stat[]; notes: string[] };

function overviewFrom(w: WazuhOverview): Overview {
  const home = homeFromEnv();
  const sampleBase = {
    radar: { score: 986, basis: "Sample value" },
    trend: SAMPLE.trend,
    timeline: SAMPLE.timeline,
    severity: SAMPLE.severity,
    map: { home, markers: [] as MapMarker[] }
  };
  const managerUp = w.status.connected;
  const indexerUp = w.alerts.available && w.alerts.severity !== null;
  if (!managerUp && !indexerUp) return { source: "sample", stats: SAMPLE.overview, notes: [], ...sampleBase };

  const endpoints: Stat = ["Endpoints", managerUp ? fmt(w.agents.total) : "—"];
  if (!indexerUp || !w.alerts.severity) {
    return {
      source: "mixed",
      stats: [endpoints, ["Alerts (24h)", "—"], ["Critical alerts (24h)", "—"]],
      notes: ["Overview charts, severity counts and the map need the Wazuh Indexer (WAZUH_INDEXER_URL and credentials)."],
      ...sampleBase
    };
  }
  const markers: MapMarker[] = w.alerts.sources.map((s) => ({
    lat: s.lat, lon: s.lon, count: s.count,
    severity: s.maxLevel >= 12 ? "high" : "normal",
    label: `${[s.city, s.country].filter(Boolean).join(", ") || "Unknown location"} · ${s.ip} (${s.count} alerts)`
  }));
  const notes: string[] = [];
  if (!markers.length) notes.push("No geolocated alert sources in the last 24 h (the map needs Wazuh GeoIP data on srcip).");
  else if (!home) notes.push("Set PRIMESEC_HOME_LAT and PRIMESEC_HOME_LON to draw attack paths to your SOC.");
  return {
    source: managerUp ? "live" : "mixed",
    stats: [endpoints, ["Alerts (24h)", fmt(w.alerts.total24h)], ["Critical alerts (24h)", fmt(w.alerts.critical24h)]],
    radar: { score: threatLevel(w.alerts.severity), basis: RADAR_BASIS },
    trend: w.alerts.hourly,
    timeline: w.alerts.hourlyHigh,
    severity: w.alerts.severity,
    map: { home, markers },
    notes
  };
}

function intelFrom(c: OpenCtiOverview): { source: SectionSource; data: DashboardData["intel"] } {
  if (!c.status.connected) return { source: "sample", data: SAMPLE.intel };
  const latest = (total: number | null, shown: number) => (total == null ? ` (latest ${shown})` : "");
  return {
    source: "live",
    data: {
      indicators: c.indicators.map((i) => ({ type: i.patternType || "Indicator", value: i.name, tag: day(i.createdAt), conf: i.score })),
      actors: c.threatActors.map((a) => [a.name, null]),
      stats: [
        [`Indicators${latest(c.totals.indicators, c.indicators.length)}`, fmt(c.totals.indicators ?? c.indicators.length)],
        [`Threat actors${latest(c.totals.threatActors, c.threatActors.length)}`, fmt(c.totals.threatActors ?? c.threatActors.length)],
        [`Reports${latest(c.totals.reports, c.reports.length)}`, fmt(c.totals.reports ?? c.reports.length)]
      ]
    }
  };
}

function vulnsFrom(w: WazuhOverview): { source: SectionSource; data: DashboardData["vulns"]; note?: string } {
  if (!w.vulns.available) {
    return { source: "sample", data: SAMPLE.vulns, note: w.vulns.configured ? w.vulns.message : undefined };
  }
  return {
    source: "live",
    data: {
      items: w.vulns.top,
      stats: [["Open findings", fmt(w.vulns.total)], ["Critical", fmt(w.vulns.critical)], ["Hosts affected", fmt(w.vulns.hosts)]]
    }
  };
}

function investigationsFrom(w: WazuhOverview): { source: SectionSource; data: DashboardData["investigations"] } {
  if (!w.alerts.available) return { source: "sample", data: SAMPLE.investigations };
  return {
    source: "live",
    data: {
      alerts: w.alerts.recent.map((a) => ({ id: a.id, rule: a.description, agent: a.agent, detail: `Source IP: ${a.sourceIp}`, level: a.level, investigable: true })),
      stats: [["Alerts (24h)", fmt(w.alerts.total24h)], ["Critical (24h)", fmt(w.alerts.critical24h)], ["Endpoints", fmt(w.agents.total)]]
    }
  };
}

/**
 * Single seam for dashboard data. Wazuh and OpenCTI are queried server-side; any section whose
 * platform is not configured or unreachable falls back to sample data and is labelled as such.
 */
export async function getDashboardData(): Promise<DashboardData> {
  const [wazuh, cti] = await Promise.all([getWazuhOverview(), getOpenCtiOverview()]);
  const overview = overviewFrom(wazuh);
  const intel = intelFrom(cti);
  const vulns = vulnsFrom(wazuh);
  const investigations = investigationsFrom(wazuh);

  return {
    sources: { overview: overview.source, intel: intel.source, vulns: vulns.source, investigations: investigations.source },
    integrations: { wazuh: wazuh.status, opencti: cti.status },
    scope: { team: process.env.PRIMESEC_TEAM || null, region: process.env.PRIMESEC_REGION || null, range: "Last 24 Hours" },
    map: overview.map,
    radar: overview.radar,
    trend: overview.trend,
    timeline: overview.timeline,
    severity: overview.severity,
    overview: { stats: overview.stats },
    intel: intel.data,
    vulns: vulns.data,
    investigations: investigations.data,
    demo: process.env.DEMO_INTEGRATIONS === "true",
    notes: [...overview.notes, ...(vulns.note ? [vulns.note] : [])]
  };
}
