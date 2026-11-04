/**
 * Read-only alert investigation: re-read the alert from Wazuh (the browser never supplies alert contents), extract its observables,
 * CVE ids and MITRE technique ids, search OpenCTI for matching indicators and known vulnerabilities, and correlate. Shared by the
 * Investigate button and by "open a case from an alert". Nothing here blocks, isolates or changes anything.
 */
import { getWazuhAlertById, openCtiConfigured, openCtiRequest, searchOpenCtiIndicators, wazuhSafeError, type WazuhAlert } from "./integrations.ts";
import { correlate, extractCves, extractObservables, extractTechniques, MAX_OBSERVABLES, type Correlation } from "./correlation.ts";
import { browse, type Deps } from "./opencti.ts";

/** Wazuh/OpenSearch document ids: short, URL-safe. Anything else is rejected before it reaches an upstream query. */
export const ALERT_ID = /^[A-Za-z0-9_\-:.]{1,200}$/;

export class InvestigateError extends Error {
  code: "INVALID" | "NOT_FOUND" | "NOT_CONFIGURED";
  constructor(message: string, code: InvestigateError["code"]) {
    super(message);
    this.code = code;
  }
}

export type VulnerabilityMatch = {
  cve: string;
  /** True when OpenCTI holds this CVE. null when OpenCTI could not be asked. */
  known: boolean | null;
  cvss: number | null;
  /** CISA lists it as exploited in the wild (OpenCTI's CISA KEV connector sets the flag). null when unknown. */
  knownExploited: boolean | null;
  restricted: boolean;
};

export type InvestigationResult = {
  alert: WazuhAlert;
  searched: number;
  openCti: { configured: boolean; connected: boolean; message: string };
  correlation: Correlation;
  /** CVE ids found in the alert, each looked up in OpenCTI by exact id. */
  vulnerabilities: VulnerabilityMatch[];
  /** MITRE ATT&CK technique ids from the alert and its rule. Context only: they are not used to match indicators. */
  techniques: string[];
};

const realDeps = (): Deps => ({ query: openCtiRequest, configured: openCtiConfigured, safeError: wazuhSafeError, env: process.env });

/** Exact-id lookup: OpenCTI's search is a text search, so only a result whose name IS the CVE counts. One failed lookup never fails the investigation. */
export async function lookupCves(cves: string[], deps: Deps = realDeps()): Promise<VulnerabilityMatch[]> {
  const out: VulnerabilityMatch[] = [];
  for (const cve of cves) {
    try {
      const page = await browse("vulnerabilities", { search: cve, first: 5 }, deps);
      const hit = page.items.find((i) => (i.restricted ? false : i.name.toUpperCase() === cve));
      const restricted = !hit && page.items.some((i) => i.restricted);
      out.push({
        cve, known: hit ? true : restricted ? null : false,
        cvss: hit && typeof hit.fields.x_opencti_cvss_base_score === "number" ? hit.fields.x_opencti_cvss_base_score : null,
        knownExploited: hit ? (typeof hit.fields.x_opencti_cisa_kev === "boolean" ? hit.fields.x_opencti_cisa_kev : null) : null,
        restricted
      });
    } catch {
      out.push({ cve, known: null, cvss: null, knownExploited: null, restricted: false });
    }
  }
  return out;
}

export async function investigateAlert(alertId: unknown, deps?: Deps): Promise<InvestigationResult> {
  if (typeof alertId !== "string" || !alertId) throw new InvestigateError("alertId is required.", "INVALID");
  if (!ALERT_ID.test(alertId)) throw new InvestigateError("alertId is not a valid Wazuh alert id.", "INVALID");
  let detail;
  try {
    detail = await getWazuhAlertById(alertId);
  } catch (error) {
    if ((error as { code?: string })?.code === "NOT_CONFIGURED") throw new InvestigateError("The Wazuh Indexer is not configured, so alerts cannot be investigated.", "NOT_CONFIGURED");
    throw error;
  }
  if (!detail) throw new InvestigateError("Alert not found in Wazuh. Refresh and try again.", "NOT_FOUND");
  const observables = extractObservables(detail.text).slice(0, MAX_OBSERVABLES);
  const cti = await searchOpenCtiIndicators(observables.map((o) => o.value));
  const cves = extractCves(detail.text);
  return {
    alert: detail.alert,
    searched: observables.length,
    openCti: { configured: cti.configured, connected: cti.connected, message: cti.message },
    correlation: correlate(detail.text, cti.indicators),
    vulnerabilities: cves.length && (deps ? deps.configured() : openCtiConfigured()) ? await lookupCves(cves, deps) : cves.map((cve) => ({ cve, known: null, cvss: null, knownExploited: null, restricted: false })),
    techniques: [...new Set([...detail.mitre.map((t) => t.toUpperCase()), ...extractTechniques(detail.text)])].slice(0, 25)
  };
}
