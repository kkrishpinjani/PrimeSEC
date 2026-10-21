/**
 * Deterministic, explainable correlation between a Wazuh alert and OpenCTI indicators.
 * Observables are extracted from both sides and compared for EXACT equality (after
 * normalisation). A match is only a lead for analyst review, never a confirmed incident.
 */
import type { CtiIndicator } from "./integrations";

export type ObservableType = "ipv4" | "domain" | "md5" | "sha1" | "sha256";
export type Observable = { type: ObservableType; value: string };

export type CorrelationMatch = {
  indicatorId: string;
  indicatorName: string;
  patternType: string;
  pattern: string;
  matchedValue: string;
  observableType: ObservableType;
  score: number | null;
  assessment: string;
};
export type Correlation = { observables: Observable[]; matches: CorrelationMatch[]; matchCount: number };

export const MAX_OBSERVABLES = 25;
export const ASSESSMENT = "Potential match: analyst validation required";

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const HASH = /\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi;
const DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
// Common file extensions that look like TLDs: "powershell.exe" is a file, not a domain.
const FILE_EXTENSIONS = new Set([
  "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jse", "py", "sh", "so", "tmp", "dat", "log", "txt", "conf", "cfg", "ini",
  "json", "xml", "yml", "yaml", "zip", "rar", "tar", "gz", "msi", "doc", "docx", "xls", "xlsx", "pdf", "lnk", "jar", "bin", "db", "sql", "html", "htm", "php", "asp", "aspx", "evtx"
]);

const norm = (v: string) => v.trim().toLowerCase();

/** Pulls IPs, domains and hashes out of free text. Order-stable and de-duplicated. */
export function extractObservables(text: string): Observable[] {
  const out = new Map<string, Observable>();
  const add = (type: ObservableType, raw: string) => {
    const value = norm(raw);
    if (value) out.set(`${type}:${value}`, { type, value });
  };
  const input = String(text || "");
  for (const ip of input.match(IPV4) || []) add("ipv4", ip);
  for (const h of input.match(HASH) || []) add(h.length === 64 ? "sha256" : h.length === 40 ? "sha1" : "md5", h);
  // strip IPs first so "203.0.113.45" is never read as a domain
  const withoutIps = input.replace(IPV4, " ");
  for (const d of withoutIps.match(DOMAIN) || []) {
    const tld = d.slice(d.lastIndexOf(".") + 1).toLowerCase();
    if (!FILE_EXTENSIONS.has(tld)) add("domain", d);
  }
  return [...out.values()];
}

/** Observables that OpenCTI itself holds for an indicator, from its name and STIX/other pattern. */
function indicatorObservables(indicator: CtiIndicator): Observable[] {
  return extractObservables(`${indicator.name} ${indicator.pattern}`);
}

export function correlate(alertText: string, indicators: CtiIndicator[]): Correlation {
  const observables = extractObservables(alertText).slice(0, MAX_OBSERVABLES);
  const alertSet = new Map(observables.map((o) => [`${o.type}:${o.value}`, o]));
  const matches: CorrelationMatch[] = [];
  for (const indicator of indicators) {
    for (const io of indicatorObservables(indicator)) {
      const hit = alertSet.get(`${io.type}:${io.value}`);
      if (!hit) continue;
      matches.push({
        indicatorId: indicator.id,
        indicatorName: indicator.name,
        patternType: indicator.patternType || "Unknown",
        pattern: indicator.pattern,
        matchedValue: hit.value,
        observableType: hit.type,
        score: indicator.score,
        assessment: ASSESSMENT
      });
      break; // one match per indicator is enough for the analyst
    }
  }
  return { observables, matches, matchCount: matches.length };
}
