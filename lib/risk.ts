/**
 * Explainable risk score for prioritising vulnerability remediation.
 *
 * It is a TRIAGE AID: not a probability of exploitation, not a replacement for CVSS, and not evidence that
 * anything is compromised. Every factor, its weight and its source are shown with the score.
 *
 * Unknown is not zero. A factor whose data is missing is excluded and the remaining weights are renormalised, and
 * the score then carries (a) the percentage of weight that is actually known and (b) a RANGE showing what the
 * score could be if every unknown factor were as low (0) or as high (100) as possible. Findings are ranked by
 * score, then by the top of that range, so missing context can never hide a potentially urgent finding.
 */
import type { Asset } from "./assets";
import type { ExploitEvidence, Finding } from "./findings";

export const FACTORS = ["severity", "exploit", "business", "exposure", "detection"] as const;
export type FactorId = (typeof FACTORS)[number];

export const WEIGHTS: Record<FactorId, number> = { severity: 0.3, exploit: 0.25, business: 0.2, exposure: 0.15, detection: 0.1 };
export const FACTOR_LABELS: Record<FactorId, string> = {
  severity: "Severity (CVSS from the scanner)",
  exploit: "Exploit evidence",
  business: "Asset criticality",
  exposure: "Exposure",
  detection: "Corroborating detection"
};

const CRITICALITY_VALUE: Record<string, number | null> = { Unknown: null, Low: 25, Medium: 50, High: 75, Critical: 100 };
const EXPOSURE_VALUE: Record<string, number | null> = { Unknown: null, Internal: 40, "Internet-facing": 100 };
const EXPLOIT_VALUE: Record<string, number | null> = { Unknown: null, "None known": 15, "Public exploit": 80, "Exploited in the wild": 100 };

export type RiskBand = "Critical" | "High" | "Medium" | "Low" | "Unrated";
export type Factor = { id: FactorId; label: string; weight: number; value: number | null; known: boolean; contribution: number | null; source: string };
export type Risk = {
  score: number | null;
  band: RiskBand;
  /** Percentage of the total weight whose data is known (100 = every factor known). */
  confidence: number;
  /** What the score would be with every unknown factor at 0 / at 100. Equal to `score` when nothing is unknown. */
  scoreMin: number | null;
  scoreMax: number | null;
  provisional: boolean;
  /** Set when a rule limited the score (explains why a high-importance host did not raise it). */
  note: string | null;
  factors: Factor[];
  model: string;
};

export const MODEL = "PrimeSEC explainable weighted score v2";
/** A finding with severity 0.0 (an informational "Log" result) is not a vulnerability. Host importance alone must not lift it. */
export const INFO_CAP = 20;
const clamp = (n: number) => Math.max(0, Math.min(100, n));

export function bandOf(score: number | null): RiskBand {
  if (score === null) return "Unrated";
  return score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 35 ? "Medium" : "Low";
}

export type ScoreInput = {
  severityScore: number;
  exploitEvidence?: ExploitEvidence | string | null;
  asset?: Pick<Asset, "criticality" | "exposure"> | null;
  /** 0-100 evidence that other monitoring (for example Wazuh) corroborates the finding. No source feeds this yet. */
  detectionEvidence?: number | null;
};

export function scoreRisk(input: ScoreInput): Risk {
  const sev = Number(input.severityScore);
  const values: Record<FactorId, number | null> = {
    // 0.0 is a KNOWN, low severity (an informational "Log" result), not missing data. Only a non-number is unknown.
    severity: Number.isFinite(sev) ? clamp(sev * 10) : null,
    exploit: EXPLOIT_VALUE[input.exploitEvidence ?? "Unknown"] ?? null,
    business: CRITICALITY_VALUE[input.asset?.criticality ?? "Unknown"] ?? null,
    exposure: EXPOSURE_VALUE[input.asset?.exposure ?? "Unknown"] ?? null,
    detection: typeof input.detectionEvidence === "number" && Number.isFinite(input.detectionEvidence) ? clamp(input.detectionEvidence) : null
  };
  const sources: Record<FactorId, string> = {
    severity: "Greenbone result severity x 10",
    exploit: "Analyst-recorded exploit evidence on the finding",
    business: "Analyst-recorded criticality of the host",
    exposure: "Analyst-recorded exposure of the host",
    detection: "No automated source is connected yet"
  };

  let known = 0, weighted = 0;
  const factors: Factor[] = FACTORS.map((id) => {
    const value = values[id];
    if (value !== null) { known += WEIGHTS[id]; weighted += value * WEIGHTS[id]; }
    return { id, label: FACTOR_LABELS[id], weight: WEIGHTS[id], value, known: value !== null, contribution: null, source: sources[id] };
  });
  if (known === 0) return { score: null, band: "Unrated", confidence: 0, scoreMin: null, scoreMax: null, provisional: true, note: null, factors, model: MODEL };

  const informational = values.severity === 0;
  const cap = (n: number) => (informational ? Math.min(n, INFO_CAP) : n);
  const raw = Math.round(weighted / known);
  const score = cap(raw);
  const note = informational && raw > INFO_CAP ? `Informational finding (severity 0.0): capped at ${INFO_CAP}. Host importance alone does not make a non-vulnerability urgent.` : null;
  for (const f of factors) f.contribution = f.value === null ? null : Math.round(((f.value * f.weight) / known) * 10) / 10;
  const unknownWeight = 1 - known;
  return {
    score,
    band: bandOf(score),
    confidence: Math.round(known * 100),
    scoreMin: cap(Math.round(weighted)),
    scoreMax: cap(Math.round(weighted + 100 * unknownWeight)),
    provisional: unknownWeight > 1e-9,
    note,
    factors,
    model: MODEL
  };
}

export type RiskFinding = Finding & { risk: Risk; asset: Pick<Asset, "criticality" | "exposure" | "updatedAt"> };

/** Pure ranking, so it can be tested without any storage. Highest score first, then the top of the range. */
export function rankFindings(findings: Finding[], assets: Map<string, Asset>, opts: { includeClosed?: boolean } = {}): RiskFinding[] {
  return findings
    .filter((f) => opts.includeClosed || !["Resolved", "Closed"].includes(f.remediationStatus))
    .map((f) => {
      const a = assets.get(f.host.trim().toLowerCase()) ?? null;
      const risk = scoreRisk({ severityScore: f.severityScore, exploitEvidence: f.exploitEvidence, asset: a });
      return { ...f, risk, asset: { criticality: a?.criticality ?? "Unknown", exposure: a?.exposure ?? "Unknown", updatedAt: a?.updatedAt ?? null } };
    })
    .sort((x, y) =>
      (y.risk.score ?? -1) - (x.risk.score ?? -1) ||
      (y.risk.scoreMax ?? -1) - (x.risk.scoreMax ?? -1) ||
      y.severityScore - x.severityScore ||
      x.host.localeCompare(y.host) ||
      x.name.localeCompare(y.name)
    );
}

export const METHODOLOGY = {
  model: MODEL,
  weights: WEIGHTS,
  note:
    "A triage aid, not a probability of exploitation and not a replacement for CVSS. Unknown factors are excluded and the remaining weights " +
    "renormalised; confidence is the share of weight that is known, and the range shows the score if every unknown factor were 0 or 100. " +
    "Ranking uses the score, then the top of the range."
};
