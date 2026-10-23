/**
 * Application telemetry helpers. They use only @opentelemetry/api, which is a no-op until the SDK is started
 * (instrumentation.ts, and only when OTEL_ENABLED=true), so instrumented code costs nothing and cannot fail when
 * telemetry is off or the collector is down.
 *
 * Data protection: span and metric attributes are built from a FIXED vocabulary. Callers pass an integration and an
 * operation name chosen in code, never a URL, host, finding, prompt, token or user value, and anything outside the
 * vocabulary is recorded as "other" so metric label cardinality stays bounded.
 */
import { metrics, trace, SpanStatusCode, type Attributes } from "@opentelemetry/api";

const SCOPE = "primesec.application";
const tracer = trace.getTracer(SCOPE);
const meter = metrics.getMeter(SCOPE);
const calls = meter.createCounter("primesec.integration.calls", { description: "Outbound PrimeSEC integration calls" });
const errors = meter.createCounter("primesec.integration.errors", { description: "Failed outbound PrimeSEC integration calls" });
const duration = meter.createHistogram("primesec.integration.duration", { description: "Duration of outbound integration calls", unit: "ms" });

export const INTEGRATIONS = ["wazuh", "wazuh_indexer", "opencti", "greenbone", "ollama"] as const;
export const OPERATIONS = ["authenticate", "request", "search", "graphql", "overview", "findings", "assessments", "chat"] as const;
const pick = <T extends readonly string[]>(list: T, value: string): T[number] | "other" => ((list as readonly string[]).includes(value) ? (value as T[number]) : "other");

/** Keys that must never become attributes, whatever the caller passes. */
const FORBIDDEN_KEY = /token|secret|password|cookie|authorization|prompt|completion|body|evidence|pattern|ip.?address|host|email|url|finding|cve/i;
export function sanitizeAttributes(attributes: Record<string, unknown> = {}): Attributes {
  const out: Attributes = {};
  for (const [key, value] of Object.entries(attributes)) {
    if (value === undefined || value === null || FORBIDDEN_KEY.test(key)) continue;
    if (typeof value === "string") out[key] = value.slice(0, 120);
    else if (typeof value === "number" || typeof value === "boolean") out[key] = value;
  }
  return out;
}

const errorType = (error: unknown) => String((error as Error)?.name || "Error").replace(/[^a-zA-Z0-9_.-]/g, "").slice(0, 60) || "Error";

/**
 * Runs `fn` inside a span and records call count, error count and duration. Error messages are NOT recorded (they can
 * carry upstream text); only the error class name is.
 */
export async function instrumentedCall<T>(integration: string, operation: string, fn: () => Promise<T>): Promise<T> {
  const labels = { "primesec.integration": pick(INTEGRATIONS, integration), "primesec.operation": pick(OPERATIONS, operation) };
  const started = Date.now();
  let outcome = "success";
  return tracer.startActiveSpan(`integration.${labels["primesec.integration"]}.${labels["primesec.operation"]}`, { attributes: labels }, async (span) => {
    try {
      return await fn();
    } catch (error) {
      outcome = "error";
      span.setAttribute("error.type", errorType(error));
      span.setStatus({ code: SpanStatusCode.ERROR });
      throw error;
    } finally {
      span.setAttribute("primesec.outcome", outcome);
      span.end();
      const attrs = { ...labels, "primesec.outcome": outcome };
      calls.add(1, attrs);
      if (outcome === "error") errors.add(1, attrs);
      duration.record(Date.now() - started, attrs);
    }
  });
}
