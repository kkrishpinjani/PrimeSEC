/** Starts the OpenTelemetry Node SDK. Imported only from instrumentation.ts, only on the Node runtime, only when OTEL_ENABLED=true. */
import { NodeSDK } from "@opentelemetry/sdk-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-http";
import { PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from "@opentelemetry/semantic-conventions";

let sdk: NodeSDK | undefined;

/** Loopback collector by default: spans describe internal activity, so they do not leave the host unless explicitly allowed. */
export function collectorUrl(env: Record<string, string | undefined> = process.env): string {
  const raw = (env.OTEL_EXPORTER_OTLP_ENDPOINT || "http://127.0.0.1:4318").trim().replace(/\/+$/, "");
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error("OTEL_EXPORTER_OTLP_ENDPOINT is not a valid URL."); }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("OTEL_EXPORTER_OTLP_ENDPOINT must be http or https.");
  if (url.username || url.password) throw new Error("OTEL_EXPORTER_OTLP_ENDPOINT must not contain credentials.");
  const loopback = ["127.0.0.1", "localhost", "::1", "[::1]"].includes(url.hostname);
  if (!loopback && env.OTEL_ALLOW_REMOTE !== "true") {
    throw new Error("OTEL_EXPORTER_OTLP_ENDPOINT points away from this machine; set OTEL_ALLOW_REMOTE=true to send telemetry off the host.");
  }
  return raw;
}

export async function startTelemetry(): Promise<void> {
  if (sdk) return;
  const base = collectorUrl();
  const interval = Math.max(5000, Number(process.env.OTEL_METRIC_EXPORT_INTERVAL_MS) || 15000);
  sdk = new NodeSDK({
    resource: resourceFromAttributes({
      [ATTR_SERVICE_NAME]: process.env.OTEL_SERVICE_NAME || "primesec-web",
      [ATTR_SERVICE_VERSION]: process.env.OTEL_SERVICE_VERSION || "1.0.0",
      "deployment.environment.name": process.env.OTEL_DEPLOYMENT_ENVIRONMENT || "development"
    }),
    traceExporter: new OTLPTraceExporter({ url: `${base}/v1/traces` }),
    metricReaders: [new PeriodicExportingMetricReader({ exporter: new OTLPMetricExporter({ url: `${base}/v1/metrics` }), exportIntervalMillis: interval })]
  });
  sdk.start();
  const stop = () => { sdk?.shutdown().catch(() => undefined); };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  console.log(JSON.stringify({ level: "info", event: "otel_started", service: process.env.OTEL_SERVICE_NAME || "primesec-web" }));
}
