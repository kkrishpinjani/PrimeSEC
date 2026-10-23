# Day 8 acceptance checklist (OpenTelemetry: traces, metrics, Observe page)

[x] = verified against the running app with a real OpenTelemetry Collector, Jaeger and Prometheus in Docker (collector 0.140.0, Jaeger 1.62.0, Prometheus v2.55.1), real Ollama and the demo Wazuh/OpenCTI/Greenbone servers. Not verified: a production deployment, persistent trace storage, TLS/auth to telemetry backends.

## Switch and safety
- [x] **Opt-in.** Telemetry loads only when `OTEL_ENABLED=true`; otherwise nothing is imported or exported and the helpers are no-ops. *The supplied package enabled it by default.*
- [x] A telemetry start-up failure is logged and never stops the app. With the collector **down** the app kept answering (200 on dashboard, VAPT, findings, observe) and the Observe page reports the collector "Unavailable".
- [x] **Telemetry stays on the machine.** A non-loopback `OTEL_EXPORTER_OTLP_ENDPOINT` (including a LAN address or a look-alike host) is refused unless `OTEL_ALLOW_REMOTE=true`.

## What is recorded
- [x] Next.js request spans (route and status), plus one span and three metrics per outbound call to Wazuh (API and indexer), OpenCTI, the Greenbone bridge and Ollama: `integration.<name>.<operation>`, `primesec_integration_calls_total`, `..._errors_total`, `..._duration_milliseconds`. Seen in Jaeger and Prometheus for all eight call types.
- [x] **Bounded labels.** Integration and operation come from fixed lists chosen in code (never a URL); anything else becomes `other`. Metric series carry only integration, operation and outcome.
- [x] **No sensitive data in spans.** Verified on real traces: no credential-like attribute keys, no bearer tokens or session cookies in values. Error spans record the error class only, never its message. A helper drops attributes named like token, secret, password, cookie, prompt, body, evidence, host, url, finding, CVE.
- [x] **Query strings are redacted in the collector**: a request to `/api/vapt/reports/compare?baseline=SECRETISH123...` appears in Jaeger as `...compare?REDACTED`. Authorization and cookie header attributes are dropped there too.

## Observe page (`/observe`, `GET /api/observe/health`)
- [x] Any PrimeSEC role; 401 when signed out; GET only; rate-limited to 30 per minute per user (429).
- [x] Reports only state and latency for the Collector, Jaeger and Prometheus: no URL, host or port in the response (checked).
- [x] The page says plainly that reachability is not proof that data is flowing, and that app telemetry is off when it is.

## Stack (`docker compose --profile observe up -d jaeger otel-collector prometheus`)
- [x] All ports bound to 127.0.0.1; only 4318 (OTLP), 13133 (health), 16686 and 9090 are published. The collector's Prometheus port and Jaeger's OTLP port stay on the compose network. *The supplied file published them.*
- [x] Pinned images. *The supplied collector tag (0.115.0) no longer exists on Docker Hub and its config used an option removed from current collectors; both fixed and the stack was run.*
- [x] Packages: a consistent OpenTelemetry 2.x set (sdk-node 0.220.0 with core/resources/sdk-metrics 2.9.0). *The supplied versions did not match each other (the code used `resourceFromAttributes` and a semantic-convention constant that its pinned versions do not provide) and the 2.7 line has an open advisory.* `npm audit` reports 0 vulnerabilities. No auto-instrumentation bundle is installed (it adds hundreds of packages); the Next.js request spans plus the integration spans cover what this app needs.
- [x] 23 unit tests (`npm run test:telemetry`) and 26 end-to-end checks.

## Not done / limits
- [ ] Application logs are not exported (no OTLP logs pipeline), and there are no Grafana dashboards, alert rules or SLOs.
- [ ] Jaeger here is in-memory: traces are lost when its container restarts. Prometheus keeps 7 days in a Docker volume.
- [ ] No TLS or authentication between the app, collector and backends; fine for loopback, not for a shared host.
- [ ] Spans are not linked to audit events or to individual users (by design: no user identifiers in telemetry).
- [ ] Review exported attributes again after adding new instrumentation or after a Next.js upgrade.
