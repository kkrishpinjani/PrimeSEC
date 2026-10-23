// Tests for the telemetry helpers: bounded vocabulary, attribute filtering, no error messages in spans,
// and the collector endpoint guard. Run: npm run test:telemetry (Node 22.6+; TypeScript is type-stripped).
import { trace } from "@opentelemetry/api";
import { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";

const exporter = new InMemorySpanExporter();
trace.setGlobalTracerProvider(new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(exporter)] }));

const T = await import("../lib/telemetry.ts");
const N = await import("../lib/telemetry-node.ts");

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const throws = (name, fn) => { try { fn(); fail++; console.log("FAIL (no error):", name); } catch { pass++; } };

// ---- vocabulary ----
await T.instrumentedCall("wazuh", "request", async () => 1);
await T.instrumentedCall("10.0.0.5", "GET /secret?token=abc", async () => 1);
let spans = exporter.getFinishedSpans();
ok("known integration and operation named as given", spans[0].name === "integration.wazuh.request");
ok("unknown values collapse to 'other'", spans[1].name === "integration.other.other", spans[1].name);
ok("no caller-supplied string reaches an attribute", JSON.stringify(spans[1].attributes).indexOf("10.0.0.5") === -1 && JSON.stringify(spans[1].attributes).indexOf("secret") === -1);
ok("outcome recorded as success", spans[0].attributes["primesec.outcome"] === "success");

// ---- errors ----
exporter.reset();
const boom = Object.assign(new Error("upstream said: password=hunter2 at http://10.1.2.3"), { name: "UpstreamError" });
let caught;
try { await T.instrumentedCall("opencti", "graphql", async () => { throw boom; }); } catch (e) { caught = e; }
ok("the original error is rethrown unchanged", caught === boom);
spans = exporter.getFinishedSpans();
ok("failed span has error outcome", spans[0].attributes["primesec.outcome"] === "error" && spans[0].status.code === 2);
ok("error type recorded", spans[0].attributes["error.type"] === "UpstreamError");
ok("error message and detail are NOT recorded anywhere", !JSON.stringify({ n: spans[0].name, a: spans[0].attributes, e: spans[0].events, s: spans[0].status }).match(/hunter2|10\.1\.2\.3/) && spans[0].events.length === 0);
ok("return value passes through", (await T.instrumentedCall("greenbone", "findings", async () => 42)) === 42);

// ---- attribute filter ----
const a = T.sanitizeAttributes({ ok: "x", n: 5, b: true, token: "t", Authorization: "a", password: "p", cookie: "c", prompt: "p", body: "b", evidence: "e", pattern: "x", host: "h", hostname: "h", ip_address: "1.2.3.4", email: "a@b.c", url: "http://x", finding_id: "f", cve: "CVE-1", obj: { a: 1 }, nul: null, long: "y".repeat(500) });
ok("safe keys kept", a.ok === "x" && a.n === 5 && a.b === true);
ok("sensitive keys dropped", ["token", "Authorization", "password", "cookie", "prompt", "body", "evidence", "pattern", "host", "hostname", "ip_address", "email", "url", "finding_id", "cve"].every((k) => !(k in a)), Object.keys(a).join());
ok("objects and nulls dropped", !("obj" in a) && !("nul" in a));
ok("long strings capped", a.long.length === 120);

// ---- collector endpoint guard ----
ok("default is loopback", N.collectorUrl({}) === "http://127.0.0.1:4318");
ok("localhost ok", N.collectorUrl({ OTEL_EXPORTER_OTLP_ENDPOINT: "http://localhost:4318/" }) === "http://localhost:4318");
throws("remote refused by default", () => N.collectorUrl({ OTEL_EXPORTER_OTLP_ENDPOINT: "http://telemetry.example.com:4318" }));
throws("LAN refused by default", () => N.collectorUrl({ OTEL_EXPORTER_OTLP_ENDPOINT: "http://192.168.1.9:4318" }));
throws("look-alike host refused", () => N.collectorUrl({ OTEL_EXPORTER_OTLP_ENDPOINT: "http://127.0.0.1.evil.com" }));
ok("remote allowed with explicit flag", N.collectorUrl({ OTEL_EXPORTER_OTLP_ENDPOINT: "http://192.168.1.9:4318", OTEL_ALLOW_REMOTE: "true" }) === "http://192.168.1.9:4318");
throws("flag must be exactly true", () => N.collectorUrl({ OTEL_EXPORTER_OTLP_ENDPOINT: "http://192.168.1.9:4318", OTEL_ALLOW_REMOTE: "1" }));
throws("credentials refused", () => N.collectorUrl({ OTEL_EXPORTER_OTLP_ENDPOINT: "http://u:p@127.0.0.1:4318" }));
throws("non-http refused", () => N.collectorUrl({ OTEL_EXPORTER_OTLP_ENDPOINT: "file:///x" }));
throws("garbage refused", () => N.collectorUrl({ OTEL_EXPORTER_OTLP_ENDPOINT: "nope" }));

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
