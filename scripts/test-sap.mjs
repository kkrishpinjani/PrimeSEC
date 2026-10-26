// Tests for the SAP configuration-risk module: rules, parsing, input limits, knowledge search, explanation guard, storage.
// Run: npm run test:sap (Node 22.6+; TypeScript is type-stripped).
import http from "node:http";
import { mkdtempSync, writeFileSync, mkdirSync, cpSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const root = process.cwd();
const work = mkdtempSync(path.join(tmpdir(), "primesec-sap-"));
mkdirSync(path.join(work, "knowledge"), { recursive: true });
cpSync(path.join(root, "knowledge", "sap"), path.join(work, "knowledge", "sap"), { recursive: true });
process.chdir(work);
const S = await import(path.join(root, "lib", "sap.ts").replace(/\\/g, "/").replace(/^([A-Za-z]):/, "file:///$1:"));

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const throws = (name, fn, code = "INVALID") => { try { fn(); fail++; console.log("FAIL (no error):", name); } catch (e) { (e.code === code) ? pass++ : (fail++, console.log("FAIL (wrong error):", name, e.code, e.message)); } };
const A = (over = {}) => S.analyzeConfig({ assetId: "LAB", saprouttab: "", gatewayProfile: "", reginfo: "", secinfo: "", ...over });
const ids = (fs) => new Set(fs.map((f) => f.id));

// ---- the original package's tests, ported ----
const demo = A({ saprouttab: 'P * * *\nKP "p:CN=trusted-router" * sapdp00', gatewayProfile: "snc/enable = 0\nsnc/permit_insecure_start = 1\ngw/acl_mode = 0", reginfo: "P TP=* HOST=*", secinfo: "P TP=* HOST=*" });
ok("demo input detects all seven rules", ["SAPROUTER-001", "SAPROUTER-002", "SAPGW-001", "SAPGW-002", "SAPGW-003", "SAPGW-004", "SAPGW-005"].every((i) => ids(demo).has(i)), [...ids(demo)].join());
const scoped = A({ saprouttab: 'P 10.1.2.3 sapapp01 3200\nKP "p:CN=trusted-router" sapapp01 sapdp00', gatewayProfile: "snc/enable = 1\nsnc/permit_insecure_start = 0\ngw/acl_mode = 1", reginfo: "P TP=Z_SAFE_PROGRAM HOST=10.1.2.3", secinfo: "P TP=Z_SAFE_PROGRAM HOST=10.1.2.3" });
ok("scoped, hardened configuration produces no finding", scoped.length === 0, [...ids(scoped)].join());
ok("the built-in demo input matches the original demo", S.DEMO_INPUT.assetId === "SAP-LAB-DEMO-01" && ids(A({ saprouttab: S.DEMO_INPUT.saprouttab, gatewayProfile: S.DEMO_INPUT.gatewayProfile, reginfo: S.DEMO_INPUT.reginfo, secinfo: S.DEMO_INPUT.secinfo })).size === 7);

// ---- fixes over the original: deny lines are not findings ----
ok("a final deny-all line in reginfo/secinfo is NOT flagged", A({ reginfo: "P TP=Z_APP HOST=10.1.2.3\nD TP=* HOST=*", secinfo: "D TP=* HOST=*" }).length === 0);
ok("a permit line IS flagged even when other tokens are present", ids(A({ reginfo: "P TP=* USER=* HOST=* USER-HOST=*" })).has("SAPGW-004"));
ok("wildcard in only one of program/host is not flagged", A({ reginfo: "P TP=* HOST=10.0.0.5" }).length === 0 && A({ secinfo: "P TP=Z_X HOST=*" }).length === 0);
ok("lower-case keywords are understood", ids(A({ secinfo: "p tp=* host=*" })).has("SAPGW-005"));
ok("commented-out wildcard rules are ignored", A({ reginfo: "# P TP=* HOST=*", secinfo: "#P TP=* HOST=*" }).length === 0);
ok("version header line is ignored", A({ reginfo: "#VERSION=2\nP TP=Z_APP HOST=10.1.2.3" }).length === 0);

// ---- fixes: quoted SNC names with spaces, overlap-aware ordering ----
ok("tokenizer keeps a quoted SNC name (with spaces) as one field", JSON.stringify(S.tokenize('KP "p:CN=router, O=Example Corp, C=DE" dest svc')) === JSON.stringify(["KP", "p:CN=router, O=Example Corp, C=DE", "dest", "svc"]));
ok("ordering finding still works when the SNC name contains spaces", ids(A({ saprouttab: 'P * * *\nKP "p:CN=a b, O=c d" * sapdp00' })).has("SAPROUTER-002"));
ok("a broad permit for a DIFFERENT destination does not shadow the SNC rule", !ids(A({ saprouttab: 'P * sapother 3200\nKP "p:CN=r" sapapp01 3200' })).has("SAPROUTER-002"));
ok("a broad permit for a different service does not shadow it either", !ids(A({ saprouttab: 'P * sapapp01 3299\nKP "p:CN=r" sapapp01 3200' })).has("SAPROUTER-002"));
ok("same destination and service: flagged", ids(A({ saprouttab: 'P * sapapp01 3200\nKP "p:CN=r" sapapp01 3200' })).has("SAPROUTER-002"));
ok("prefix wildcard destination covers the SNC rule", ids(A({ saprouttab: 'P * sapapp* 3200\nKP "p:CN=r" sapapp01 3200' })).has("SAPROUTER-002"));
ok("an SNC rule listed BEFORE the broad permit is fine", !ids(A({ saprouttab: 'KP "p:CN=r" sapapp01 3200\nP * sapapp01 3200' })).has("SAPROUTER-002"));
ok("a permit with a specific source cannot shadow by wildcard source", !ids(A({ saprouttab: 'P 10.1.1.1 sapapp01 3200\nKP "p:CN=r" sapapp01 3200' })).has("SAPROUTER-002"));
ok("covers(): wildcard, equality, prefix, case", S.covers("*", "x") && S.covers("AbC", "abc") && S.covers("sap*", "sapapp") && !S.covers("sap", "sapapp") && !S.covers("sapapp", "sap*x"));

// ---- fixes: every matching line is reported, not just the first ----
const many = A({ saprouttab: "P * * *\nP * * *\nP * * *", reginfo: "P TP=* HOST=*\nP TP=* HOST=*" });
ok("all matching broad route lines are listed as evidence", many.find((f) => f.id === "SAPROUTER-001").evidence.length === 3);
ok("all matching reginfo lines are listed", many.find((f) => f.id === "SAPGW-004").evidence.length === 2);
const huge = A({ saprouttab: Array.from({ length: 40 }, () => "P * * *").join("\n") });
ok("evidence is capped with a note instead of flooding", huge.find((f) => f.id === "SAPROUTER-001").evidence.length === 6 && /more matching/.test(huge.find((f) => f.id === "SAPROUTER-001").evidence[5]));
ok("line numbers in evidence are 1-based and skip comments", A({ saprouttab: "# header\nP * * *" })[0].evidence[0].startsWith("saprouttab line 2:"));

// ---- gateway profile parsing ----
ok("parameter names are case-insensitive", ids(A({ gatewayProfile: "SNC/Enable = 0" })).has("SAPGW-001"));
ok("false/off/no also count as disabled", ["false", "off", "no", "0"].every((v) => ids(A({ gatewayProfile: `snc/enable=${v}` })).has("SAPGW-001")));
ok("true/on/yes/1 count as enabled for permit_insecure_start", ["true", "on", "yes", "1"].every((v) => ids(A({ gatewayProfile: `snc/permit_insecure_start=${v}` })).has("SAPGW-002")));
ok("an absent parameter is not a finding (nothing is assumed)", A({ gatewayProfile: "gw/something_else = 1" }).length === 0);
ok("gw/acl_mode other than 0 is not flagged", A({ gatewayProfile: "gw/acl_mode = 1" }).length === 0);
ok("value with extra spaces and an equals sign inside is parsed", ids(A({ gatewayProfile: "  snc/enable   =   0  " })).has("SAPGW-001"));

// ---- finding shape ----
const f = demo[0];
ok("every finding carries evidence, rationale, remediation, references and the review status", demo.every((x) => x.evidence.length && x.rationale && x.remediation.length && x.references.every((r) => /^https:\/\/help\.sap\.com\//.test(r)) && x.validation_status === "configuration evidence only"));
ok("findings never claim confirmed exploitability", demo.every((x) => !/confirmed exploit|is exploitable/i.test(x.rationale)));
ok("no finding id is repeated", new Set(demo.map((x) => x.id)).size === demo.length);

// ---- input validation ----
const good = { assetId: "SAP-LAB-01", saprouttab: "P * * *" };
ok("valid input accepted", S.validateInput(good).assetId === "SAP-LAB-01");
ok("blank asset id defaults", S.validateInput({ saprouttab: "P * * *" }).assetId === "SAP-ASSET-UNNAMED");
throws("asset id with spaces", () => S.validateInput({ ...good, assetId: "bad id" }));
throws("asset id with shell characters", () => S.validateInput({ ...good, assetId: "a;rm -rf /" }));
throws("asset id with path characters", () => S.validateInput({ ...good, assetId: "../../etc" }));
throws("asset id too long", () => S.validateInput({ ...good, assetId: "a".repeat(129) }));
throws("nothing to assess", () => S.validateInput({ assetId: "X" }));
throws("all inputs blank", () => S.validateInput({ assetId: "X", saprouttab: "  \n ", reginfo: "" }));
throws("non-text input", () => S.validateInput({ ...good, reginfo: { a: 1 } }));
throws("array instead of text", () => S.validateInput({ ...good, secinfo: ["P TP=* HOST=*"] }));
throws("saprouttab over the size limit", () => S.validateInput({ ...good, saprouttab: "x".repeat(200_001) }));
throws("a line over 2000 characters", () => S.validateInput({ ...good, saprouttab: "P " + "a".repeat(2100) }));
throws("too many lines", () => S.validateInput({ ...good, saprouttab: Array.from({ length: 5001 }, () => "# c").join("\n") }));
ok("control characters are stripped from the text", S.validateInput({ ...good, saprouttab: "P * *\u0000 *\u0007" }).saprouttab === "P * * *");
ok("CRLF line endings are handled", ids(A({ saprouttab: "P * * *\r\nKP \"p:CN=r\" * sapdp00\r\n" })).has("SAPROUTER-002"));
ok("a huge but valid file is analysed quickly", (() => { const t = Date.now(); A({ saprouttab: Array.from({ length: 5000 }, (_, i) => `P 10.0.${i % 255}.1 host${i} 3200`).join("\n") }); return Date.now() - t < 500; })());

// ---- knowledge search ----
const r1 = await S.retrieve("SNC gateway parameters snc/enable", 3);
ok("knowledge search returns ranked notes from the bundled files", r1.length > 0 && r1[0].source.endsWith(".md") && r1[0].score >= r1[r1.length - 1].score);
ok("an empty or symbol-only query returns nothing", (await S.retrieve("   ")).length === 0 && (await S.retrieve("!!! ???")).length === 0);
ok("top_k is bounded", (await S.retrieve("sap gateway snc route", 999)).length <= 10);
ok("a very long query is truncated, not rejected", Array.isArray(await S.retrieve("snc ".repeat(5000))));
const ctx = await S.buildContext(demo);
ok("context is de-duplicated and capped at 8", ctx.length > 0 && ctx.length <= 8 && new Set(ctx.map((c) => c.source + c.text)).size === ctx.length);

// ---- explanation: a fake local model ----
let mode = "ok", lastBody = null, calls = 0;
const server = http.createServer((req, res) => {
  let b = ""; req.on("data", (c) => (b += c));
  req.on("end", () => {
    calls++; lastBody = b ? JSON.parse(b) : null;
    const send = (code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
    if (mode === "500") return send(500, { error: "SECRET detail" });
    if (mode === "slow") return setTimeout(() => send(200, { message: { content: "late" } }), 1500);
    if (mode === "bad") return send(200, { message: { content: "Run msfconsole and use meterpreter to exploit this." } });
    if (mode === "empty") return send(200, { message: { content: "" } });
    send(200, { message: { content: "Summary: broad rules found.\u0000 Top risks: ordering. Remediation: narrow scope." } });
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const env = { OLLAMA_BASE_URL: `http://127.0.0.1:${server.address().port}`, CYBERREASONER_MODEL: "m", CYBERREASONER_TIMEOUT_MS: "800" };
let ex = await S.explainFindings("LAB", demo, ctx, env);
ok("explanation returned as plain text, control characters removed", ex.text && ex.text.startsWith("Summary") && !ex.text.includes("\u0000") && ex.note === null);
ok("scanner evidence is sent as data in the user message, with an untrusted-data warning in the system prompt", /untrusted data/.test(lastBody.messages[0].content) && lastBody.messages[1].content.includes("SAPROUTER-001") && !lastBody.messages[0].content.includes("SAPROUTER-001"));
ok("request is non-streaming with low temperature", lastBody.stream === false && lastBody.options.temperature === 0.1);
mode = "500"; ex = await S.explainFindings("LAB", demo, ctx, env);
ok("model error: no text, a generic note, upstream text not leaked", ex.text === null && !/SECRET/.test(ex.note));
mode = "bad"; ex = await S.explainFindings("LAB", demo, ctx, env);
ok("offensive model output is withheld", ex.text === null && /withheld/.test(ex.note));
mode = "empty"; ex = await S.explainFindings("LAB", demo, ctx, env);
ok("empty model output handled", ex.text === null && ex.note);
mode = "slow"; ex = await S.explainFindings("LAB", demo, ctx, env);
ok("a slow model times out cleanly", ex.text === null && /in time/.test(ex.note));
ex = await S.explainFindings("LAB", demo, ctx, { ...env, OLLAMA_BASE_URL: "http://127.0.0.1:1" });
ok("model down: note, no exception", ex.text === null && /unavailable/.test(ex.note));
const before = calls;
ex = await S.explainFindings("LAB", demo, ctx, { ...env, OLLAMA_BASE_URL: "http://203.0.113.9:11434" });
ok("a non-local model endpoint is refused before any request", ex.text === null && /away from this machine/.test(ex.note) && calls === before);
ex = await S.explainFindings("LAB", [], ctx, env);
ok("no findings: nothing to explain, no model call", ex.text === null && ex.note === null && calls === before);
mode = "ok";
mode = "slow";
const first = S.explainFindings("LAB", demo, ctx, { ...env, CYBERREASONER_TIMEOUT_MS: "3000" });
const second = await S.explainFindings("LAB", demo, ctx, env);
ok("a second concurrent explanation is skipped with a note, not queued", second.text === null && /still running/.test(second.note));
await first;
mode = "ok";
ok("the lock is released afterwards", (await S.explainFindings("LAB", demo, ctx, env)).text !== null);
server.close();

// ---- storage ----
const a1 = await S.assess(S.validateInput({ assetId: "A1", saprouttab: "P * * *" }), { explain: false, createdBy: "tester" });
ok("assessment stored with an id, summary, findings and limitations", /^sap_/.test(a1.id) && a1.findings.length === 1 && a1.limitations.length >= 4 && a1.llmExplanation === null);
ok("the raw pasted configuration is not stored (only evidence lines and line counts)", !("saprouttab" in a1) && a1.inputs.saprouttabLines === 1);
const clean = await S.assess(S.validateInput({ assetId: "A2", saprouttab: "P 10.1.1.1 host 3200" }), { explain: false, createdBy: "tester" });
ok("no finding: honest summary, not 'secure'", clean.findings.length === 0 && /not proof/.test(clean.summary));
const stored = await S.readAssessments();
ok("newest first", stored[0].id === clean.id && stored[1].id === a1.id);
await Promise.all(Array.from({ length: 30 }, (_, i) => S.assess(S.validateInput({ assetId: "P" + i, saprouttab: "P * * *" }), { explain: false, createdBy: "t" })));
ok("30 parallel assessments are all kept (no lost updates)", (await S.readAssessments()).length === 32);
for (let i = 0; i < 80; i++) await S.assess(S.validateInput({ assetId: "L" + i, saprouttab: "P * * *" }), { explain: false, createdBy: "t" });
ok("history is capped at 100", (await S.readAssessments()).length === 100);

console.log(`${pass} passed, ${fail} failed`);
process.chdir(tmpdir());
process.exit(fail ? 1 : 0);
