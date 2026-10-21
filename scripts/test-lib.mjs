// Tests for the audit tail-reader and the observable extractor.
// Run: npm run test:lib (Node 22.6+; TypeScript is type-stripped).
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const original = process.cwd();
const work = mkdtempSync(path.join(tmpdir(), "primesec-test-"));
process.chdir(work); // lib/audit.ts resolves ./data/audit-events.jsonl from the working directory
mkdirSync("data");
const { readAuditEvents, writeAuditEvent } = await import("../lib/audit.ts");
const { extractObservables, correlate } = await import("../lib/correlation.ts");

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { cond ? pass++ : (fail++, console.log("FAIL:", name, extra)); };
const file = path.join(work, "data", "audit-events.jsonl");
const ev = (i, action = "alert_investigation_created", extra = "") => JSON.stringify({ eventId: `e${i}`, timestamp: `t${i}`, action, actor: { name: null, email: null, roles: [] }, note: extra });

/** Reference implementation: read everything, parse, filter, newest first. */
const naive = (lines, n, actions) => lines.filter((l) => l.trim()).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter((e) => e && (!actions || actions.includes(e.action))).slice(-n).reverse();
const ids = (xs) => xs.map((e) => e.eventId).join(",");

// --- audit: missing file
ok("missing file -> []", (await readAuditEvents(10)).length === 0);

// --- audit: small file, order, limit
let lines = Array.from({ length: 12 }, (_, i) => ev(i));
writeFileSync(file, lines.join("\n") + "\n");
ok("small file newest first", ids(await readAuditEvents(5)) === ids(naive(lines, 5)));
ok("limit larger than file", (await readAuditEvents(100)).length === 12);
ok("no trailing newline", (writeFileSync(file, lines.join("\n")), ids(await readAuditEvents(3)) === ids(naive(lines, 3))));

// --- audit: large file, many chunks, multi-byte characters sitting on chunk boundaries
const wide = "é€😀漢字".repeat(40);
lines = Array.from({ length: 3000 }, (_, i) => ev(i, i % 7 === 0 ? "vapt_scope_approved" : "alert_investigation_created", wide));
writeFileSync(file, lines.join("\n") + "\n");
ok("large file (>64KB, multibyte): newest 25", ids(await readAuditEvents(25)) === ids(naive(lines, 25)));
ok("large file: all of limit 100", ids(await readAuditEvents(100)) === ids(naive(lines, 100)));
ok("large file: filtered by action", ids(await readAuditEvents(10, ["vapt_scope_approved"])) === ids(naive(lines, 10, ["vapt_scope_approved"])));
ok("filtered events are all that action", (await readAuditEvents(10, ["vapt_scope_approved"])).every((e) => e.action === "vapt_scope_approved"));
ok("multibyte text survives intact", (await readAuditEvents(5)).every((e) => e.note === wide));

// --- audit: filter matching only very old events forces a deep read
lines = Array.from({ length: 4000 }, (_, i) => ev(i, i < 3 ? "vapt_scope_revoked" : "alert_investigation_created", wide));
writeFileSync(file, lines.join("\n") + "\n");
ok("deep filter finds events at the very start of the file", ids(await readAuditEvents(10, ["vapt_scope_revoked"])) === "e2,e1,e0");

// --- audit: corrupt lines are skipped, never thrown
lines = [ev(0), "{ not json", ev(1), "", "garbage", ev(2)];
writeFileSync(file, lines.join("\n") + "\n");
ok("corrupt and blank lines skipped", ids(await readAuditEvents(10)) === "e2,e1,e0");

// --- audit: write then read round-trips
rmSync(file);
const w = await writeAuditEvent({ action: "vapt_assessment_denied", actor: { name: "n", email: "e@x", roles: ["SOC_Analyst"] }, target: "10.0.0.5", reason: "r" });
const back = await readAuditEvents(1);
ok("write then read", back.length === 1 && back[0].eventId === w.eventId && back[0].target === "10.0.0.5");
ok("new launch-audit actions are readable by filter", (await readAuditEvents(5, ["vapt_assessment_denied"])).length === 1);

// --- observables: real indicators are found
const obs = (t) => extractObservables(t).map((o) => `${o.type}:${o.value}`);
ok("ipv4", obs("from 203.0.113.45 port 22").includes("ipv4:203.0.113.45"));
ok("domain", obs("GET http://update-check.example/payload.bin").includes("domain:update-check.example"));
ok("uppercase hostname kept (lowercased)", obs("query EXAMPLE.COM from host").includes("domain:example.com"));
ok("sha256", obs("hash 9f2c" + "0".repeat(56) + "e41a seen").some((x) => x.startsWith("sha256:")));
ok("md5", obs("md5=d41d8cd98f00b204e9800998ecf8427e").some((x) => x.startsWith("md5:")));
ok("url host that is an ip", obs("http://203.0.113.45/payload.bin").includes("ipv4:203.0.113.45"));

// --- observables: code identifiers and file names are not domains (reviewer's examples)
for (const junk of ["Microsoft.Windows.Defender", "System.Net.Sockets", "Program.Files", "libssl.so.3", "powershell.exe", "C:\\Windows\\System32\\cmd.exe", "Newtonsoft.Json.dll", "app.config", "Contoso.Corp.Services"]) {
  ok(`not a domain: ${junk}`, !obs(`log line ${junk} loaded`).some((x) => x.startsWith("domain:")), obs(junk).join());
}
ok("junk next to a real domain: only the real one remains", JSON.stringify(obs("System.Net.Sockets reached login-portal.example")) === JSON.stringify(["domain:login-portal.example"]));
ok("junk no longer crowds out the cap", extractObservables(Array.from({ length: 60 }, (_, i) => `Ns${i}.Type.Name`).join(" ") + " evil.example").some((o) => o.value === "evil.example"));

// --- correlation still matches exactly
const indicators = [
  { id: "i1", name: "203.0.113.45 (demo)", pattern: "[ipv4-addr:value = '203.0.113.45']", patternType: "stix", createdAt: null, score: 92 },
  { id: "i2", name: "10.0.0.15", pattern: "[ipv4-addr:value = '10.0.0.15']", patternType: "stix", createdAt: null, score: 10 },
  { id: "i3", name: "other.example", pattern: "[domain-name:value = 'other.example']", patternType: "stix", createdAt: null, score: 50 }
];
const c = correlate("alert from 203.0.113.45 and 10.0.0.1 via System.Net.Sockets", indicators);
ok("exact IP match found", c.matches.some((m) => m.indicatorId === "i1"));
ok("10.0.0.1 does NOT match 10.0.0.15 (no substring matching)", !c.matches.some((m) => m.indicatorId === "i2"));
ok("unrelated indicator not matched", !c.matches.some((m) => m.indicatorId === "i3"));

process.chdir(original); // Windows cannot delete the directory the process is in
rmSync(work, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
