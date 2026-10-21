// Scope-rule tests for the VAPT safety model. Run: npm run test:vapt (Node 22.6+; TypeScript is type-stripped).
import { parseCidr, targetAllowed } from "../lib/vapt.ts";

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : (fail++, console.log("FAIL:", name)); };
const throws = (name, fn, re) => { try { fn(); fail++; console.log("FAIL (no throw):", name); } catch (e) { re.test(e.message) ? pass++ : (fail++, console.log("FAIL (wrong error):", name, "->", e.message)); } };

// --- parsing
ok("plain ip", parseCidr("10.0.0.5").network === "10.0.0.5");
ok("cidr", parseCidr("10.0.0.0/24").network === "10.0.0.0/24");
throws("host bits set is rejected, not widened", () => parseCidr("10.0.0.5/24"), /host bits/);
throws("/16 too wide", () => parseCidr("10.0.0.0/16"), /\/24 or narrower/);
throws("/8 too wide", () => parseCidr("10.0.0.0/8"), /\/24 or narrower/);
throws("octet > 255", () => parseCidr("10.0.0.256"), /Invalid/);
throws("garbage", () => parseCidr("example.com"), /Invalid/);
throws("empty", () => parseCidr(""), /Invalid/);
throws("ipv6", () => parseCidr("::1"), /Invalid/);
throws("injection-ish", () => parseCidr("10.0.0.1; rm -rf /"), /Invalid/);

// --- reserved ranges can never be scanned
throws("loopback", () => parseCidr("127.0.0.1"), /never be scanned/);
throws("loopback /24", () => parseCidr("127.0.0.0/24"), /never be scanned/);
throws("cloud metadata", () => parseCidr("169.254.169.254"), /never be scanned/);
throws("this-network", () => parseCidr("0.0.0.5"), /never be scanned/);
throws("multicast", () => parseCidr("224.0.0.1"), /never be scanned/);
throws("broadcast", () => parseCidr("255.255.255.255"), /never be scanned/);
throws("reserved 240", () => parseCidr("240.1.2.3"), /never be scanned/);

// --- public vs private classification
ok("10/8 private", parseCidr("10.20.30.0/24").public === false);
ok("172.16/12 private", parseCidr("172.31.1.1").public === false);
ok("172.32 is public", parseCidr("172.32.0.1").public === true);
ok("192.168 private", parseCidr("192.168.1.0/24").public === false);
ok("CGNAT private", parseCidr("100.64.1.1").public === false);
ok("8.8.8.8 public", parseCidr("8.8.8.8").public === true);
ok("203.0.113.0/24 public", parseCidr("203.0.113.0/24").public === true);

// --- scope containment
const future = new Date(Date.now() + 86400000).toISOString();
const past = new Date(Date.now() - 1000).toISOString();
const scope = (over = {}) => ({ id: "s1", name: "t", authorizationReference: "REF-12345", targets: ["10.0.0.0/24"], expiresAt: future, status: "Approved", createdAt: "", createdBy: "", includesPublicRanges: false, ...over });
ok("inside /24", !!targetAllowed("10.0.0.7", [scope()]));
ok("whole /24 allowed", !!targetAllowed("10.0.0.0/24", [scope()]));
ok("narrower /28 allowed", !!targetAllowed("10.0.0.16/28", [scope()]));
ok("neighbour /24 denied", !targetAllowed("10.0.1.5", [scope()]));
ok("last+1 denied", !targetAllowed("10.0.1.0", [scope()]));
ok("a /32 scope does not cover its /24", !targetAllowed("10.0.0.0/24", [scope({ targets: ["10.0.0.5"] })]));
ok("a /32 scope covers only itself", !!targetAllowed("10.0.0.5", [scope({ targets: ["10.0.0.5"] })]) && !targetAllowed("10.0.0.6", [scope({ targets: ["10.0.0.5"] })]));
ok("expired denied", !targetAllowed("10.0.0.7", [scope({ expiresAt: past })]));
ok("revoked denied", !targetAllowed("10.0.0.7", [scope({ status: "Revoked" })]));
ok("missing expiry denied", !targetAllowed("10.0.0.7", [scope({ expiresAt: "" })]));
ok("garbage expiry denied", !targetAllowed("10.0.0.7", [scope({ expiresAt: "soon" })]));
ok("empty scope list denied", !targetAllowed("10.0.0.7", []));
ok("corrupt stored target never grants", !targetAllowed("10.0.0.7", [scope({ targets: ["10.0.0.0/8"] })]));
ok("garbage target denied", !targetAllowed("not-an-ip", [scope()]));
ok("loopback target denied even if 'in scope'", !targetAllowed("127.0.0.1", [scope({ targets: ["127.0.0.1"] })]));
ok("second scope can grant", !!targetAllowed("10.0.9.9", [scope({ status: "Revoked" }), scope({ id: "s2", targets: ["10.0.9.0/24"] })])?.id === true);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
