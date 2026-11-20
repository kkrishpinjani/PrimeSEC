/**
 * Demo threat-intelligence dataset served through a fake OpenCTI GraphQL API: indicators, reports, threat actors, malware,
 * vulnerabilities and observables, with TLP markings (some AMBER/RED, so the app's marking policy has something to hide).
 * Actor and malware names are public; descriptions are short, generic and not authoritative. IOCs are documentation-range
 * addresses, reserved-TLD domains and random hashes. The campaign IOCs also appear in the Wazuh alerts so investigations match.
 */
const { makeRandom, MIN, DAY, iso } = require("./common");
const { IOC, SOURCES } = require("./iocs");
const { GROUP_ROWS } = require("./wazuh-ref");
const { VULN_CAT } = require("./wazuh-alerts");

const rnd = makeRandom(9001);
const NOW = Date.now();

function uuid(key) {
  const r = makeRandom([...key].reduce((h, c) => (Math.imul(h, 31) + c.charCodeAt(0)) | 0, 7));
  const h = r.hex(32);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
const marking = () => rnd.weighted([["TLP:CLEAR", 46], ["TLP:GREEN", 40], ["TLP:AMBER", 10], ["TLP:RED", 4]]);
const SAFE_MARKINGS = [["TLP:CLEAR", 55], ["TLP:GREEN", 45]];
const label = (...v) => v.map((value) => ({ value }));
const at = (daysAgo, jitterH = 0) => iso(NOW - daysAgo * DAY - rnd.int(0, jitterH * 60) * MIN);

/* --------------------------------------------- malware --------------------------------------------- */
const MALWARE_ROWS = [
  ["Cobalt Strike", ["implant", "remote-access-trojan"], true, "Commercial adversary-simulation framework widely abused by criminal and state-aligned operators; beacons over HTTPS, DNS or SMB."],
  ["Emotet", ["bot", "trojan"], true, "Modular loader spread by malicious spam; historically delivered banking trojans and ransomware."],
  ["QakBot", ["bot", "trojan"], true, "Banking trojan turned initial-access broker; spread via phishing with HTML smuggling and OneNote lures."],
  ["IcedID", ["trojan", "bot"], true, "Modular banking trojan and loader used to deploy post-exploitation tools."],
  ["TrickBot", ["trojan", "bot"], true, "Modular crimeware platform used for credential theft and as a precursor to ransomware."],
  ["BazarLoader", ["loader"], true, "Stealthy loader associated with ransomware precursor operations."],
  ["LockBit 3.0", ["ransomware"], true, "Ransomware-as-a-service family with a double-extortion model and a self-spreading capability."],
  ["BlackCat (ALPHV)", ["ransomware"], true, "Rust-based ransomware-as-a-service that supports Windows, Linux and ESXi targets."],
  ["Conti", ["ransomware"], true, "Ransomware operation that merged into several successor groups after 2022."],
  ["Ryuk", ["ransomware"], true, "Targeted ransomware typically deployed after TrickBot and BazarLoader footholds."],
  ["Clop", ["ransomware"], true, "Ransomware family also used for mass data theft via file-transfer appliance vulnerabilities."],
  ["Akira", ["ransomware"], true, "Ransomware family observed targeting VPN appliances without multi-factor authentication."],
  ["Royal", ["ransomware"], true, "Ransomware family that evolved into BlackSuit; uses partial encryption for speed."],
  ["Play", ["ransomware"], true, "Ransomware family known for intermittent encryption and double extortion."],
  ["Mimikatz", ["credential-stealer", "tool"], true, "Open-source tool that extracts plaintext passwords, hashes and Kerberos tickets from Windows memory."],
  ["Raccoon Stealer", ["spyware"], true, "Information stealer sold as malware-as-a-service."],
  ["RedLine Stealer", ["spyware"], true, "Information stealer that harvests browser data, crypto wallets and VPN credentials."],
  ["Agent Tesla", ["spyware", "remote-access-trojan"], true, ".NET keylogger and remote access tool sold on criminal forums."],
  ["AsyncRAT", ["remote-access-trojan"], true, "Open-source remote access tool used in many commodity campaigns."],
  ["Remcos", ["remote-access-trojan"], true, "Commercial remote administration tool abused by many threat actors."],
  ["NjRAT", ["remote-access-trojan"], true, "Long-lived remote access trojan popular in the Middle East and North Africa."],
  ["Sliver", ["implant"], true, "Open-source command-and-control framework increasingly used in place of Cobalt Strike."],
  ["Brute Ratel C4", ["implant"], true, "Commercial red-team tool designed to evade EDR; cracked copies have been abused."],
  ["Havoc", ["implant"], true, "Open-source post-exploitation framework with sleep obfuscation."],
  ["PlugX", ["remote-access-trojan"], true, "Modular RAT used by several China-nexus groups for years."],
  ["ShadowPad", ["backdoor"], true, "Modular backdoor and successor to PlugX, shared among multiple espionage actors."],
  ["Industroyer2", ["wiper"], false, "Malware targeting industrial control systems, observed in an attempted attack on an energy provider."],
  ["HermeticWiper", ["wiper"], false, "Destructive malware that corrupts the partition table and master boot record."],
  ["DarkGate", ["loader"], true, "Loader with remote access, credential theft and cryptomining modules."],
  ["Pikabot", ["loader"], true, "Loader seen replacing QakBot in phishing campaigns."],
  ["BumbleBee", ["loader"], true, "Loader used by ransomware affiliates to deliver Cobalt Strike."],
  ["SystemBC", ["proxy", "bot"], true, "SOCKS5 proxy and backdoor commonly deployed during ransomware intrusions."],
  ["Meterpreter", ["implant"], true, "Payload of the Metasploit Framework providing an interactive session on the target."],
  ["Mirai", ["bot"], true, "Botnet that infects IoT devices and launches large DDoS attacks."],
  ["XorDDoS", ["bot"], true, "Linux trojan that conscripts devices into a DDoS botnet via SSH brute force."],
  ["China Chopper", ["webshell"], true, "Tiny web shell that has been used for over a decade to maintain access to web servers."]
];
const malwares = MALWARE_ROWS.map(([name, malware_types, is_family, description], i) => {
  const first = rnd.int(200, 3500);
  return { id: uuid("malware:" + name), entity_type: "Malware", name, description, is_family, malware_types, first_seen: at(first), last_seen: at(rnd.int(1, 120)), created: at(first), modified: at(rnd.int(1, 60)), created_at: at(first), objectLabel: label(...malware_types), objectMarking: [{ definition: rnd.weighted(SAFE_MARKINGS) }] };
});

/* ------------------------------------------- threat actors ------------------------------------------- */
const CRIME = [
  ["LockBit", ["LockBit Gang", "Bitwise Spider"], "Ransomware-as-a-service operation that recruited affiliates and used a data-leak site for double extortion."],
  ["ALPHV / BlackCat", ["ALPHV", "Noberus"], "Ransomware-as-a-service group that targeted healthcare and critical infrastructure before shutting down in 2024."],
  ["Cl0p", ["Clop", "Lace Tempest"], "Extortion group known for mass exploitation of file-transfer products and data theft."],
  ["Akira", ["Storm-1567"], "Ransomware group that frequently gains access through VPN accounts lacking multi-factor authentication."],
  ["Black Basta", ["Storm-0506"], "Ransomware group with ties to the former Conti operation; known for Qakbot-led intrusions."],
  ["Play", ["Playcrypt"], "Ransomware group using intermittent encryption; targets many sectors across the Americas and Europe."],
  ["Medusa", ["Spearwing"], "Ransomware-as-a-service operation that runs a public leak blog."],
  ["Rhysida", ["Vice Society successor"], "Ransomware group known for attacks on education and public sector bodies."]
];
const threatActors = [...GROUP_ROWS.map(([ext, name, aliases, description]) => ({ name, aliases, description, ext })), ...CRIME.map(([name, aliases, description]) => ({ name, aliases, description }))]
  .map((g, i) => {
    const first = rnd.int(400, 5000);
    return { id: uuid("actor:" + g.name), entity_type: "Threat-Actor-Group", name: g.name, description: g.description, aliases: g.aliases, first_seen: at(first), last_seen: at(rnd.int(0, 45)), created: at(first), modified: at(rnd.int(0, 30)), created_at: at(first), objectLabel: label(g.ext ? "intrusion-set" : "ransomware"), objectMarking: [{ definition: rnd.weighted(SAFE_MARKINGS) }], _i: i };
  });

/* ------------------------------------------- vulnerabilities ------------------------------------------- */
const EXTRA_VULNS = [
  ["CVE-2023-34362", "Progress MOVEit Transfer SQL injection leading to remote code execution and mass data theft.", 9.8, "CWE-89", true],
  ["CVE-2024-3400", "Palo Alto Networks PAN-OS GlobalProtect command injection allowing unauthenticated remote code execution.", 10.0, "CWE-77", true],
  ["CVE-2023-22515", "Atlassian Confluence Data Center broken access control allowing creation of administrator accounts.", 10.0, "CWE-20", true],
  ["CVE-2023-20198", "Cisco IOS XE web UI privilege escalation allowing creation of a privileged account.", 10.0, "CWE-420", true],
  ["CVE-2024-1709", "ConnectWise ScreenConnect authentication bypass using an alternate path.", 10.0, "CWE-288", true],
  ["CVE-2023-27350", "PaperCut MF/NG improper access control allowing remote code execution.", 9.8, "CWE-284", true],
  ["CVE-2024-21887", "Ivanti Connect Secure command injection in web components.", 9.1, "CWE-77", true],
  ["CVE-2023-4966", "Citrix NetScaler ADC and Gateway sensitive information disclosure (Citrix Bleed).", 9.4, "CWE-119", true],
  ["CVE-2022-41040", "Microsoft Exchange Server server-side request forgery (ProxyNotShell).", 8.8, "CWE-918", true],
  ["CVE-2021-26855", "Microsoft Exchange Server server-side request forgery (ProxyLogon).", 9.8, "CWE-918", true],
  ["CVE-2019-0708", "Microsoft Remote Desktop Services remote code execution (BlueKeep).", 9.8, "CWE-416", true],
  ["CVE-2014-0160", "OpenSSL TLS heartbeat extension buffer over-read (Heartbleed).", 7.5, "CWE-125", true],
  ["CVE-2017-5638", "Apache Struts 2 Jakarta Multipart parser remote code execution.", 10.0, "CWE-20", true],
  ["CVE-2024-24919", "Check Point Security Gateways information disclosure allowing credential access.", 8.6, "CWE-200", true],
  ["CVE-2023-3519", "Citrix NetScaler ADC and Gateway unauthenticated remote code execution.", 9.8, "CWE-94", true],
  ["CVE-2022-1388", "F5 BIG-IP iControl REST authentication bypass.", 9.8, "CWE-306", true],
  ["CVE-2021-21972", "VMware vCenter Server remote code execution in the vSphere Client.", 9.8, "CWE-22", true],
  ["CVE-2023-46747", "F5 BIG-IP Configuration utility authentication bypass.", 9.8, "CWE-288", true],
  ["CVE-2024-27198", "JetBrains TeamCity authentication bypass allowing administrative control.", 9.8, "CWE-288", true],
  ["CVE-2023-42793", "JetBrains TeamCity authentication bypass leading to remote code execution.", 9.8, "CWE-288", true]
];
const KEV = new Set(["CVE-2021-44228", "CVE-2021-41773", "CVE-2022-22965", "CVE-2023-46604", "CVE-2020-1472", "CVE-2021-34527", "CVE-2017-0144", "CVE-2023-23397", "CVE-2023-4863", "CVE-2024-21412", "CVE-2022-30190", "CVE-2021-3156", "CVE-2022-0847", "CVE-2024-3094", "CVE-2024-4671", "CVE-2023-41993", "CVE-2023-36884", "CVE-2022-42889", "CVE-2024-1086", "CVE-2023-0386", "CVE-2024-21626"]);
const CWE = ["CWE-787", "CWE-416", "CWE-78", "CWE-22", "CWE-89", "CWE-20", "CWE-269", "CWE-287", "CWE-119", "CWE-190", "CWE-362"];
const seenCve = new Set();
const vulnerabilities = [
  ...VULN_CAT.filter(([cve]) => !seenCve.has(cve) && seenCve.add(cve)).map(([cve, pkg, , base]) => [cve, `A vulnerability in ${pkg} (${cve}) could allow an attacker to compromise affected systems. Patch or mitigate as described by the vendor.`, base, rnd.pick(CWE), KEV.has(cve)]),
  ...EXTRA_VULNS
].map(([cve, description, base, cwe, kev]) => {
  const pub = rnd.int(20, 2800);
  return { id: uuid("vuln:" + cve), entity_type: "Vulnerability", name: cve, description, x_opencti_cvss_base_score: base, x_opencti_cwe: cwe, x_opencti_cisa_kev: kev, created: at(pub), modified: at(rnd.int(0, 30)), created_at: at(rnd.int(0, 400)), objectLabel: label(kev ? "cisa-kev" : "cve"), objectMarking: [{ definition: "TLP:CLEAR" }] };
});

/* ------------------------------------------------ indicators ------------------------------------------------ */
const ips = () => `${rnd.pick(["203.0.113", "198.51.100", "192.0.2"])}.${rnd.int(2, 250)}`;
const WORDS_A = ["login-secure", "account-verify", "update-center", "cdn-static", "mail-support", "docs-share", "invoice-portal", "payroll-update", "vpn-access", "helpdesk-portal", "sso-auth", "secure-files"];
const WORDS_B = ["microsoft", "office365", "okta", "dropbox", "docusign", "adobe", "zoom", "webex", "sharepoint", "onedrive"];
const YARA = ["MAL_Win_CobaltStrike_Beacon_Strings", "MAL_Win_Mimikatz_Memory", "RANSOM_Win_LockBit_Config", "WEBSHELL_PHP_Generic_Eval", "MAL_Linux_XorDDoS", "HKTL_Sliver_Implant", "MAL_Win_QakBot_Loader", "LOADER_DarkGate_Autoit"];
const SIGMA = ["Suspicious LSASS Access via comsvcs.dll", "Shadow Copy Deletion Using vssadmin", "Encoded PowerShell from Office Application", "Web Shell Creation in Web Directory", "Kerberoasting via RC4 Service Ticket"];

const ind = (name, pattern, pattern_type, score, labels, description, daysAgo, minutesAgo, types = ["malicious-activity"]) => {
  const created = minutesAgo != null ? iso(NOW - minutesAgo * MIN) : at(daysAgo);
  const m = rnd.weighted(SAFE_MARKINGS);
  return { id: uuid("ind:" + name), entity_type: "Indicator", name, description, pattern, pattern_type, valid_from: created, valid_until: iso(Date.parse(created) + rnd.int(30, 365) * DAY), created, modified: created, created_at: created, x_opencti_score: score, indicator_types: types, objectLabel: label(...labels), objectMarking: [{ definition: m }] };
};
const stixIp = (v) => `[ipv4-addr:value = '${v}']`;
const stixDom = (v) => `[domain-name:value = '${v}']`;
const stixUrl = (v) => `[url:value = '${v}']`;
const stixHash = (v) => `[file:hashes.'SHA-256' = '${v}']`;

const indicators = [];
// campaign IOCs: the ones that appear in the Wazuh alerts, created recently
indicators.push(
  ind(IOC.c2Ip, stixIp(IOC.c2Ip), "stix", 92, ["c2", "cobalt-strike", "apt29"], "Cobalt Strike team server observed serving payloads and receiving HTTPS beacons.", null, 150),
  ind(IOC.c2Domain, stixDom(IOC.c2Domain), "stix", 85, ["c2", "cobalt-strike"], "Domain used as a redirector for the Cobalt Strike infrastructure.", null, 190),
  ind(IOC.payloadUrl, stixUrl(IOC.payloadUrl), "stix", 88, ["payload-delivery", "cobalt-strike"], "Staged payload download linked to Office-macro phishing.", null, 205),
  ind(IOC.phishDomain, stixDom(IOC.phishDomain), "stix", 89, ["phishing", "credential-harvesting"], "Lookalike Microsoft 365 sign-in page used to harvest credentials.", null, 240),
  ind(IOC.phishUrl, stixUrl(IOC.phishUrl), "stix", 86, ["phishing", "credential-harvesting"], "Credential-harvesting URL on the lookalike sign-in domain.", null, 250),
  ind(IOC.dropperSha256, stixHash(IOC.dropperSha256), "stix", 95, ["maldoc", "dropper"], "Macro-enabled spreadsheet (Invoice_Q4.xlsm) that launches an encoded PowerShell downloader.", null, 280),
  ind(IOC.mimikatzSha256, stixHash(IOC.mimikatzSha256), "stix", 93, ["credential-theft", "mimikatz"], "Renamed Mimikatz binary dropped to C:\\Users\\Public.", null, 310),
  ind(IOC.ransomSha256, stixHash(IOC.ransomSha256), "stix", 97, ["ransomware", "lockbit"], "Ransomware payload that renames files to the .lckd extension and drops README_RESTORE.txt.", null, 330),
  ind(IOC.webshellSha256, stixHash(IOC.webshellSha256), "stix", 90, ["webshell"], "PHP web shell with an eval-based command interface.", null, 360),
  ind(IOC.c2Ip2, stixIp(IOC.c2Ip2), "stix", 88, ["c2", "webshell"], "Command-and-control address contacted by web shells on compromised web servers.", null, 400),
  ind(IOC.exfilIp, stixIp(IOC.exfilIp), "stix", 81, ["exfiltration"], "Staging server that receives bulk data over HTTPS from compromised databases.", null, 450),
  ind(IOC.sprayIp, stixIp(IOC.sprayIp), "stix", 74, ["password-spray"], "Address responsible for password-spraying against VPN and ADFS endpoints.", null, 520),
  ind(IOC.webAttackIp, stixIp(IOC.webAttackIp), "stix", 79, ["scanner", "sqli"], "Automated exploitation tooling (sqlmap) against public web applications.", null, 600),
  ind(IOC.log4jIp, stixIp(IOC.log4jIp), "stix", 70, ["scanner", "log4shell"], "Mass-scanning source sending JNDI lookup strings in HTTP headers.", null, 700),
  ind(IOC.dgaDomain, stixDom(IOC.dgaDomain), "stix", 73, ["dga", "c2"], "Algorithmically generated domain from a loader family.", null, 820),
  ind("accounts@invoice-portal.example", "[email-addr:value = 'accounts@invoice-portal.example']", "stix", 68, ["phishing"], "Sender address of an invoice-themed phishing wave.", null, 880)
);
// the attacker sources: most of them are known to threat intel (the rest are not, which is realistic)
for (const s of SOURCES) {
  if (indicators.some((x) => x.name === s.ip) || rnd.chance(0.4)) continue;
  const lab = { c2: ["c2"], ssh: ["bruteforce", "ssh"], web: ["scanner", "web-attack"], scan: ["scanner"], phish: ["phishing"], spray: ["password-spray"] }[s.profile];
  indicators.push(ind(s.ip, stixIp(s.ip), "stix", rnd.int(35, 82), lab, `Address observed in ${lab[0]} activity.`, rnd.int(1, 40)));
}
for (let i = 0; i < 110; i++) { const v = ips(); indicators.push(ind(v, stixIp(v), "stix", rnd.int(25, 96), [rnd.pick(["c2", "scanner", "bruteforce", "botnet", "tor-exit"])], "Address reported by community and commercial feeds.", rnd.int(1, 59))); }
for (let i = 0; i < 80; i++) { const v = `${rnd.pick(WORDS_A)}-${rnd.pick(WORDS_B)}.example`; if (indicators.some((x) => x.name === v)) continue; indicators.push(ind(v, stixDom(v), "stix", rnd.int(40, 94), [rnd.pick(["phishing", "c2", "malware-delivery"])], "Newly registered lookalike domain.", rnd.int(1, 59))); }
for (let i = 0; i < 46; i++) { const v = `http://${ips()}/${rnd.pick(["update", "invoice", "setup", "scan", "doc", "files"])}/${rnd.hex(6)}.${rnd.pick(["exe", "bin", "ps1", "hta", "dll"])}`; indicators.push(ind(v, stixUrl(v), "stix", rnd.int(50, 96), ["payload-delivery"], "URL serving a malicious payload.", rnd.int(1, 59))); }
for (let i = 0; i < 48; i++) { const v = rnd.hex(64); indicators.push(ind(v, stixHash(v), "stix", rnd.int(55, 98), [rnd.pick(["ransomware", "loader", "stealer", "rat", "maldoc"])], "File hash from a malware analysis sandbox.", rnd.int(1, 59))); }
for (const y of YARA) indicators.push(ind(y, `rule ${y} { strings: $a = { 4D 5A 90 00 } condition: $a at 0 }`, "yara", rnd.int(60, 90), ["detection-rule"], "YARA rule for hunting on endpoints and in sandboxes.", rnd.int(10, 200), null, ["anomalous-activity"]));
for (const s of SIGMA) indicators.push(ind(s, `title: ${s}\nlogsource: { category: process_creation, product: windows }\ndetection: { selection: { Image|endswith: '.exe' }, condition: selection }`, "sigma", rnd.int(55, 85), ["detection-rule"], "Sigma rule for log-based detection.", rnd.int(10, 200), null, ["anomalous-activity"]));
// the tail keeps AMBER/RED objects in the mix
for (const x of indicators.slice(24)) if (rnd.chance(0.12)) x.objectMarking = [{ definition: rnd.pick(["TLP:AMBER", "TLP:AMBER", "TLP:RED"]) }];

/* --------------------------------------------------- reports --------------------------------------------------- */
const SECTORS = ["financial services", "healthcare", "energy and utilities", "manufacturing", "government", "telecommunications", "retail", "higher education", "logistics", "technology"];
const REPORT_TEMPLATES = [
  (a, m, s) => `${a} intrusion set targets ${s} with ${m}`, (a, m, s) => `${m} campaign against ${s}: tactics and indicators`, (a, m, s) => `Threat landscape: ${s} (${a} activity)`,
  (a, m, s) => `${a} adds ${m} to its toolkit`, (a, m, s) => `Initial-access trends in ${s}: ${m} and valid accounts`
];
const reports = Array.from({ length: 56 }, (_, i) => {
  const a = threatActors[(i * 7) % threatActors.length].name, m = malwares[(i * 5) % malwares.length].name, s = SECTORS[i % SECTORS.length];
  const name = REPORT_TEMPLATES[i % REPORT_TEMPLATES.length](a, m, s);
  const published = i < 3 ? iso(NOW - (6 + i * 5) * 3600_000) : at(i * 3 + rnd.int(0, 2));
  return { id: uuid("report:" + i + name), entity_type: "Report", name, description: `Analyst report covering ${a} and ${m} activity affecting ${s}. Includes observed tradecraft, mapped ATT&CK techniques and indicators of compromise.`, published, created: published, modified: published, created_at: published, report_types: [rnd.pick(["threat-report", "threat-report", "campaign", "intrusion-set"])], objectLabel: label(rnd.pick(["apt", "crimeware", "ransomware", "phishing"]), s.split(" ")[0]), objectMarking: [{ definition: marking() }] };
});

/* -------------------------------------------------- observables -------------------------------------------------- */
const observables = [];
const obs = (entity_type, value) => observables.push({ id: uuid("obs:" + entity_type + value), entity_type, observable_value: value, created_at: at(rnd.int(0, 50), 20), updated_at: at(rnd.int(0, 5), 20), objectMarking: [{ definition: rnd.weighted([["TLP:CLEAR", 55], ["TLP:GREEN", 35], ["TLP:AMBER", 10]]) }] });
for (const s of SOURCES) obs("IPv4-Addr", s.ip);
for (const v of [IOC.c2Domain, IOC.phishDomain, IOC.dgaDomain]) obs("Domain-Name", v);
for (const v of [IOC.payloadUrl, IOC.phishUrl]) obs("Url", v);
for (const v of [IOC.dropperSha256, IOC.ransomSha256, IOC.webshellSha256, IOC.mimikatzSha256]) obs("StixFile", v);
obs("Email-Addr", "accounts@invoice-portal.example");
for (const x of indicators.slice(24, 200)) {
  const m = /'([^']+)'/.exec(x.pattern);
  if (!m) continue;
  const t = x.pattern.startsWith("[ipv4") ? "IPv4-Addr" : x.pattern.startsWith("[domain") ? "Domain-Name" : x.pattern.startsWith("[url") ? "Url" : x.pattern.startsWith("[file") ? "StixFile" : null;
  if (t && !observables.some((o) => o.observable_value === m[1])) obs(t, m[1]);
}

const byNewest = (a, b, k = "created_at") => (a[k] < b[k] ? 1 : -1);
const COLLECTIONS = {
  indicators: indicators.sort(byNewest),
  reports: reports.sort((a, b) => byNewest(a, b, "published")),
  threatActors: threatActors.sort(byNewest),
  malwares: malwares.sort(byNewest),
  vulnerabilities: vulnerabilities.sort(byNewest),
  stixCyberObservables: observables.sort(byNewest)
};
const DETAIL = { indicator: "indicators", report: "reports", threatActor: "threatActors", vulnerability: "vulnerabilities", malware: "malwares" };

module.exports = { COLLECTIONS, DETAIL };
