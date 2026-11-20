/**
 * Demo Greenbone data: four weekly scan reports over the fictional fleet, so the findings list has history. Some findings
 * appear in every report, some were fixed after an earlier report ("not in latest scan"), some are new in the latest one.
 * Scan names, NVT names and CVE ids are realistic; the oids are invented. Nothing is scanned.
 */
const { makeRandom, DAY, iso } = require("./common");
const { AGENTS } = require("./fleet");

const rnd = makeRandom(1357);
const HOST_NAMES = ["web-01", "web-02", "web-03", "web-04", "app-01", "app-02", "app-04", "api-gw-01", "db-01", "db-02", "db-03", "db-04", "dc-01", "fs-01", "mail-01", "vpn-gw-01", "jump-01"];
const HOSTS = HOST_NAMES.map((n) => AGENTS.find((a) => a.name === n)).map((a) => ({ name: a.name, ip: a.ip, role: a._role, family: a._family, osKey: a._osKey }));

let oidN = 100000;
const T = (name, port, severity, threat, cves, solution, description, opts = {}) => ({ oid: `1.3.6.1.4.1.25623.1.0.${++oidN}`, name, port, severity, threat, cves, solution, description, ...opts });

const SSH = [
  T("OpenSSH < 9.8 RCE Vulnerability (regreSSHion)", "22/tcp", 8.1, "High", ["CVE-2024-6387"], "Update to OpenSSH 9.8 or later.", "A signal handler race condition in sshd can allow unauthenticated remote code execution on glibc-based Linux systems."),
  T("SSH Weak Encryption Algorithms Supported", "22/tcp", 4.3, "Medium", [], "Disable the weak encryption algorithms (CBC ciphers) in sshd_config.", "The remote SSH server is configured to allow weak encryption algorithms."),
  T("SSH Weak MAC Algorithms Supported", "22/tcp", 2.6, "Low", [], "Disable the weak MAC algorithms (for example hmac-md5, hmac-sha1-96).", "The remote SSH server is configured to allow weak MAC algorithms.")
];
const COMMON = [
  T("TCP Timestamps Information Disclosure", "general/tcp", 2.6, "Low", [], "Disable TCP timestamps, or accept the risk.", "The remote host implements TCP timestamps and therefore allows to compute the uptime."),
  T("ICMP Timestamp Reply Information Disclosure", "general/icmp", 2.1, "Low", ["CVE-1999-0524"], "Filter ICMP timestamp requests and replies at the firewall.", "The remote host responds to an ICMP timestamp request."),
  T("OS Detection Consolidation and Reporting", "general/tcp", 0, "Log", [], "", "Consolidated operating-system detection results for the host."),
  T("Services Detection", "general/tcp", 0, "Log", [], "", "Network services discovered on the host.")
];
const WEB = [
  T("SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection", "443/tcp", 4.3, "Medium", ["CVE-2011-3389", "CVE-2015-0204"], "Disable TLSv1.0 and TLSv1.1 and enable TLSv1.2 or newer.", "The service accepts connections using deprecated TLS versions.", { quick: true }),
  T("SSL/TLS: Report Weak Cipher Suites", "443/tcp", 5.0, "Medium", ["CVE-2013-2566", "CVE-2015-2808"], "Configure the server to disable weak cipher suites (RC4, 3DES).", "Weak cipher suites are accepted by the service."),
  T("Missing HTTP Security Headers", "443/tcp", 3.7, "Low", [], "Add Strict-Transport-Security, Content-Security-Policy and X-Frame-Options headers.", "The web server does not set recommended security response headers."),
  T("HTTP TRACE Method Enabled", "80/tcp", 4.3, "Medium", ["CVE-2003-1567"], "Disable the TRACE method.", "The web server allows the HTTP TRACE method, which can aid cross-site tracing attacks."),
  T("phpMyAdmin Administration Interface Exposed", "80/tcp", 5.0, "Medium", [], "Restrict /phpmyadmin to administrative networks or remove it.", "A database administration interface is reachable from the scanned network.")
];
const SPECIFIC = {
  "web-01": [T("nginx HTTP/2 Rapid Reset Denial of Service (CVE-2023-44487)", "443/tcp", 7.5, "High", ["CVE-2023-44487"], "Update nginx to 1.25.3 or later, or limit concurrent HTTP/2 streams.", "The nginx version in use is affected by the HTTP/2 Rapid Reset attack.")],
  "web-02": [T("Apache HTTP Server 2.4.49 Path Traversal and RCE", "80/tcp", 9.8, "High", ["CVE-2021-41773", "CVE-2021-42013"], "Update to Apache HTTP Server 2.4.51 or later.", "A path normalization flaw allows reading files outside the document root and, with CGI enabled, remote code execution.", { quick: true, exploit: "Exploited in the wild", life: [0, 3] })],
  "web-03": [
    T("PHP-CGI Argument Injection Remote Code Execution", "80/tcp", 9.8, "High", ["CVE-2024-4577"], "Update PHP to 8.1.29 or later.", "On Windows-style best-fit conversions PHP-CGI argument injection allows remote code execution.", { exploit: "Public exploit", life: [2, 3] }),
    T("WordPress < 6.4.3 Multiple Vulnerabilities", "80/tcp", 6.1, "Medium", ["CVE-2024-31210"], "Update WordPress to the latest release.", "The installed WordPress version is affected by multiple vulnerabilities."),
    T("Web Shell Detected in Upload Directory", "80/tcp", 9.0, "High", [], "Remove the file, rotate credentials and investigate the host as compromised.", "A script resembling a web shell is reachable at /uploads/shell.php.", { exploit: "Exploited in the wild", life: [3, 3] })
  ],
  "web-04": [T("SSL/TLS: Certificate Expired", "443/tcp", 5.0, "Medium", [], "Replace the expired certificate.", "The TLS certificate presented by the service has expired.", { quick: true })],
  "app-01": [T("Jenkins < 2.442 Arbitrary File Read (CVE-2024-23897)", "8080/tcp", 9.8, "High", ["CVE-2024-23897"], "Update Jenkins to 2.442 or later.", "The Jenkins CLI parser allows reading arbitrary files, which can lead to remote code execution.", { exploit: "Public exploit" })],
  "app-02": [
    T("Spring Framework RCE via Data Binding (Spring4Shell)", "8080/tcp", 9.8, "High", ["CVE-2022-22965"], "Update Spring Framework to 5.3.18 / 5.2.20 or later.", "Data binding on JDK 9+ allows remote code execution in some deployments.", { exploit: "Exploited in the wild" }),
    T("Docker Remote API Unauthenticated Access", "2375/tcp", 10.0, "High", [], "Disable the TCP listener or protect it with mutual TLS.", "The Docker daemon API is exposed without authentication.")
  ],
  "app-04": [
    T("Apache Log4j Remote Code Execution (Log4Shell)", "8080/tcp", 10.0, "High", ["CVE-2021-44228"], "Update Log4j to 2.17.1 or later, or remove the JndiLookup class.", "Log4j 2 JNDI features allow remote code execution through crafted log messages.", { exploit: "Exploited in the wild", life: [1, 3] }),
    T("Operating System End of Life (EOL) Detection", "general/tcp", 10.0, "High", [], "Upgrade to a supported operating system release.", "The installed operating system has reached end of life and no longer receives security updates."),
    T("Apache Tomcat < 9.0.83 Multiple Vulnerabilities", "8080/tcp", 7.5, "High", ["CVE-2023-46589"], "Update Apache Tomcat to 9.0.83 or later.", "The installed Tomcat version is affected by an HTTP request smuggling flaw.")
  ],
  "api-gw-01": [
    T("Kong Admin API Exposed", "8001/tcp", 7.5, "High", [], "Bind the admin API to localhost or protect it with authentication.", "The API gateway admin interface is reachable without authentication."),
    T("SSL/TLS: Self-Signed Certificate", "8443/tcp", 5.0, "Medium", [], "Use a certificate issued by a trusted CA.", "The service presents a self-signed certificate.")
  ],
  "db-01": [T("PostgreSQL < 15.5 Multiple Vulnerabilities", "5432/tcp", 6.5, "Medium", ["CVE-2023-5868", "CVE-2023-5869"], "Update PostgreSQL to 15.5 or later.", "The installed PostgreSQL version is affected by memory disclosure and integer overflow flaws."), T("PostgreSQL Weak Authentication (trust in pg_hba.conf)", "5432/tcp", 7.5, "High", [], "Replace trust with scram-sha-256 for network connections.", "The server accepts connections from the local network without a password.")],
  "db-02": [T("MySQL / MariaDB Default Credentials", "3306/tcp", 9.0, "High", [], "Change the default credentials and restrict network access.", "The database accepts a vendor default account.", { exploit: "Public exploit", life: [0, 3] }), T("Oracle MySQL Server < 8.0.36 Multiple Vulnerabilities", "3306/tcp", 4.9, "Medium", ["CVE-2024-20961"], "Update MySQL Server to 8.0.36 or later.", "Several denial-of-service flaws affect the installed MySQL version.")],
  "db-03": [
    T("Microsoft SQL Server Unsupported Version (2012)", "1433/tcp", 10.0, "High", [], "Upgrade to a supported SQL Server release.", "The installed SQL Server version no longer receives security updates."),
    T("Microsoft Windows SMBv1 Enabled (MS17-010)", "445/tcp", 8.1, "High", ["CVE-2017-0144"], "Disable SMBv1 and apply the vendor patches.", "SMBv1 is enabled and the host is missing the MS17-010 patch.", { exploit: "Public exploit" }),
    T("Microsoft RDP Network Level Authentication Not Required", "3389/tcp", 4.3, "Medium", [], "Require Network Level Authentication for Remote Desktop.", "RDP accepts connections that do not use NLA.")
  ],
  "db-04": [T("Oracle Database TNS Listener Poison Attack", "1521/tcp", 7.5, "High", ["CVE-2012-1675"], "Apply the vendor patch or enable valid-node checking on the listener.", "The listener allows remote registration of services, enabling man-in-the-middle attacks."), T("Operating System End of Life (EOL) Detection", "general/tcp", 10.0, "High", [], "Upgrade to a supported operating system release.", "The installed operating system has reached end of life.")],
  "dc-01": [
    T("Microsoft Windows Netlogon Elevation of Privilege (Zerologon)", "445/tcp", 10.0, "High", ["CVE-2020-1472"], "Apply the August 2020 patch and enable enforcement mode.", "A flaw in the Netlogon secure channel allows an unauthenticated attacker to become a domain administrator.", { exploit: "Public exploit", life: [0, 3] }),
    T("Kerberos RC4 Encryption Types Allowed", "88/tcp", 3.5, "Low", [], "Disable RC4 for Kerberos service tickets.", "Weak Kerberos encryption types make Kerberoasting easier."),
    T("LDAP Signing Not Required", "389/tcp", 5.3, "Medium", [], "Require LDAP signing and channel binding.", "The domain controller accepts unsigned LDAP binds.")
  ],
  "fs-01": [
    T("Microsoft Windows SMBv1 Enabled (MS17-010)", "445/tcp", 8.1, "High", ["CVE-2017-0144"], "Disable SMBv1 and apply the vendor patches.", "SMBv1 is enabled and the host is missing the MS17-010 patch.", { exploit: "Public exploit" }),
    T("SMB Signing Not Required", "445/tcp", 5.3, "Medium", [], "Require SMB signing.", "The SMB server does not require message signing."),
    T("Microsoft Windows Print Spooler RCE (PrintNightmare)", "445/tcp", 8.8, "High", ["CVE-2021-34527"], "Apply the July 2021 updates or disable the Print Spooler service.", "The Print Spooler service allows remote code execution with SYSTEM privileges.")
  ],
  "mail-01": [
    T("Postfix SMTP Smuggling (CVE-2023-51764)", "25/tcp", 5.3, "Medium", ["CVE-2023-51764"], "Update Postfix to a fixed release or set smtpd_forbid_bare_newline.", "Bare newline handling allows SMTP smuggling and spoofing."),
    T("SMTP STARTTLS Not Enforced", "25/tcp", 4.0, "Medium", [], "Require STARTTLS for authenticated sessions.", "Credentials can be sent over an unencrypted connection."),
    T("Dovecot < 2.3.21 Multiple Vulnerabilities", "143/tcp", 7.5, "High", ["CVE-2023-41079"], "Update Dovecot to 2.3.21 or later.", "The installed Dovecot version is affected by denial-of-service flaws.")
  ],
  "vpn-gw-01": [T("OpenVPN < 2.6.9 Multiple Vulnerabilities", "1194/udp", 7.5, "High", ["CVE-2024-28882"], "Update OpenVPN to 2.6.9 or later.", "The installed OpenVPN version is affected by a flaw that keeps client sessions alive after exit notification."), T("IKE Aggressive Mode with Pre-Shared Key", "500/udp", 5.0, "Medium", [], "Disable aggressive mode or use certificates.", "Aggressive mode leaks a hash that can be attacked offline.")],
  "jump-01": [T("SSH Password Authentication Enabled on Bastion", "22/tcp", 5.3, "Medium", [], "Require key-based authentication with MFA on the bastion.", "The bastion host allows password logins from the network."), T("SSH Root Login Enabled", "22/tcp", 6.4, "Medium", [], "Set PermitRootLogin no.", "Direct root login over SSH is permitted.")]
};

const WIN_COMMON = [T("Windows Defender Antivirus Signature Out of Date", "general/tcp", 3.1, "Low", [], "Ensure signature updates reach the server.", "Antivirus signatures are older than seven days.")];

function findingsFor(h) {
  const base = [...COMMON];
  if (h.family === "linux") base.push(...SSH.filter((s, i) => !(s.name.includes("regreSSHion") && !rnd.chance(0.6)) && (i === 0 || rnd.chance(0.6))));
  if (h.family === "windows") base.push(...WIN_COMMON);
  if (["web", "waf"].includes(h.role)) base.push(...WEB.filter(() => rnd.chance(0.55)));
  return [...base, ...(SPECIFIC[h.name] || [])];
}

/* ------------------------------------- reports over time ------------------------------------- */
const DAYS_AGO = [21, 14, 7, 1];
const TASKS = ["Weekly authenticated scan: all zones", "Weekly authenticated scan: all zones", "Weekly authenticated scan: all zones", "Weekly authenticated scan: all zones"];
const BASELINE_REPORTS = DAYS_AGO.map((d, i) => ({ id: `rep-2026-w${i + 1}`, status: "Done", timestamp: iso(Date.now() - d * DAY - 4 * 3600_000), taskName: TASKS[i], scannedHosts: [] }));

// each (host, finding) gets a lifetime across the four reports
const LIFE = [];
for (const h of HOSTS) {
  for (const f of findingsFor(h)) {
    let from = 0, to = 3;
    if (f.life) [from, to] = f.life;
    else if (f.threat !== "Log") {
      const x = rnd.r();
      if (f.quick && x < 0.4) to = rnd.pick([1, 2]);            // got fixed along the way
      else if (x < 0.14) to = rnd.pick([1, 2]);                 // fixed along the way
      else if (x < 0.27) from = rnd.pick([2, 3]);               // newly introduced
    }
    if (["web-04", "app-04", "db-04", "jump-01"].includes(h.name)) from = Math.max(from, 1); // these hosts joined the scan after week 1
    LIFE.push({ h, f, from, to });
  }
}
for (const rep of BASELINE_REPORTS) rep.scannedHosts = [];
BASELINE_REPORTS.forEach((rep, i) => { rep.scannedHosts = HOSTS.filter((h) => !(i === 0 && ["web-04", "app-04", "db-04", "jump-01"].includes(h.name))).map((h) => h.ip).sort(); });

/**
 * All raw findings for the baseline reports plus `extra` (reports created through the demo bridge). `reportIndex` is 0 for the
 * newest report, as the real bridge reports it.
 */
function rows(extraReports = []) {
  const reports = [...BASELINE_REPORTS, ...extraReports.map((r) => ({ ...r }))];
  const out = [];
  const last = reports.length - 1;
  reports.forEach((rep, i) => {
    if (i < BASELINE_REPORTS.length) {
      for (const { h, f, from, to } of LIFE) {
        if (i < from || i > to || !rep.scannedHosts.includes(h.ip)) continue;
        out.push({ reportId: rep.id, taskName: rep.taskName, host: h.ip, port: f.port, name: f.name, oid: f.oid, cves: f.cves, severity: f.severity, threat: f.threat, description: `${f.description}`, solution: f.solution, creationTime: rep.timestamp, resultId: `${rep.id}-${h.ip}-${f.oid}`, reportIndex: last - i });
      }
    } else {
      for (const item of rep.findings || []) out.push({ ...item, reportIndex: last - i });
    }
  });
  return { reports, rows: out };
}

const latestHostFindings = (ip) => LIFE.filter((x) => x.h.ip === ip && x.to === 3 && x.f.threat !== "Log").map((x) => x.f);
const hostByIp = (ip) => HOSTS.find((h) => h.ip === ip) || null;

/* ---------------------------------- targets, tasks, platform ---------------------------------- */
const ZONES = [
  ["DMZ web tier", ["web-01", "web-02", "web-03", "web-04", "api-gw-01"]],
  ["Application tier", ["app-01", "app-02", "app-04"]],
  ["Data tier", ["db-01", "db-02", "db-03", "db-04"]],
  ["Identity, file and mail", ["dc-01", "fs-01", "mail-01"]],
  ["Remote access", ["vpn-gw-01", "jump-01"]]
];
const zoneHosts = (names) => names.map((n) => HOSTS.find((h) => h.name === n).ip).join(", ");
const id = (s) => { const r = makeRandom([...s].reduce((a, c) => (Math.imul(a, 33) + c.charCodeAt(0)) | 0, 5)); const x = r.hex(32); return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`; };
const TARGETS = ZONES.map(([name, hosts]) => ({ id: id("t:" + name), name: `${name} (internal)`, hosts: zoneHosts(hosts), comment: "Authorised internal assessment scope" }));
TARGETS.push({ id: id("t:cloud"), name: "Cloud workloads", hosts: "10.40.1.11, 10.40.1.21, 10.40.1.31, 10.40.2.11", comment: "AWS and Azure production instances" });
TARGETS.push({ id: id("t:ext"), name: "External perimeter", hosts: "203.0.113.20, 203.0.113.21", comment: "Public web and VPN addresses (PCI ASV)" });
const TASKS_BASE = [
  ["Weekly authenticated scan: DMZ web tier", "Done", "100", 0, "rep-2026-w4"], ["Weekly authenticated scan: Application tier", "Done", "100", 1, "rep-2026-w4"], ["Weekly authenticated scan: Data tier", "Done", "100", 2, "rep-2026-w4"],
  ["Weekly authenticated scan: Identity, file and mail", "Done", "100", 3, "rep-2026-w4"], ["Weekly authenticated scan: Remote access", "Done", "100", 4, "rep-2026-w4"],
  ["Cloud workloads: monthly credentialed scan", "Running", "63", 5, ""], ["External perimeter: quarterly PCI ASV scan", "Queued", "0", 6, ""], ["Pre-production regression scan", "New", "-1", 0, ""], ["Legacy file server decommission check", "Stopped", "27", 3, ""]
].map(([name, status, progress, t, lastReportId]) => ({ id: id("task:" + name), name, status, progress, target: TARGETS[t].name, lastReportId }));

const PLATFORM = {
  scanners: { items: [{ id: id("s1"), name: "OpenVAS Default", type: "OpenVAS Scanner", host: "/var/run/ospd/ospd-openvas.sock", port: "0" }, { id: id("s2"), name: "CVE", type: "CVE Scanner", host: "", port: "0" }, { id: id("s3"), name: "Remote scanner: Frankfurt", type: "OpenVAS Scanner", host: "10.20.9.40", port: "9390" }] },
  configs: { items: [["Full and fast", "Most NVTs; optimised by using previously collected information.", "88142", "61"], ["Full and fast ultimate", "Most NVTs including those that can stop services or hosts.", "88142", "61"], ["Full and very deep", "Most NVTs; slower, does not trust previously collected information.", "88142", "61"], ["Discovery", "Network Discovery scan configuration.", "3510", "9"], ["Host Discovery", "Network Host Discovery scan configuration.", "3", "1"], ["System Discovery", "Network System Discovery scan configuration.", "412", "5"], ["PrimeSEC credentialed Linux and Windows", "Full and fast with SSH and SMB credentials.", "88142", "61"]].map(([name, comment, nvtCount, familyCount], i) => ({ id: id("c" + i), name, comment, nvtCount, familyCount })) },
  portLists: { items: [["All IANA assigned TCP", "T:1-5,7,9,11,13,..."], ["All TCP and Nmap top 100 UDP", "T:1-65535,U:7,9,17,19,..."], ["OpenVAS Default", "T:1-5,7,9,11,...,U:7,9,17,..."], ["Web and database ports", "T:22,25,80,143,443,445,1433,1521,3306,3389,5432,8080,8443"]].map(([name, ports], i) => ({ id: id("p" + i), name, ports })) },
  schedules: { items: [["Sunday 02:00 weekly", "Weekly full scans", "Asia/Kolkata"], ["First Saturday 01:00 monthly", "Cloud workloads", "Asia/Kolkata"], ["Quarterly PCI window", "External ASV scan", "UTC"]].map(([name, comment, timezone], i) => ({ id: id("sc" + i), name, comment, timezone })) },
  alerts: { items: [["Email SOC on High findings", "Task run status changed", "Severity at least 7.0", "Email", "1"], ["Forward report to Wazuh (syslog)", "Task run status changed", "Always", "Syslog", "1"], ["Create ticket for Critical findings", "New NVT results arrived", "Severity at least 9.0", "HTTP Get", "0"]].map(([name, event, condition, method, active], i) => ({ id: id("a" + i), name, event, condition, method, active })) },
  feeds: { items: [{ name: "Greenbone Community Feed", type: "NVT", version: "202611190431", syncing: false }, { name: "Greenbone Community Feed", type: "SCAP", version: "202611190302", syncing: false }, { name: "Greenbone Community Feed", type: "CERT", version: "202611190402", syncing: false }, { name: "Greenbone Community Feed", type: "GVMD_DATA", version: "202611181905", syncing: false }] }
};

module.exports = { HOSTS, BASELINE_REPORTS, rows, latestHostFindings, hostByIp, TARGETS, TASKS_BASE, PLATFORM };
