/**
 * Demo fleet: a fictional mid-size enterprise ("Meridian Group") with ~50 Wazuh agents across a DMZ web tier, application and
 * database tiers, Active Directory, cloud workloads, Kubernetes nodes, VPN/jump hosts and office workstations in four cities.
 * Everything is invented. IPs are private ranges.
 */
const { makeRandom, DAY, MIN, iso } = require("./common");

const OS = {
  ubuntu22: { name: "Ubuntu", version: "22.04.4 LTS", platform: "ubuntu", codename: "jammy", arch: "x86_64", kernel: "5.15.0-105-generic", family: "linux" },
  ubuntu24: { name: "Ubuntu", version: "24.04 LTS", platform: "ubuntu", codename: "noble", arch: "x86_64", kernel: "6.8.0-31-generic", family: "linux" },
  debian12: { name: "Debian GNU/Linux", version: "12", platform: "debian", codename: "bookworm", arch: "x86_64", kernel: "6.1.0-21-amd64", family: "linux" },
  rhel8: { name: "Red Hat Enterprise Linux", version: "8.9", platform: "rhel", codename: "Ootpa", arch: "x86_64", kernel: "4.18.0-513.el8.x86_64", family: "linux" },
  rhel9: { name: "Red Hat Enterprise Linux", version: "9.3", platform: "rhel", codename: "Plow", arch: "x86_64", kernel: "5.14.0-362.el9.x86_64", family: "linux" },
  ol8: { name: "Oracle Linux Server", version: "8.9", platform: "ol", codename: "", arch: "x86_64", kernel: "5.15.0-200.el8uek", family: "linux" },
  al2023: { name: "Amazon Linux", version: "2023", platform: "amzn", codename: "", arch: "x86_64", kernel: "6.1.84-99.169.amzn2023", family: "linux" },
  win2022: { name: "Microsoft Windows Server 2022 Standard", version: "10.0.20348.2461", platform: "windows", codename: "", arch: "x86_64", kernel: "10.0.20348", family: "windows" },
  win2019: { name: "Microsoft Windows Server 2019 Standard", version: "10.0.17763.5936", platform: "windows", codename: "", arch: "x86_64", kernel: "10.0.17763", family: "windows" },
  win11: { name: "Microsoft Windows 11 Pro", version: "10.0.22631.3447", platform: "windows", codename: "", arch: "x86_64", kernel: "10.0.22631", family: "windows" },
  win10: { name: "Microsoft Windows 10 Enterprise", version: "10.0.19045.4291", platform: "windows", codename: "", arch: "x86_64", kernel: "10.0.19045", family: "windows" },
  macos14: { name: "macOS", version: "14.4.1", platform: "darwin", codename: "Sonoma", arch: "arm64", kernel: "23.4.0", family: "mac" }
};

// id, name, ip, os, groups, status, wazuh version, role, site
const ROWS = [
  ["000", "wazuh-manager", "127.0.0.1", "ubuntu22", "default", "active", "4.9.2", "manager", "Mumbai DC"],
  // DMZ web tier
  ["001", "web-01", "172.16.10.11", "ubuntu22", "default,linux,web-servers,dmz,pci-scope", "active", "4.9.2", "web", "Mumbai DC"],
  ["002", "web-02", "172.16.10.12", "ubuntu22", "default,linux,web-servers,dmz,pci-scope", "active", "4.9.2", "web", "Mumbai DC"],
  ["003", "web-03", "172.16.10.13", "debian12", "default,linux,web-servers,dmz", "active", "4.8.1", "web", "Mumbai DC"],
  ["004", "web-04", "172.16.10.14", "rhel9", "default,linux,web-servers,dmz", "active", "4.9.2", "web", "Frankfurt DC"],
  ["005", "waf-01", "172.16.10.5", "ubuntu22", "default,linux,dmz", "active", "4.9.2", "waf", "Mumbai DC"],
  // Application tier
  ["006", "app-01", "10.20.1.21", "rhel8", "default,linux,app-servers", "active", "4.9.2", "app", "Mumbai DC"],
  ["007", "app-02", "10.20.1.22", "rhel8", "default,linux,app-servers", "active", "4.9.2", "app", "Mumbai DC"],
  ["008", "app-03", "10.20.1.23", "ubuntu22", "default,linux,app-servers", "active", "4.9.2", "app", "Mumbai DC"],
  ["009", "app-04", "10.20.1.24", "rhel8", "default,linux,app-servers,pci-scope", "active", "4.7.5", "app", "Frankfurt DC"],
  ["010", "app-05", "10.20.1.25", "ubuntu22", "default,linux,app-servers", "active", "4.9.2", "app", "Frankfurt DC"],
  ["011", "app-06", "10.20.1.26", "ubuntu22", "default,linux,app-servers", "disconnected", "4.9.2", "app", "Frankfurt DC"],
  ["012", "api-gw-01", "10.20.1.5", "ubuntu22", "default,linux,app-servers,dmz", "active", "4.9.2", "apigw", "Mumbai DC"],
  ["013", "api-gw-02", "10.20.1.6", "ubuntu22", "default,linux,app-servers,dmz", "active", "4.9.2", "apigw", "Mumbai DC"],
  // Data tier
  ["014", "db-01", "10.20.2.31", "ubuntu22", "default,linux,databases,pci-scope", "active", "4.9.2", "db-pg", "Mumbai DC"],
  ["015", "db-02", "10.20.2.32", "ubuntu22", "default,linux,databases,pci-scope", "active", "4.9.2", "db-my", "Mumbai DC"],
  ["016", "db-03", "10.20.2.33", "win2019", "default,windows,databases", "active", "4.9.2", "db-ms", "Mumbai DC"],
  ["017", "db-04", "10.20.2.34", "ol8", "default,linux,databases", "active", "4.8.1", "db-ora", "Frankfurt DC"],
  ["018", "cache-01", "10.20.2.40", "debian12", "default,linux,databases", "active", "4.9.2", "cache", "Mumbai DC"],
  // Identity, file and mail
  ["019", "dc-01", "10.20.3.10", "win2022", "default,windows,domain-controllers", "active", "4.9.2", "dc", "Mumbai DC"],
  ["020", "dc-02", "10.20.3.11", "win2022", "default,windows,domain-controllers", "active", "4.9.2", "dc", "Frankfurt DC"],
  ["021", "adfs-01", "10.20.3.20", "win2022", "default,windows,domain-controllers", "active", "4.9.2", "adfs", "Mumbai DC"],
  ["022", "fs-01", "10.20.3.50", "win2019", "default,windows,file-servers", "active", "4.9.2", "fs", "Mumbai DC"],
  ["023", "mail-01", "10.20.4.30", "ubuntu22", "default,linux,mail", "active", "4.9.2", "mail", "Mumbai DC"],
  ["024", "mail-02", "10.20.4.31", "ubuntu22", "default,linux,mail", "active", "4.9.2", "mail", "Frankfurt DC"],
  // Edge, remote access and operations
  ["025", "vpn-gw-01", "10.20.0.2", "debian12", "default,linux,dmz,remote-access", "active", "4.9.2", "vpn", "Mumbai DC"],
  ["026", "vpn-gw-02", "10.20.0.3", "debian12", "default,linux,dmz,remote-access", "active", "4.9.2", "vpn", "Frankfurt DC"],
  ["027", "jump-01", "10.20.0.8", "ubuntu22", "default,linux,remote-access", "active", "4.9.2", "jump", "Mumbai DC"],
  ["028", "bk-01", "10.20.5.10", "rhel9", "default,linux,backup", "active", "4.9.2", "backup", "Mumbai DC"],
  // Cloud workloads
  ["029", "aws-prod-web-01", "10.40.1.11", "al2023", "default,linux,cloud-aws,web-servers", "active", "4.9.2", "cloud-web", "AWS ap-south-1"],
  ["030", "aws-prod-api-01", "10.40.1.21", "al2023", "default,linux,cloud-aws,app-servers", "active", "4.9.2", "cloud-api", "AWS ap-south-1"],
  ["031", "aws-prod-db-01", "10.40.1.31", "al2023", "default,linux,cloud-aws,databases", "active", "4.9.2", "cloud-db", "AWS ap-south-1"],
  ["032", "azure-app-01", "10.40.2.11", "win2022", "default,windows,cloud-azure,app-servers", "active", "4.9.2", "cloud-win", "Azure Central India"],
  ["033", "gcp-analytics-01", "10.40.3.11", "debian12", "default,linux,cloud-gcp", "active", "4.9.2", "cloud-analytics", "GCP asia-south1"],
  ["034", "k8s-node-01", "10.40.4.11", "ubuntu22", "default,linux,kubernetes", "active", "4.9.2", "k8s", "AWS ap-south-1"],
  ["035", "k8s-node-02", "10.40.4.12", "ubuntu22", "default,linux,kubernetes", "active", "4.9.2", "k8s", "AWS ap-south-1"],
  ["036", "k8s-node-03", "10.40.4.13", "ubuntu22", "default,linux,kubernetes", "active", "4.9.2", "k8s", "AWS ap-south-1"],
  // Workstations
  ["037", "ws-mum-101", "10.30.1.101", "win11", "default,windows,workstations", "active", "4.9.2", "ws-win", "Mumbai HQ"],
  ["038", "ws-mum-114", "10.30.1.114", "win11", "default,windows,workstations,finance", "active", "4.9.2", "ws-win", "Mumbai HQ"],
  ["039", "ws-mum-118", "10.30.1.118", "win11", "default,windows,workstations,finance", "active", "4.9.2", "ws-win", "Mumbai HQ"],
  ["040", "ws-mum-207", "10.30.1.207", "win10", "default,windows,workstations", "disconnected", "4.8.1", "ws-win", "Mumbai HQ"],
  ["041", "ws-mum-220", "10.30.1.220", "macos14", "default,mac,workstations,engineering", "active", "4.9.2", "ws-mac", "Mumbai HQ"],
  ["042", "ws-lon-031", "10.30.2.31", "win11", "default,windows,workstations", "active", "4.9.2", "ws-win", "London"],
  ["043", "ws-lon-044", "10.30.2.44", "win11", "default,windows,workstations,finance", "active", "4.9.2", "ws-win", "London"],
  ["044", "ws-lon-052", "10.30.2.52", "macos14", "default,mac,workstations,engineering", "active", "4.9.2", "ws-mac", "London"],
  ["045", "ws-nyc-012", "10.30.3.12", "win11", "default,windows,workstations", "active", "4.9.2", "ws-win", "New York"],
  ["046", "ws-nyc-027", "10.30.3.27", "win10", "default,windows,workstations,executive", "active", "4.9.2", "ws-win", "New York"],
  ["047", "ws-nyc-033", "10.30.3.33", "ubuntu24", "default,linux,workstations,engineering", "active", "4.9.2", "ws-lin", "New York"],
  ["048", "ws-sin-008", "10.30.4.8", "win11", "default,windows,workstations", "active", "4.9.2", "ws-win", "Singapore"],
  ["049", "ws-sin-019", "10.30.4.19", "macos14", "default,mac,workstations", "disconnected", "4.9.2", "ws-mac", "Singapore"],
  ["050", "ws-sin-024", "10.30.4.24", "win11", "default,windows,workstations", "active", "4.9.2", "ws-win", "Singapore"],
  ["051", "ws-mum-301", "10.30.1.131", "win11", "default,windows,workstations", "never_connected", "4.9.2", "ws-win", "Mumbai HQ"],
  ["052", "ws-lon-060", "10.30.2.60", "win11", "default,windows,workstations", "never_connected", "4.9.2", "ws-win", "London"],
  ["053", "ws-nyc-041", "10.30.3.41", "win11", "default,windows,workstations", "pending", "4.9.2", "ws-win", "New York"]
];

const rnd = makeRandom(77);

function buildAgents() {
  const now = Date.now();
  return ROWS.map(([id, name, ip, os, groups, status, ver, role, site], i) => {
    const o = OS[os];
    const alive = status === "active";
    const added = now - (20 + ((i * 13) % 300)) * DAY;
    const lastKeepAlive = status === "never_connected" ? null : alive ? now - rnd.int(2, 55) * 1000 : now - (3 + (i % 9)) * DAY;
    return {
      id, name, ip: status === "never_connected" ? "any" : ip, registerIP: ip, status, version: `Wazuh v${ver}`,
      os: { name: o.name, version: o.version, platform: o.platform, codename: o.codename, arch: o.arch, uname: `${o.family === "windows" ? "Microsoft Windows" : o.family === "mac" ? "Darwin" : "Linux"} |${name} |${o.kernel}` },
      group: groups.split(","), manager: "wazuh-manager-mum", node_name: id === "000" || i % 2 === 0 ? "worker-mum" : "worker-fra",
      dateAdd: iso(added), lastKeepAlive: lastKeepAlive ? iso(lastKeepAlive) : null, status_code: alive ? 0 : 1,
      configSum: rnd.hex(40), mergedSum: rnd.hex(32),
      // not part of the Wazuh API: kept so the other generators can reach it. Stripped before sending.
      _role: role, _osKey: os, _family: o.family, _site: site
    };
  });
}

const AGENTS = buildAgents();
const publicAgent = ({ _role, _osKey, _family, _site, ...rest }) => rest;
const byId = new Map(AGENTS.map((a) => [a.id, a]));

function groups() {
  const counts = new Map();
  for (const a of AGENTS) for (const g of a.group) counts.set(g, (counts.get(g) || 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count, mergedSum: rnd.hex(32), configSum: rnd.hex(40) }));
}

function summary() {
  const c = { active: 0, disconnected: 0, never_connected: 0, pending: 0 };
  for (const a of AGENTS) c[a.status]++;
  return { connection: { ...c, total: AGENTS.length }, configuration: { synced: AGENTS.length - c.never_connected - c.pending, "not synced": c.never_connected + c.pending, total: AGENTS.length } };
}

/* ------------------------------- per-agent detail ------------------------------- */

const sd = (id) => makeRandom(Number(id) * 7919 + 11);

function syscollectorOs(a) {
  const o = OS[a._osKey];
  return {
    os: { name: o.name, version: o.version, platform: o.platform, codename: o.codename || undefined },
    architecture: o.arch, hostname: a.name, release: o.kernel, sysname: o.family === "windows" ? "Windows" : o.family === "mac" ? "Darwin" : "Linux",
    version: o.version, scan: { id: 0, time: iso(Date.now() - 6 * 3600_000) }
  };
}

const SCA_POLICIES = {
  ubuntu: [["cis_ubuntu22-04", "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0", 224], ["cis_apache2_24", "CIS Apache HTTP Server 2.4 Benchmark v2.1.0", 76], ["cis_nginx", "CIS NGINX Benchmark v2.0.1", 63]],
  debian: [["cis_debian12", "CIS Debian Linux 12 Benchmark v1.0.0", 210], ["cis_nginx", "CIS NGINX Benchmark v2.0.1", 63]],
  rhel: [["cis_rhel9", "CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0", 236], ["cis_docker", "CIS Docker Benchmark v1.6.0", 98]],
  windows_server: [["cis_win2022", "CIS Microsoft Windows Server 2022 Benchmark v2.0.0", 354], ["cis_win2019", "CIS Microsoft Windows Server 2019 Benchmark v3.0.0", 332]],
  windows_client: [["cis_win11_ent", "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0", 392], ["cis_win10_ent", "CIS Microsoft Windows 10 Enterprise Benchmark v3.0.1", 380]],
  mac: [["cis_macos14", "CIS Apple macOS 14.0 Sonoma Benchmark v1.0.0", 118]],
  db: [["cis_pgsql15", "CIS PostgreSQL 15 Benchmark v1.0.0", 88], ["cis_mysql80", "CIS Oracle MySQL Enterprise Edition 8.0 Benchmark v1.2.0", 112]]
};
function scaFor(a) {
  const r = sd(a.id);
  let list;
  if (a._family === "mac") list = SCA_POLICIES.mac.slice(0, 1);
  else if (a._family === "windows") list = (a._osKey.startsWith("win20") ? SCA_POLICIES.windows_server : SCA_POLICIES.windows_client).slice(0, 1);
  else if (a._osKey.startsWith("ubuntu")) list = a._role === "web" ? [SCA_POLICIES.ubuntu[0], SCA_POLICIES.ubuntu[2]] : [SCA_POLICIES.ubuntu[0]];
  else if (a._osKey.startsWith("debian")) list = SCA_POLICIES.debian.slice(0, a._role === "web" ? 2 : 1);
  else list = SCA_POLICIES.rhel.slice(0, a._role === "app" ? 2 : 1);
  if (a._role.startsWith("db-")) list = [...list, a._role === "db-my" ? SCA_POLICIES.db[1] : SCA_POLICIES.db[0]];
  return list.map(([policy_id, name, total], i) => {
    const pass = Math.round(total * (0.52 + r.r() * 0.3 - (a._role.startsWith("ws") ? 0.04 : 0)));
    const invalid = r.int(0, 6);
    const fail = total - pass - invalid;
    return {
      policy_id, name, description: `Hardening guidance for ${name.replace(/ Benchmark.*/, "")}.`, references: "https://www.cisecurity.org/cis-benchmarks/",
      score: Math.round((pass / (pass + fail)) * 100), pass, fail, invalid, total_checks: total,
      start_scan: iso(Date.now() - (6 + i) * 3600_000), end_scan: iso(Date.now() - (6 + i) * 3600_000 + 41_000), hash_file: r.hex(64)
    };
  });
}

const LINUX_FILES = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/crontab", "/etc/hosts", "/etc/resolv.conf", "/root/.ssh/authorized_keys", "/usr/bin/sudo", "/usr/sbin/sshd", "/etc/pam.d/common-auth", "/etc/fstab", "/boot/grub/grub.cfg", "/etc/systemd/system/multi-user.target.wants/cron.service"];
const ROLE_FILES = {
  web: ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/default.conf", "/var/www/html/index.php", "/var/www/html/wp-config.php", "/var/www/html/uploads/shell.php", "/etc/ssl/private/portal.key"],
  "cloud-web": ["/etc/nginx/nginx.conf", "/var/www/html/index.php", "/opt/app/.env"],
  app: ["/opt/app/config/application.yml", "/opt/app/bin/start.sh", "/etc/systemd/system/app.service", "/opt/app/lib/app.jar"],
  apigw: ["/etc/kong/kong.conf", "/usr/local/bin/kong"],
  "db-pg": ["/etc/postgresql/15/main/pg_hba.conf", "/etc/postgresql/15/main/postgresql.conf"],
  "db-my": ["/etc/mysql/my.cnf", "/var/lib/mysql/mysql/user.MYD"],
  mail: ["/etc/postfix/main.cf", "/etc/dovecot/dovecot.conf"],
  vpn: ["/etc/openvpn/server.conf", "/etc/wireguard/wg0.conf"],
  jump: ["/etc/ssh/sshd_config.d/10-bastion.conf", "/var/log/auth.log"],
  k8s: ["/etc/kubernetes/kubelet.conf", "/var/lib/kubelet/config.yaml", "/etc/containerd/config.toml"]
};
const WIN_FILES = ["C:\\Windows\\System32\\drivers\\etc\\hosts", "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Temp\\svchost.exe", "C:\\Windows\\System32\\Tasks\\GoogleUpdateTaskMachineCore", "C:\\Users\\Public\\Documents\\update.ps1", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\helper.lnk", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"];
function syscheckFor(a) {
  const r = sd(a.id);
  const files = a._family === "windows" ? WIN_FILES : [...LINUX_FILES, ...(ROLE_FILES[a._role] || [])];
  return files.map((file, i) => {
    const type = file.startsWith("HKEY") ? "registry_key" : "file";
    const when = Date.now() - r.int(10, 60 * 24 * 14) * MIN;
    return {
      file, type, size: type === "file" ? r.int(120, 4_800_000) : undefined, date: iso(when), mtime: iso(when),
      md5: r.hex(32), sha1: r.hex(40), sha256: r.hex(64), uid: a._family === "windows" ? "S-1-5-18" : "0", gid: a._family === "windows" ? undefined : "0",
      perm: a._family === "windows" ? "rw-r--r--" : file.includes("shadow") || file.includes(".key") || file.endsWith(".env") ? "rw-------" : "rw-r--r--",
      uname: a._family === "windows" ? "SYSTEM" : "root", gname: a._family === "windows" ? undefined : "root", inode: a._family === "windows" ? undefined : r.int(1000, 900000), changes: r.int(1, 6)
    };
  }).sort((x, y) => (x.date < y.date ? 1 : -1));
}

const ROOTCHECK_LINUX = [
  ["System Audit: CIS - Debian Linux - 1.1.1 - Robust partition scheme - /tmp is not on its own partition {CIS: 1.1.1} {PCI_DSS: 2.2.4}", "outstanding"],
  ["System Audit: CIS - Debian Linux - 5.2.8 - SSH Configuration - Root login allowed {CIS: 5.2.8 Debian Linux} {PCI_DSS: 4.1}", "outstanding"],
  ["System Audit: CIS - Debian Linux - 5.2.10 - SSH Configuration - Password authentication enabled {CIS: 5.2.10}", "outstanding"],
  ["System Audit: SSH Hardening - 5: Password Authentication {PCI_DSS: 2.2.4}", "solved"],
  ["Process '2143' hidden from /proc. Possible kernel level rootkit.", "solved"],
  ["Application Found: nmap - Network port scanner present on the system.", "outstanding"],
  ["System Audit: Web vulnerability - Backdoor/shell script found in web directory", "outstanding"]
];
const ROOTCHECK_WIN = [
  ["Windows Audit: Windows Defender real-time protection is disabled {PCI_DSS: 5.1}", "outstanding"],
  ["Windows Audit: Guest account is enabled {CIS: 2.3.1.1}", "solved"],
  ["Windows Audit: SMBv1 client protocol is enabled {CIS: 18.3.2}", "outstanding"],
  ["Windows Audit: Remote Desktop without Network Level Authentication {CIS: 18.9.65}", "outstanding"],
  ["Windows Audit: Windows Firewall disabled for the public profile {CIS: 9.3.1}", "solved"]
];
function rootcheckFor(a) {
  const r = sd(a.id);
  const pool = a._family === "windows" ? ROOTCHECK_WIN : ROOTCHECK_LINUX;
  const n = Math.min(pool.length, 3 + r.int(0, 3));
  return r.shuffle(pool).slice(0, n).map(([event, status]) => {
    const first = Date.now() - r.int(2, 60) * DAY;
    return { event, status, date_first: iso(first), date_last: iso(Date.now() - r.int(1, 36) * 3600_000), log: event.split(" {")[0], cis: [], pci_dss: [] };
  });
}

module.exports = { OS, AGENTS, byId, publicAgent, groups, summary, syscollectorOs, scaFor, syscheckFor, rootcheckFor };
