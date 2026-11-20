/**
 * Wazuh reference data for the demo: ruleset, decoders, MITRE ATT&CK techniques and groups, and manager/cluster details.
 * Rule ids and levels follow the real Wazuh ruleset where it has a matching rule; ids from 100000 up are "custom rules" the
 * fictional SOC wrote itself, exactly as a real deployment would have.
 */
const { iso } = require("./common");

// key, id, level, description, groups, mitre technique ids, file
const RULE_ROWS = [
  ["sshd_nonexist", 5710, 5, "sshd: Attempt to login using a non-existent user", ["syslog", "sshd", "authentication_failed"], ["T1110.001"], "0095-sshd_rules.xml"],
  ["sshd_fail", 5760, 5, "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"], ["T1110.001"], "0095-sshd_rules.xml"],
  ["sshd_bf", 5712, 10, "sshd: brute force trying to get access to the system. Non existent user.", ["syslog", "sshd", "authentication_failures"], ["T1110"], "0095-sshd_rules.xml"],
  ["sshd_multi", 5720, 10, "sshd: Multiple authentication failures.", ["syslog", "sshd", "authentication_failures"], ["T1110"], "0095-sshd_rules.xml"],
  ["sshd_scan", 5706, 6, "sshd: insecure connection attempt (scan).", ["syslog", "sshd", "recon"], ["T1046"], "0095-sshd_rules.xml"],
  ["pam_fail", 5503, 5, "PAM: User login failed.", ["pam", "syslog", "authentication_failed"], ["T1110"], "0085-pam_rules.xml"],
  ["pam_open", 5501, 3, "PAM: Login session opened.", ["pam", "syslog", "authentication_success"], ["T1078"], "0085-pam_rules.xml"],
  ["sudo_root", 5402, 3, "Successful sudo to ROOT executed.", ["syslog", "sudo"], ["T1548.003"], "0080-sudo_rules.xml"],
  ["new_user_linux", 5902, 8, "New user added to the system.", ["syslog", "adduser", "account_changed"], ["T1136.001"], "0120-pam_rules.xml"],
  ["web400", 31101, 5, "Web server 400 error code.", ["web", "accesslog", "attack"], ["T1190"], "0245-web_rules.xml"],
  ["web_multi400", 31151, 10, "Multiple web server 400 error codes from same source ip.", ["web", "accesslog", "web_scan", "recon"], ["T1595"], "0245-web_rules.xml"],
  ["sqli", 31103, 7, "SQL injection attempt.", ["web", "accesslog", "attack", "sql_injection"], ["T1190"], "0245-web_rules.xml"],
  ["sqli_multi", 31152, 10, "Multiple SQL injection attempts from same source ip.", ["web", "accesslog", "attack", "sql_injection"], ["T1190"], "0245-web_rules.xml"],
  ["xss", 31105, 6, "XSS (Cross Site Scripting) attempt.", ["web", "accesslog", "attack"], ["T1190"], "0245-web_rules.xml"],
  ["web200", 31106, 9, "A web attack returned code 200 (success).", ["web", "accesslog", "attack"], ["T1190"], "0245-web_rules.xml"],
  ["shellshock", 31168, 15, "Shellshock attack detected.", ["web", "accesslog", "attack"], ["T1190"], "0245-web_rules.xml"],
  ["win_logon_fail", 60122, 5, "Logon failure - Unknown user or bad password.", ["windows", "windows_security", "authentication_failed"], ["T1110"], "0580-win-security_rules.xml"],
  ["win_multi_fail", 60204, 10, "Multiple Windows Logon Failures.", ["windows", "windows_security", "authentication_failures"], ["T1110"], "0580-win-security_rules.xml"],
  ["win_logon_ok", 60106, 3, "Windows logon success.", ["windows", "windows_security", "authentication_success"], ["T1078"], "0580-win-security_rules.xml"],
  ["win_new_user", 60109, 8, "User account enabled or created.", ["windows", "windows_security", "account_changed"], ["T1136.001"], "0580-win-security_rules.xml"],
  ["win_admin_group", 60154, 12, "Administrators group changed.", ["windows", "windows_security", "group_changed"], ["T1098"], "0580-win-security_rules.xml"],
  ["win_cleared_log", 63103, 12, "Windows audit log was cleared.", ["windows", "windows_security", "log_cleared"], ["T1070.001"], "0580-win-security_rules.xml"],
  ["syscheck_changed", 550, 7, "Integrity checksum changed.", ["ossec", "syscheck", "syscheck_entry_modified", "syscheck_file"], ["T1565.001"], "0015-ossec_rules.xml"],
  ["syscheck_added", 554, 5, "File added to the system.", ["ossec", "syscheck", "syscheck_entry_added", "syscheck_file"], ["T1105"], "0015-ossec_rules.xml"],
  ["syscheck_deleted", 553, 7, "File deleted.", ["ossec", "syscheck", "syscheck_entry_deleted", "syscheck_file"], ["T1070.004"], "0015-ossec_rules.xml"],
  ["rootcheck", 510, 7, "Host-based anomaly detection event (rootcheck).", ["ossec", "rootcheck"], [], "0015-ossec_rules.xml"],
  ["vt_malware", 87105, 12, "VirusTotal: Alert - file detected as malicious by multiple engines", ["virustotal"], ["T1204.002"], "0490-virustotal_rules.xml"],
  ["fw_block", 651, 3, "Host Blocked by firewall-drop Active Response", ["ossec", "active_response"], [], "0020-syslog_rules.xml"],
  ["agent_disconnect", 504, 3, "Wazuh agent disconnected.", ["ossec", "pci_dss_10.6.1"], [], "0015-ossec_rules.xml"],
  ["suricata", 86601, 3, "Suricata: Alert - network signature matched", ["suricata", "ids"], ["T1046"], "0475-suricata_rules.xml"],
  ["vuln", 23504, 10, "CVE affects a package installed on the agent", ["vulnerability-detector"], ["T1190"], "0585-vulnerability-detector_rules.xml"],
  ["log4shell", 100110, 14, "Log4Shell JNDI exploitation attempt in HTTP request headers", ["web", "attack", "log4shell"], ["T1190"], "local_rules.xml"],
  ["webshell", 100210, 13, "Web shell detected: new script written to the web root or uploads directory", ["web", "syscheck", "webshell"], ["T1505.003"], "local_rules.xml"],
  ["crit_file", 100150, 12, "Critical system file modified outside of a change window", ["syscheck", "pci_dss_11.5"], ["T1098"], "local_rules.xml"],
  ["cron_mod", 100160, 9, "Crontab modified by a non-administrative user", ["syscheck", "persistence"], ["T1053.003"], "local_rules.xml"],
  ["powershell_enc", 100301, 12, "Suspicious PowerShell: hidden window with encoded command spawned by an Office application", ["windows", "sysmon", "powershell"], ["T1059.001", "T1027"], "local_rules.xml"],
  ["lsass", 100321, 13, "Process accessed LSASS memory (possible credential dumping)", ["windows", "sysmon", "credential_access"], ["T1003.001"], "local_rules.xml"],
  ["mimikatz", 100320, 15, "Credential dumping tool detected: Mimikatz", ["windows", "sysmon", "credential_access"], ["T1003.001"], "local_rules.xml"],
  ["vssadmin", 100341, 13, "Volume shadow copies deleted via vssadmin", ["windows", "sysmon", "ransomware"], ["T1490"], "local_rules.xml"],
  ["ransomware", 100340, 15, "Ransomware-like behaviour: mass file renames to a new extension", ["windows", "syscheck", "ransomware"], ["T1486"], "local_rules.xml"],
  ["psexec", 100330, 10, "PsExec-style remote service created from another host", ["windows", "lateral_movement"], ["T1569.002", "T1021.002"], "local_rules.xml"],
  ["smb_admin", 100331, 9, "Admin share accessed from a non-administrative workstation", ["windows", "lateral_movement"], ["T1021.002"], "local_rules.xml"],
  ["av_disabled", 100900, 12, "Endpoint protection disabled on the host", ["windows", "defense_evasion"], ["T1562.001"], "local_rules.xml"],
  ["usb", 100910, 6, "USB mass storage device connected on a finance workstation", ["windows", "dlp"], ["T1052.001"], "local_rules.xml"],
  ["c2_beacon", 100400, 13, "Outbound beaconing to known command-and-control infrastructure (threat intel match)", ["network", "threat_intel", "c2"], ["T1071.001"], "local_rules.xml"],
  ["dns_dga", 100401, 10, "DNS query to an algorithmically generated domain", ["network", "dns", "c2"], ["T1568.002"], "local_rules.xml"],
  ["data_exfil", 100450, 13, "Unusual large outbound transfer to a rare external host", ["network", "exfiltration"], ["T1048"], "local_rules.xml"],
  ["dump_exec", 100710, 11, "Database dump utility spawned by a web-server account", ["linux", "database", "exfiltration"], ["T1005"], "local_rules.xml"],
  ["phish_mail", 100500, 9, "Email gateway: message with a macro-enabled attachment delivered", ["email", "phishing"], ["T1566.001"], "local_rules.xml"],
  ["phish_click", 100501, 12, "User opened a link to a known phishing domain (proxy log)", ["proxy", "phishing", "threat_intel"], ["T1566.002"], "local_rules.xml"],
  ["aws_root", 100600, 12, "AWS CloudTrail: root account used for an API call", ["aws", "cloudtrail", "iam"], ["T1078.004"], "local_rules.xml"],
  ["aws_s3", 100601, 10, "AWS CloudTrail: S3 bucket policy changed to allow public access", ["aws", "cloudtrail", "s3"], ["T1530"], "local_rules.xml"],
  ["aws_iam", 100602, 9, "AWS CloudTrail: access key created for a privileged IAM user", ["aws", "cloudtrail", "iam"], ["T1098.001"], "local_rules.xml"],
  ["k8s_priv", 100700, 11, "Kubernetes audit: privileged container started in the prod namespace", ["kubernetes", "container"], ["T1611"], "local_rules.xml"],
  ["vpn_geo", 100800, 10, "VPN login from an unusual location shortly after a login from another country", ["vpn", "authentication_success", "impossible_travel"], ["T1078"], "local_rules.xml"],
  ["vpn_fail", 100801, 5, "VPN authentication failure", ["vpn", "authentication_failed"], ["T1110.003"], "local_rules.xml"],
  ["mfa_fatigue", 100810, 11, "Repeated MFA push requests rejected then approved for the same user", ["identity", "mfa"], ["T1621"], "local_rules.xml"],
  ["kerberoast", 100340 + 21, 11, "Kerberos service ticket requested with weak RC4 encryption (possible Kerberoasting)", ["windows", "kerberos", "credential_access"], ["T1558.003"], "local_rules.xml"],
  ["adcs_abuse", 100362, 12, "Certificate enrolment with a user-supplied subject alternative name (AD CS abuse)", ["windows", "adcs"], ["T1649"], "local_rules.xml"]
];

const MITRE = {
  "T1110": ["Brute Force", ["Credential Access"], "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained."],
  "T1110.001": ["Brute Force: Password Guessing", ["Credential Access"], "Adversaries with no prior knowledge of legitimate credentials may guess passwords to attempt access to accounts."],
  "T1110.003": ["Brute Force: Password Spraying", ["Credential Access"], "Adversaries may use a single or small list of commonly used passwords against many different accounts."],
  "T1078": ["Valid Accounts", ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"], "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining access."],
  "T1078.004": ["Valid Accounts: Cloud Accounts", ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"], "Adversaries may obtain and abuse credentials of a cloud account to gain access to cloud resources."],
  "T1190": ["Exploit Public-Facing Application", ["Initial Access"], "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to gain initial access."],
  "T1133": ["External Remote Services", ["Persistence", "Initial Access"], "Adversaries may leverage external-facing remote services such as VPNs to initially access and persist within a network."],
  "T1059.001": ["Command and Scripting Interpreter: PowerShell", ["Execution"], "Adversaries may abuse PowerShell commands and scripts for execution."],
  "T1059.004": ["Command and Scripting Interpreter: Unix Shell", ["Execution"], "Adversaries may abuse Unix shell commands and scripts for execution."],
  "T1003.001": ["OS Credential Dumping: LSASS Memory", ["Credential Access"], "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service."],
  "T1021.001": ["Remote Services: Remote Desktop Protocol", ["Lateral Movement"], "Adversaries may use valid accounts to log into a computer using the Remote Desktop Protocol."],
  "T1021.002": ["Remote Services: SMB/Windows Admin Shares", ["Lateral Movement"], "Adversaries may use valid accounts to interact with a remote network share using Server Message Block."],
  "T1569.002": ["System Services: Service Execution", ["Execution"], "Adversaries may abuse the Windows service control manager to execute malicious commands or payloads."],
  "T1486": ["Data Encrypted for Impact", ["Impact"], "Adversaries may encrypt data on target systems to interrupt availability to system and network resources."],
  "T1490": ["Inhibit System Recovery", ["Impact"], "Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system."],
  "T1071.001": ["Application Layer Protocol: Web Protocols", ["Command and Control"], "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection."],
  "T1568.002": ["Dynamic Resolution: Domain Generation Algorithms", ["Command and Control"], "Adversaries may make use of Domain Generation Algorithms to dynamically identify a destination domain for command and control."],
  "T1105": ["Ingress Tool Transfer", ["Command and Control"], "Adversaries may transfer tools or other files from an external system into a compromised environment."],
  "T1136.001": ["Create Account: Local Account", ["Persistence"], "Adversaries may create a local account to maintain access to victim systems."],
  "T1098": ["Account Manipulation", ["Persistence", "Privilege Escalation"], "Adversaries may manipulate accounts to maintain and/or elevate access to victim systems."],
  "T1098.001": ["Account Manipulation: Additional Cloud Credentials", ["Persistence", "Privilege Escalation"], "Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access."],
  "T1053.003": ["Scheduled Task/Job: Cron", ["Execution", "Persistence", "Privilege Escalation"], "Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code."],
  "T1053.005": ["Scheduled Task/Job: Scheduled Task", ["Execution", "Persistence", "Privilege Escalation"], "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution."],
  "T1070.001": ["Indicator Removal: Clear Windows Event Logs", ["Defense Evasion"], "Adversaries may clear Windows Event Logs to hide the activity of an intrusion."],
  "T1070.004": ["Indicator Removal: File Deletion", ["Defense Evasion"], "Adversaries may delete files left behind by the actions of their intrusion activity."],
  "T1562.001": ["Impair Defenses: Disable or Modify Tools", ["Defense Evasion"], "Adversaries may modify and/or disable security tools to avoid possible detection of their malware and activities."],
  "T1505.003": ["Server Software Component: Web Shell", ["Persistence"], "Adversaries may backdoor web servers with web shells to establish persistent access to systems."],
  "T1046": ["Network Service Discovery", ["Discovery"], "Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation."],
  "T1595": ["Active Scanning", ["Reconnaissance"], "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting."],
  "T1566.001": ["Phishing: Spearphishing Attachment", ["Initial Access"], "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems."],
  "T1566.002": ["Phishing: Spearphishing Link", ["Initial Access"], "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems."],
  "T1204.002": ["User Execution: Malicious File", ["Execution"], "An adversary may rely upon a user opening a malicious file in order to gain execution."],
  "T1027": ["Obfuscated Files or Information", ["Defense Evasion"], "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents."],
  "T1548.003": ["Abuse Elevation Control Mechanism: Sudo and Sudo Caching", ["Privilege Escalation", "Defense Evasion"], "Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges."],
  "T1068": ["Exploitation for Privilege Escalation", ["Privilege Escalation"], "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges."],
  "T1048": ["Exfiltration Over Alternative Protocol", ["Exfiltration"], "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel."],
  "T1567": ["Exfiltration Over Web Service", ["Exfiltration"], "Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel."],
  "T1530": ["Data from Cloud Storage", ["Collection"], "Adversaries may access data from cloud storage."],
  "T1611": ["Escape to Host", ["Privilege Escalation"], "Adversaries may break out of a container to gain access to the underlying host."],
  "T1565.001": ["Data Manipulation: Stored Data Manipulation", ["Impact"], "Adversaries may insert, delete, or manipulate data at rest in order to influence external outcomes or hide activity."],
  "T1547.001": ["Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", ["Persistence", "Privilege Escalation"], "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key."],
  "T1052.001": ["Exfiltration Over Physical Medium: Exfiltration over USB", ["Exfiltration"], "Adversaries may attempt to exfiltrate data over a USB connected physical device."],
  "T1055": ["Process Injection", ["Defense Evasion", "Privilege Escalation"], "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges."],
  "T1210": ["Exploitation of Remote Services", ["Lateral Movement"], "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network."],
  "T1219": ["Remote Access Software", ["Command and Control"], "An adversary may use legitimate desktop support and remote access software to establish an interactive command and control channel."],
  "T1087": ["Account Discovery", ["Discovery"], "Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a compromised environment."],
  "T1550.002": ["Use Alternate Authentication Material: Pass the Hash", ["Defense Evasion", "Lateral Movement"], "Adversaries may pass the hash using stolen password hashes to move laterally within an environment."],
  "T1558.003": ["Steal or Forge Kerberos Tickets: Kerberoasting", ["Credential Access"], "Adversaries may abuse a valid Kerberos ticket-granting ticket or sniff network traffic to obtain a ticket-granting service ticket."],
  "T1649": ["Steal or Forge Authentication Certificates", ["Credential Access"], "Adversaries may steal or forge certificates used for authentication to access remote systems or resources."],
  "T1621": ["Multi-Factor Authentication Request Generation", ["Credential Access"], "Adversaries may attempt to bypass multi-factor authentication mechanisms by generating MFA push notifications to the user."],
  "T1005": ["Data from Local System", ["Collection"], "Adversaries may search local system sources to find files of interest and sensitive data prior to exfiltration."]
};

const GROUP_ROWS = [
  ["G0007", "APT28", ["Fancy Bear", "Sofacy", "STRONTIUM"], "Threat group attributed in public reporting to Russian military intelligence; targets governments, militaries and security organizations."],
  ["G0016", "APT29", ["Cozy Bear", "NOBELIUM", "The Dukes"], "Threat group attributed in public reporting to Russian foreign intelligence; known for long-running espionage against governments and technology providers."],
  ["G0096", "APT41", ["Wicked Panda", "Double Dragon"], "Threat group that carries out both state-sponsored espionage and financially motivated activity."],
  ["G0032", "Lazarus Group", ["Hidden Cobra", "ZINC"], "Threat group attributed in public reporting to North Korea; known for destructive attacks and cryptocurrency theft."],
  ["G0046", "FIN7", ["Carbon Spider", "Sangria Tempest"], "Financially motivated group known for targeting point-of-sale systems and, later, ransomware affiliate activity."],
  ["G0037", "FIN6", ["Skeleton Spider", "ITG08"], "Financially motivated group that has stolen payment card data and deployed ransomware."],
  ["G1015", "Scattered Spider", ["UNC3944", "Octo Tempest"], "English-speaking financially motivated group known for social engineering of help desks, SIM swapping and MFA fatigue."],
  ["G0034", "Sandworm Team", ["Voodoo Bear", "IRIDIUM"], "Destructive threat group attributed in public reporting to Russian military intelligence."],
  ["G0010", "Turla", ["Snake", "Venomous Bear"], "Long-running espionage group known for sophisticated implants and satellite-based command and control."],
  ["G0049", "OilRig", ["APT34", "Helix Kitten"], "Threat group attributed in public reporting to Iran; targets Middle East financial, government and energy sectors."],
  ["G0069", "MuddyWater", ["Seedworm", "Static Kitten"], "Threat group attributed in public reporting to Iran's intelligence ministry; targets telecommunications and government."],
  ["G0094", "Kimsuky", ["Velvet Chollima", "Black Banshee"], "Threat group attributed in public reporting to North Korea; focuses on intelligence gathering."],
  ["G0102", "Wizard Spider", ["Grim Spider", "UNC1878"], "Financially motivated group behind TrickBot, BazarLoader and Ryuk/Conti ransomware operations."],
  ["G1017", "Volt Typhoon", ["Bronze Silhouette", "Vanguard Panda"], "Threat group that pre-positions in critical infrastructure networks using living-off-the-land techniques."],
  ["G0092", "TA505", ["Hive0065", "Graceful Spider"], "Financially motivated group known for large-scale phishing campaigns and Clop ransomware."],
  ["G0047", "Gamaredon Group", ["Primitive Bear", "Armageddon"], "Threat group attributed in public reporting to Russian security services; targets Ukrainian organizations."],
  ["G0059", "Magic Hound", ["Charming Kitten", "APT35"], "Threat group attributed in public reporting to Iran; targets researchers, journalists and government officials."],
  ["G0008", "Carbanak", ["Anunak"], "Financially motivated group that has stolen funds from banks via targeted intrusions."],
  ["G0045", "menuPass", ["APT10", "Stone Panda"], "Threat group attributed in public reporting to China; targets managed service providers and their clients."],
  ["G0035", "Dragonfly", ["Energetic Bear", "Berserk Bear"], "Threat group that targets the energy sector, using supply-chain and watering-hole attacks."]
];

const DECODER_ROWS = [
  ["sshd", "sshd"], ["sudo", "sudo"], ["pam", "pam"], ["syslog", "syslog"], ["nginx-errorlog", "nginx"], ["web-accesslog", "nginx"], ["apache-errorlog", "apache2"],
  ["windows_eventchannel", ""], ["json", ""], ["syscheck_new_entry", ""], ["syscheck_integrity_changed", ""], ["rootcheck", ""], ["ossec", "ossec"],
  ["suricata", ""], ["postgresql_log", "postgres"], ["mysql_log", "mysqld"], ["postfix", "postfix"], ["dovecot", "dovecot"], ["openvpn", "openvpn"], ["kernel", "kernel"],
  ["auditd", "audit"], ["docker", "dockerd"], ["aws-cloudtrail", ""], ["kubernetes-audit", ""], ["vpn-gateway", "vpnd"]
];

function rulesList() {
  return RULE_ROWS.map(([, id, level, description, groups, mitre, filename]) => {
    const t = mitre.map((m) => MITRE[m]).filter(Boolean);
    return {
      id, level, description, groups, filename, relative_dirname: filename === "local_rules.xml" ? "etc/rules" : "ruleset/rules", status: "enabled",
      details: {}, pci_dss: groups.includes("pci_dss_11.5") ? ["11.5"] : [], gdpr: [], hipaa: [], nist_800_53: [], tsc: [],
      mitre: { id: mitre, tactic: [...new Set(t.flatMap((x) => x[1]))], technique: t.map((x) => x[0]) }
    };
  });
}
const techniques = () => Object.entries(MITRE).map(([id, [name, tactics, description]]) => ({ id: `attack-pattern--${id.toLowerCase().replace(".", "-")}`, external_id: id, name, description, tactics, platforms: ["Windows", "Linux", "macOS"] }));
const mitreGroups = () => GROUP_ROWS.map(([external_id, name, aliases, description]) => ({ id: `intrusion-set--${external_id.toLowerCase()}`, external_id, name, description, aliases }));
const decoders = () => DECODER_ROWS.map(([name, program], i) => ({ name, position: i % 3, details: program ? { program_name: program } : {}, filename: `${String(i).padStart(4, "0")}-${name.split("-")[0]}_decoders.xml`, relative_dirname: "ruleset/decoders", status: "enabled" }));

const MANAGER = {
  info: { version: "v4.9.2", name: "wazuh-manager-mum", type: "master", compilation_date: "2024-11-20T09:12:41Z", max_agents: "unlimited", openssl_support: "yes", ruleset_version: "v4.9.2", tz_offset: "+0000", tz_name: "UTC" },
  status: { "wazuh-agentlessd": "stopped", "wazuh-analysisd": "running", "wazuh-authd": "running", "wazuh-csyslogd": "stopped", "wazuh-dbd": "stopped", "wazuh-monitord": "running", "wazuh-execd": "running", "wazuh-integratord": "running", "wazuh-logcollector": "running", "wazuh-maild": "stopped", "wazuh-remoted": "running", "wazuh-reportd": "stopped", "wazuh-syscheckd": "running", "wazuh-clusterd": "running", "wazuh-modulesd": "running", "wazuh-db": "running", "wazuh-apid": "running" },
  nodes: [
    { name: "wazuh-manager-mum", type: "master", version: "4.9.2", ip: "10.20.9.10" },
    { name: "worker-mum", type: "worker", version: "4.9.2", ip: "10.20.9.11" },
    { name: "worker-fra", type: "worker", version: "4.9.2", ip: "10.20.9.12" }
  ]
};
const managerStats = () => Array.from({ length: 24 }, (_, h) => ({ hour: h, alerts: [{ sigid: 5710, level: 5, times: 40 + h * 3 }], totalAlerts: 90 + ((h * 37) % 140), events: 4000 + ((h * 211) % 1800), syscheck: 20 + (h % 9), firewall: 0 })).map((x) => ({ ...x, generatedAt: iso(Date.now()) }));

module.exports = { RULE_ROWS, GROUP_ROWS, MITRE, rulesList, techniques, mitreGroups, decoders, MANAGER, managerStats };
