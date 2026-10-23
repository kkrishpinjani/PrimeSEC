/**
 * Sample data for demos. It goes through the SAME code paths as a real import (syncFindings, captureSnapshots,
 * updateFinding, updateAsset), so what you see on /vapt/findings and /risk is exactly what a real scan would produce:
 * a baseline report covering three hosts, then a retest that rescanned only one of them.
 *
 * It is clearly labelled as sample data, makes no network call, and creates no scan scope: a retest of a sample
 * finding still needs a real approved scope, like any other scan. The API only offers it when DEMO_LOGIN is on.
 */
import { clearFindings, markRetestRequested, readFindings, syncFindings, updateFinding, type RawFinding } from "./findings.ts";
import { clearAssets, updateAsset } from "./assets.ts";
import { captureSnapshots, clearSnapshots } from "./reports.ts";

export const BASELINE_REPORT = "sample-report-1-baseline";
export const RETEST_REPORT = "sample-report-2-retest";
const HOSTS = ["10.50.1.10", "10.50.1.11", "10.50.1.12"];

type Seed = Omit<RawFinding, "reportId" | "resultId" | "taskName" | "reportIndex" | "creationTime"> & { key: string };
const f = (key: string, host: string, port: string, name: string, severity: number, threat: string, cves: string[], description: string, solution: string): Seed =>
  ({ key, host, port, name, severity, threat, cves, description, solution, oid: `sample-nvt-${key}` });

const SEEDS: Seed[] = [
  f("apache", "10.50.1.10", "80/tcp", "Apache HTTP Server path traversal (sample)", 9.8, "High", ["CVE-2021-41773"], "Sample finding: the web server version is affected by a path traversal flaw.", "Update Apache HTTP Server to a fixed release."),
  f("tls10", "10.50.1.10", "443/tcp", "TLS 1.0 protocol enabled (sample)", 5.3, "Medium", [], "Sample finding: the service accepts the deprecated TLS 1.0 protocol.", "Disable TLS 1.0 and 1.1; allow TLS 1.2 or newer."),
  f("sshenum", "10.50.1.10", "22/tcp", "OpenSSH username enumeration (sample)", 5.3, "Medium", ["CVE-2018-15473"], "Sample finding: the SSH server reveals whether a username exists.", "Upgrade OpenSSH."),
  f("banner", "10.50.1.10", "80/tcp", "HTTP server banner disclosure (sample)", 0, "Log", [], "Sample informational result: the server reveals its software and version.", "Optional: hide the version banner."),
  f("mysql", "10.50.1.11", "3306/tcp", "Database default credentials (sample)", 9.0, "High", [], "Sample finding: the database accepts a vendor default account.", "Change the default credentials and restrict network access."),
  f("pgsql", "10.50.1.11", "5432/tcp", "PostgreSQL outdated version (sample)", 6.5, "Medium", ["CVE-2023-5868"], "Sample finding: the PostgreSQL version is affected by a known flaw.", "Update PostgreSQL to a fixed release."),
  f("sshalgo", "10.50.1.11", "22/tcp", "SSH weak algorithms supported (sample)", 4.3, "Medium", [], "Sample finding: the SSH server offers weak encryption algorithms.", "Disable weak ciphers and MACs."),
  f("smb1", "10.50.1.12", "445/tcp", "SMBv1 protocol enabled (sample)", 8.1, "High", ["CVE-2017-0144"], "Sample finding: the legacy SMBv1 protocol is enabled.", "Disable SMBv1 and apply vendor patches."),
  f("samba", "10.50.1.12", "445/tcp", "Samba outdated version (sample)", 7.5, "High", ["CVE-2021-44142"], "Sample finding: the Samba version is affected by a known flaw.", "Update Samba to a fixed release."),
  f("ftpanon", "10.50.1.12", "21/tcp", "FTP anonymous login allowed (sample)", 6.4, "Medium", [], "Sample finding: the FTP server allows anonymous access.", "Disable anonymous FTP."),
  f("telnet", "10.50.1.12", "23/tcp", "Telnet service enabled (sample)", 5.8, "Medium", [], "Sample finding: Telnet sends credentials in clear text.", "Disable Telnet; use SSH."),
  f("icmp", "10.50.1.12", "general/icmp", "ICMP timestamp reply (sample)", 2.1, "Low", ["CVE-1999-0524"], "Sample finding: the host answers ICMP timestamp requests.", "Filter ICMP timestamp requests.")
];

const raw = (s: Seed, reportId: string, taskName: string, reportIndex: number): RawFinding => {
  const { key, ...rest } = s;
  return { ...rest, reportId, resultId: `${reportId}-${key}`, taskName, reportIndex, creationTime: null };
};

const SAMPLE_ACTOR = { name: "Sample data", email: "sample-data@primesec.local", roles: ["SOC_Admin"] };

export type SeedResult = { findings: number; reports: number; hosts: number };

/** Throws if findings already exist: sample data is never mixed into a real or earlier import. */
export async function seedDemoData(): Promise<SeedResult> {
  if ((await readFindings()).length > 0) throw new Error("Findings already exist. Delete the current findings data first, then load the sample data.");
  const day = 86_400_000;
  const t1 = new Date(Date.now() - 2 * day).toISOString();
  const t2 = new Date().toISOString();

  // 1) Baseline scan of all three hosts.
  const baseline = SEEDS.map((s) => raw(s, BASELINE_REPORT, "Sample: lab baseline scan", 0));
  await syncFindings(baseline, { now: t1 });
  await captureSnapshots(baseline, {
    now: t1, completedReports: [BASELINE_REPORT],
    reports: [{ id: BASELINE_REPORT, status: "Done", scannedHosts: HOSTS, timestamp: t1 }]
  });

  // 2) Retest of 10.50.1.10 only: Apache and TLS 1.0 are gone, the rest is still reported. The import carries both
  //    reports, as the real bridge does (reportIndex 0 = newest).
  const retestHost = HOSTS[0];
  const retest = SEEDS.filter((s) => s.host === retestHost && !["apache", "tls10"].includes(s.key)).map((s) => raw(s, RETEST_REPORT, "Sample: retest of 10.50.1.10", 0));
  const older = baseline.map((r) => ({ ...r, reportIndex: 1 }));
  await syncFindings([...retest, ...older], { now: t2 });
  await captureSnapshots([...retest, ...older], {
    now: t2, completedReports: [BASELINE_REPORT, RETEST_REPORT],
    reports: [
      { id: RETEST_REPORT, status: "Done", scannedHosts: [retestHost], timestamp: t2 },
      { id: BASELINE_REPORT, status: "Done", scannedHosts: HOSTS, timestamp: t1 }
    ]
  });

  // 3) The analyst's work: host context, exploit evidence, ownership, and the retest that was requested.
  await updateAsset(HOSTS[0], { criticality: "Critical", exposure: "Internet-facing" }, SAMPLE_ACTOR);
  await updateAsset(HOSTS[1], { criticality: "High", exposure: "Internal" }, SAMPLE_ACTOR);
  await updateAsset(HOSTS[2], { criticality: "Medium", exposure: "Internal" }, SAMPLE_ACTOR);
  const all = await readFindings();
  const idOf = (key: string) => all.find((x) => x.oid === `sample-nvt-${key}`)!.id;
  await updateFinding(idOf("apache"), { exploitEvidence: "Exploited in the wild" }, SAMPLE_ACTOR);
  await updateFinding(idOf("mysql"), { exploitEvidence: "Public exploit", remediationStatus: "In Progress", owner: "database team" }, SAMPLE_ACTOR);
  await updateFinding(idOf("smb1"), { exploitEvidence: "Public exploit", remediationStatus: "In Progress", owner: "infra team" }, SAMPLE_ACTOR);
  await markRetestRequested(idOf("apache"), "sample-task-retest", SAMPLE_ACTOR);
  await markRetestRequested(idOf("tls10"), "sample-task-retest", SAMPLE_ACTOR);

  return { findings: SEEDS.length, reports: 2, hosts: HOSTS.length };
}

/** Deletes findings, host context and report snapshots. Scopes and the audit log are deliberately kept. */
export async function clearAllFindingData(): Promise<{ findings: number; assets: number; reports: number }> {
  const [findings, assets, reports] = [await clearFindings(), await clearAssets(), await clearSnapshots()];
  return { findings, assets, reports };
}
