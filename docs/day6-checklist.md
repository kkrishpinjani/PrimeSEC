# Day 6 acceptance checklist (risk prioritisation and retest validation)

[x] = verified against the bridge running on the `gvm-cli` **test double**, the demo bridge (`npm run demo:integrations`) and, for sign-in and roles, real Keycloak identities. No real Greenbone was involved and nothing was ever scanned.
"Needs your Greenbone" items can only be confirmed against a real deployment.

This is analysis only. It scores and compares; it never scans, never changes a host and never closes a finding.

## Risk score (`/risk`, `GET /api/risk/queue`)
- [x] Available to any PrimeSEC role; unauthenticated requests get 401.
- [x] Weighted, explainable score: severity 30%, exploit evidence 25%, asset criticality 20%, exposure 15%, corroborating detection 10%. Every finding shows each factor, its value, weight, contribution and **where the value comes from**.
- [x] **Unknown is not zero.** Unknown factors are excluded and the remaining weights renormalised, and the score shows (a) confidence, the share of weight that is known, and (b) a **range**: what it would be if every unknown factor were 0 or 100. Findings are ranked by score, then by the top of the range, so missing context can never hide a potentially urgent finding.
- [x] Severity 0.0 (an informational "Log" result) is a **known** low severity, not missing data. *The original treated it as unknown and renormalised it, so an informational finding on a critical host could outrank real vulnerabilities.* Such findings are also capped at Low (20), so host importance alone never makes a non-vulnerability urgent. A real low severity (for example 2.1) on a critical, exposed host is **not** capped: context may legitimately raise it.
- [x] Raising severity never lowers a score (3,000 random inputs), and the range always brackets the score.
- [x] **Resolved and Closed findings leave the queue** (`?all=1` or the checkbox brings them back).
- [x] Scores are labelled a triage aid, not an exploitation probability and not a CVSS replacement.
- [x] A "May be fixed" flag (Day 5's per-host rule) is shown on findings absent from their host's latest scan.

## Asset context (host criticality and exposure)
- [x] Stored **once per host** (`data/vapt-assets.json`) and applied to every finding on it. *The original asked for both fields on every individual finding.*
- [x] `PATCH /api/vapt/assets`: `SOC_Analyst` or `SOC_Admin`, origin-checked. Only values from the fixed lists are accepted; only hosts that have findings can be classified (no junk records); edit conflicts are refused (409).
- [x] Every change is audited with the **old and new values**, because lowering a host's criticality lowers the priority of every finding on it.
- [x] `SOC_ReadOnly` can view but not edit (403).

## Exploit evidence
- [x] The 25% "exploit evidence" factor had **no data source** in the original (it read fields nothing ever set, so it was permanently unknown). It is now recorded by an analyst per finding (`Unknown`, `None known`, `Public exploit`, `Exploited in the wild`), validated, preserved across syncs and audited (field name only). Example sources: CISA KEV, a vendor advisory.
- [ ] The 10% "corroborating detection" factor still has **no automated source** and stays unknown. It is shown as unknown, never as zero. (Candidate source: Wazuh. Not built.)

## Report snapshots (`GET /api/vapt/reports`)
- [x] Each sync records one snapshot per Greenbone report, including a **clean scan with zero results** (the original could not represent one). A result without a report id creates no snapshot.
- [x] A snapshot stores whether Greenbone marked the report finished, **which hosts it really scanned**, and the finding ids. A finished report is frozen: a later partial read cannot weaken it. Capped at 200.
- [x] A **capped (truncated) import never marks any report complete**, even if Greenbone says Done.

## Comparison (`GET /api/vapt/reports/compare?baseline=&retest=`)
- [x] Read-only, any role, never changes anything; each view is audited with the summary.
- [x] Outcomes: **FIXED** only if absent from a report Greenbone marked Done **and** that report shows the host was scanned. **STILL_PRESENT** if the same finding (same host, port and NVT) is in the retest. Otherwise **INCONCLUSIVE**, with the reason: report not complete, host not confirmed scanned, or import capped.
- [x] **A host that was down is never "fixed".** A finished scan that never reached a host reports nothing for it, so the original's "Done + absent = fixed" rule would have called every finding on a down host fixed. Verified: with the host down, 0 fixed and every finding inconclusive.
- [x] Findings are matched by the stable finding id (host, port, NVT), not by CVE list or name, so a feed update that renames an NVT or adds a CVE no longer makes a still-present finding look fixed.
- [x] New findings in the retest are listed; severity change of a still-present finding is reported; warns if the retest is older than the baseline or the baseline is not complete.
- [x] Nothing is closed automatically. Verified: no finding status changes after a comparison.

## Bridge
- [x] `GET /v1/findings` now also returns `reports` (status, hosts actually scanned, timestamp per report) and `completedReports` (ids Greenbone marks `Done`, empty for a capped import). An older bridge without them still works: nothing can then be called complete.
- [ ] `scan_run_status` per report and the `<host><ip>` / `<end>` entries confirmed against your Greenbone version. This matches the GMP documentation and the test double, **not** a live Greenbone. If your layout differs, `scannedHosts` is null and every absence stays inconclusive (the safe direction).

## UI and tests
- [x] `/risk`: summary, host context editor, ranked queue with a "why this score?" breakdown (unknown factors highlighted), exploit-evidence control, report comparison with explanations, methodology. Exercised in a real browser.
- [x] 55 risk/asset unit tests (`npm run test:risk`), 41 report/comparison unit tests (`npm run test:reports`); `npm test` runs all 240.
- [x] 59 end-to-end API checks plus a "host was down" scenario (8 checks) across all three roles. All earlier suites and the real-Keycloak runs (21 + 9) still pass.

## Known limitations
- Scores are a prioritisation aid built from a handful of inputs. They are not a risk assessment, and two of five inputs are analyst-entered judgments.
- Two inputs (host context, exploit evidence) are typed in by people, so they can be wrong or stale. Changes are audited, but not otherwise reviewed or approved.
- "Fixed" proves only that a finished scan that reached the host did not report the finding. A scan can miss a vulnerability (credentials, filtering, scan configuration); review the new report before resolving.
- Snapshots, assets and findings are local files serialised within one server process (see Day 5).

## Sample data and delete (added after Day 6)
- [x] **Load sample data** (Findings page, SOC_Admin, only while `DEMO_LOGIN=true`; refused in a production build): 12 labelled "(sample)" findings on three hosts, a baseline report and a retest of one host, host context, exploit evidence and owners. It goes through the real sync/snapshot code, so `/risk` shows the real ranking and a comparison of 2 fixed / 2 still present / 8 inconclusive. It makes no network call and creates **no scan scope**: a retest of a sample finding still needs a real approved scope.
- [x] **Delete all findings data** (SOC_Admin, any environment, needs `{"confirm":"DELETE"}`): removes findings, host context and report snapshots. Scopes and the audit log are kept. Greenbone is untouched, so findings it still reports come back on the next sync.
- [x] **Delete** on a single finding (SOC_Admin). Removes its remediation history; audited with host, port and name (never notes).
- [x] Audited as `vapt_demo_data_seeded`, `vapt_finding_deleted`, `vapt_data_cleared`. 22 unit tests (`npm run test:demodata`) and 28 API checks (roles, origin, confirm, 409 on double seed).
