# Day 5 acceptance checklist (Greenbone findings, remediation, retest)

[x] = verified against the bridge running on the `gvm-cli` **test double**, the demo bridge (`npm run demo:integrations`) and, for the sign-in, real Keycloak identities. No real Greenbone was involved and nothing was ever scanned.
"Needs your Greenbone" items can only be confirmed against a real deployment.

This workflow **records** work. It never fixes anything and never changes a target. A retest is a request for a new authorized scan that goes through the same scope, audit and rate-limit path as any other scan.

## Import and normalization
- [x] `POST /api/vapt/findings/sync` imports recent Greenbone report results. It is a **POST**, not `GET ?sync=1` as in the original package: it calls an upstream service and writes a file, so a cross-site link must not be able to trigger it. Origin is checked, `SOC_Analyst` or `SOC_Admin` is required, and syncs are rate-limited (6 per 10 minutes per user).
- [x] Findings carry host, port, severity score and label, threat, CVEs, report and result ids, description and solution.
- [x] The bridge reads each report once: the nested `<report>` wrapper that GMP uses is not double-counted (the original parser doubled every result).
- [x] CVEs are read from both GMP shapes: `nvt/refs/ref[@type='cve']` and the legacy `nvt/cve` text (`NOCVE` ignored).
- [x] An import larger than the cap (`GREENBONE_MAX_FINDINGS`, default 2000) says it was **truncated** instead of silently dropping results, and a truncated import never flags anything as missing.
- [x] Finding ids are `sha256(host | port | NVT oid)`, not a 32-bit hash: 100,000 distinct findings produced zero collisions in the unit test, and a feed update that **renames** an NVT keeps the same finding and its remediation history.
- [x] A repeated sync creates no duplicates and preserves status, owner, notes and retest data.
- [x] The same result appearing in several reports collapses into one finding.

## Retest verification (the part the original could not do)
- [x] For each host, only its **most recent report** counts as current. A finding seen in an older report of that host but absent from its latest report is flagged **Not in latest scan** ("may be fixed: verify before closing"). Verified end to end: a retest of one host flagged exactly its two fixed findings and nothing on any other host.
- [x] Flagged findings keep their status, owner, notes and retest data. **Nothing is ever closed automatically.**
- [x] A finding that comes back in a newer scan is un-flagged.

## Remediation workflow
- [x] `PATCH /api/vapt/findings/{id}` updates status, owner and notes. Only the fields present in the request change: a status-only update **no longer erases the owner and notes** (the original did). Any other key in the request (severity, host, id, CVEs) is ignored.
- [x] Invalid statuses are rejected by the server. Finding ids must match `vuln_` + 16 hex characters.
- [x] **Close rule:** a finding can be closed only after a retest was requested for it, or by a `SOC_Admin` who writes a justification (at least 10 characters) in the notes. An analyst's long note does not unlock closing.
- [x] **Edit conflicts:** each edit carries the `updatedAt` it was based on. If someone else saved in between, the second save is refused (409) with a message instead of silently overwriting their work. 40 simultaneous edits to different findings were all kept.
- [x] `SOC_ReadOnly` can view findings but cannot sync, edit or request a retest (403).
- [x] Notes and owner are length-capped. Scanner text is rendered as plain text (never as HTML).

## Retest
- [x] `POST /api/vapt/findings/{id}/retest` goes through the **same** `startAuthorizedScan()` as a normal scan: the host must be inside a current approved scope (otherwise 403, audited with the finding id), the audit event is written **before** Greenbone is called, and the scan rate limit applies. The original wrote its audit event after the scan had started and skipped these guards.
- [x] A revoked or expired scope blocks the retest immediately.
- [x] A successful retest marks the finding "Retest Required" with the task id and time.

## Audit
- [x] Sync, update and retest requests are audited. Updates record which fields changed and the status change, **never the note text**. Retest scans are tagged with the finding id. The VAPT workspace shows these events.

## UI
- [x] `/vapt/findings`: summary tiles, search (every word must match, in any order), status and severity filters, a "Not in latest scan only" filter, per-finding status/owner/notes, expandable evidence and solution, "Request retest", "Show more" paging. Exercised in a real browser: sync, edit, retest, re-sync and verification.

## Tests
- [x] 71 unit tests for findings (`npm run test:findings`): id stability and collisions, normalization, merge, the per-host rule, partial updates, the close rule, conflicts and concurrent writes. `npm test` runs all 144 unit tests.
- [x] 55 end-to-end API checks across all three roles. The earlier regression suites (21 role checks, 16 audit/rollback checks, launch timeout, Wazuh-down) and the real-Keycloak runs (21 + 9) still pass after the scan path was refactored.

## Needs your Greenbone
- [ ] A completed Greenbone scan with a report, and feeds synchronized.
- [ ] `get_reports` options confirmed on your version: the bridge asks for `details="1" ignore_pagination="1"` and reads `nvt/refs`, `nvt/cve`, `nvt/solution`, `threat`, `severity` and `creation_time`. This matches the GMP documentation and a test double, **not** a live Greenbone. Field layout varies across releases.
- [ ] Reports arrive newest first (`sort-reverse=creation_time`): the per-host "latest report" rule depends on it.
- [ ] Large reports fit within the bridge's command timeout (`GREENBONE_COMMAND_TIMEOUT`, default 45 s) and the app's sync timeout (`GREENBONE_SYNC_TIMEOUT_MS`, default 60 s). Tune `GREENBONE_REPORT_ROWS` (default 25) and `GREENBONE_MAX_FINDINGS` if not.
- [ ] Hostnames: a retest needs an IPv4 host. A finding whose host is a hostname cannot be retested from here (the request is refused with a clear message).

## Known limitations
- The sync imports **every** result the bridge's Greenbone account can see, including scans not started from PrimeSEC. Use a dedicated, least-privilege GMP account.
- A retest scans the whole host, not just the one vulnerability.
- Findings are a local file (`data/vapt-findings.json`, git-ignored), serialised within one server process. Use a database before running more than one process (a second process could lose an update), and add a tamper-evident audit store.
- "Not in latest scan" is a hint from scan results. It does not prove the vulnerability is fixed (for example a scan that could not reach the host would also omit it): review the new report before resolving.
- Scanner output is evidence for analyst triage, not proof that an asset is compromised.
