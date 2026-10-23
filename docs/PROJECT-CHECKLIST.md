# PrimeSEC project checklist (Day 1 to Day 4)

Last verified: 2026-10-21 (including a real Keycloak run and an independent code review, both done).

**Legend**
- `[x]` **Done and verified** in this environment (tests, real Keycloak users, or a real browser).
- `[~]` **Built and tested against a stand-in only** (the demo server or the `gvm-cli` test double). The code path is real; it has not met the real platform.
- `[ ]` **Open**: needs your input, your platforms, or a decision. Not something that can be finished from the repo alone.

## Bottom line

| Day | Code | Fully complete? |
|---|---|---|
| 1 Identity | Built and verified | **No.** Wazuh single sign-on (4 items) is open. |
| 2 Wazuh + OpenCTI | Built, verified on demo data | **No.** Never run against a real Wazuh or OpenCTI. |
| 3 Investigation | Built, verified on demo data | **No.** Same dependency on real Wazuh/OpenCTI. |
| 4 Greenbone VAPT | Built, verified on a test double | **No.** Never run against a real Greenbone. |
| 5 Findings, remediation, retest | Built, verified on a test double and demo bridge | **No.** Never run against a real Greenbone report. |
| 6 Risk and validation | Built, verified on a test double and demo bridge | **No.** Never run against a real Greenbone report; one input factor has no source. |

Everything that can be finished and verified without your platforms is finished.

---

## Day 1: Identity foundation

### Keycloak and sign-in
- [x] Keycloak container starts and imports the `primesoc` realm (realm discovery URL answers; realm survives a container recreate).
- [x] Original realm import bug fixed: the custom `clientScopes` block broke every sign-in with `invalid_scope`.
- [x] Real Keycloak users can sign in (`socadmin`, plus throwaway users). Re-run after the Next 15 / next-auth upgrade and after the review fixes: 21 of 21 role/flow checks pass, plus 9 of 9 sign-out checks.
- [x] Roles `SOC_Admin` / `SOC_Analyst` / `SOC_ReadOnly` reach the app (`realm_access.roles`) and are shown in the dashboard.
- [x] A user with no PrimeSEC role is redirected to `/403` and gets 403 from every API.
- [x] `/dashboard` redirects to `/login` when signed out; sign-out returns to login.
- [x] `/api/health` returns 200.
- [x] **Sign out really signs out:** it ends the Keycloak SSO session too (RP-initiated logout), so "Continue with Keycloak" asks for a password again. Verified against real Keycloak, with a control showing the old behaviour silently signed you back in.
- [x] Keycloak is bound to `127.0.0.1:8080`; post-logout redirect restricted to `/login` (was a wildcard).
- [x] `NEXTAUTH_SECRET` guard: authentication is refused when the secret is missing or still the placeholder.
- [x] Renamed to PrimeSEC everywhere user-visible (realm and client IDs `primesoc` / `primesoc-web` intentionally kept, since renaming breaks the import).
- [x] Frontend on port 3010 (`package.json`, `.env`, realm file, live Keycloak client).
- [x] Demo login with **one button per role** (Admin / Analyst / Read-only), each its own identity, opt-in via `DEMO_LOGIN`. Verified: roles behave correctly side by side, an unknown or spoofed role never elevates, `DEMO_LOGIN=false` turns it fully off, and a production server ignores `DEMO_LOGIN=true` entirely.
- [~] `scripts/setup.ps1` / `setup.sh` generate secrets: the PowerShell script was only syntax-checked, neither was run end to end.

### Wazuh single sign-on (the actual goal of Day 1)
- [ ] `WAZUH_DASHBOARD_URL` set to the real HTTPS host.
- [ ] Wazuh SAML client and role mapping configured (version-matched official guide).
- [ ] Wazuh opens from PrimeSEC without a second credential prompt.
- [ ] Admin and read-only users have distinct Wazuh permissions.

---

## Day 2: Wazuh + OpenCTI integration

### Built and verified (demo server)
- [x] Server-side adapters: Wazuh Manager API, Wazuh Indexer, Wazuh Vulnerability Detector index, OpenCTI GraphQL (typed port of the Day 2 package).
- [x] The Manager API and the Indexer are queried **independently**: a Manager outage no longer hides live Indexer alerts, vulnerabilities or investigations (found by the code review; verified).
- [x] The raw Wazuh JWT is read as text, not truncated at 500 characters (found by the code review; verified with a 900-character token).
- [x] `GET /api/integrations/wazuh` and `/opencti`: 401 without a session, 403 without a role, `no-store`, read-only.
- [x] No upstream credential or token appears in any API response or page HTML.
- [x] Unconfigured or failing platforms show a status and labelled sample data, never a broken page. Wrong password reports "authentication failed (401)", not "unreachable".
- [x] Dashboard badge says Live / Partly live / Sample data / Demo data, and the footer explains what is sample.
- [x] Globe uses real Natural Earth geography; markers and arcs come only from geolocated alert sources (none are ever invented). Land and markers verified to share one coordinate mapping.
- [x] Alert volume, high-severity timeline, severity counts and the threat score are computed from real alert data (score formula documented on the card).
- [x] Vulnerabilities tab reads Wazuh's Vulnerability Detector index; Threat Intel shows OpenCTI scores and platform totals.
- [x] Scope chips are configuration (`PRIMESEC_TEAM` / `PRIMESEC_REGION`), hidden when unset.

### Needs real platforms
- [~] Wazuh Manager API authenticates and the agent list matches Wazuh.
- [~] Wazuh Indexer returns alert counts, hourly buckets, severity ranges and GeoIP'd sources (needs Wazuh's GeoIP decoder on `srcip` and `PRIMESEC_HOME_LAT/LON`).
- [~] Vulnerability index query works (needs Wazuh 4.8+ with the Vulnerability Detector enabled).
- [~] OpenCTI token returns indicators, reports and actors; the richer query (scores, totals) works on your OpenCTI version (the code falls back to a plain query if not).
- [ ] TLS with real certificates (self-signed CAs via `NODE_EXTRA_CA_CERTS`).
- [ ] Wazuh and OpenCTI native dashboards open from their URLs; native-UI SSO tested separately.

---

## Day 3: Alert investigation (read-only)

- [x] **Investigate** on each live Wazuh alert (disabled for sample alerts and for `SOC_ReadOnly`).
- [x] The browser sends only an alert id; the server re-reads the alert from Wazuh. Malformed ids rejected (400), unknown ids 404.
- [x] Observables (IPv4, domains, MD5/SHA-1/SHA-256) extracted from the alert; OpenCTI searched per observable; matches are **exact**, not substring.
- [x] File names and code identifiers are not mistaken for domains (`powershell.exe`, `app.config`, `System.Net.Sockets`, `Microsoft.Windows.Defender`), so junk cannot crowd real indicators out of the 25-observable cap (found by the code review; 33 unit tests).
- [x] Results labelled "Potential match: analyst validation required"; a no-match and a "nothing to search" result are worded honestly.
- [x] Roles enforced: `SOC_ReadOnly` gets 403 on creating an investigation; analyst and admin succeed (verified with real Keycloak users and via the demo role).
- [x] Cross-origin POST rejected (403); 6th investigation in a minute gets 429.
- [x] Every investigation is written to `data/audit-events.jsonl` and listed in the Investigations tab.
- [x] No automated response or remediation action exists anywhere.
- [~] Correlation behaviour confirmed against a real OpenCTI (search argument and field names), and Wazuh alert ids and `full_log`/`data` fields against a real Wazuh.

---

## Day 4: Greenbone VAPT

### Safety model (verified; 40 unit tests plus end-to-end runs)
- [x] A scan starts only inside a scope a `SOC_Admin` approved: written authorization reference (8+ chars), future expiry, **at most 90 days**, at most 10 targets.
- [x] Scope check runs server-side before the bridge is called; refused attempts are audited.
- [x] Expired, revoked, missing and **unparseable** expiry all deny (a fail-open bug in the original package, found and fixed).
- [x] IPv4 only, `/24` or narrower, **no host bits** (`10.0.0.5/24` is rejected, not widened).
- [x] Loopback, link-local (cloud metadata), multicast, reserved and unspecified ranges can never be scanned.
- [x] Public ranges need an explicit written-authorization acknowledgement and are flagged on the scope.
- [x] Scopes can be revoked; revocation applies immediately; re-revoking does not double-log.
- [x] Role rules: `SOC_ReadOnly` view only; `SOC_Analyst` scans inside a scope; only `SOC_Admin` approves/revokes.
- [x] 401 without a session, cross-origin writes rejected, launches limited to 5 per 10 minutes per user.
- [x] Approval, revocation, launch and **refused launch** are all audited and shown in the workspace.
- [x] **Audit before launch, fail closed:** a `requested` event is written before Greenbone is called; if the audit log is unavailable the scan is **not started** (503), and a timed-out or failed launch is audited as `failed` (found by the code review; verified).
- [x] An approval whose audit write fails is **rolled back**; a revocation whose audit write fails still takes effect (the safe direction) and reports `auditRecorded: false`.
- [x] The launch request has its own, longer timeout (`GREENBONE_LAUNCH_TIMEOUT_MS`, default 120 s), and a timeout says the scan may still have started so nobody blindly retries.
- [x] A corrupt or unreadable scope store fails closed (no scan authorized) and says so in the UI; errors reach the server log but never the browser (no filesystem paths leak).
- [x] The date picker's last allowed day is accepted by the server in every timezone.

### Bridge and UI
- [x] `/vapt` workspace (status, scopes, launch form, tasks, audit trail), linked from the dashboard and the Vulnerabilities tab. Forms exercised in a real browser.
- [~] Bridge (`bridge/server.py`) verified against the `gvm-cli` **test double**: token of 32+ chars required, strict target rules, optional independent allow-list (IPv4 only, validated at startup), password kept out of the process list via a config file.
- [~] A launch that fails partway removes the Greenbone target/task it already created, so retries do not litter Greenbone (verified against the test double with injected failures).
- [~] Demo bridge on `:9099` records "(demo)" tasks and scans nothing.
- [ ] Greenbone Community Edition deployed from its current official guide; feeds synced.
- [ ] gvmd socket reachable only by the bridge's service account (never world-writable).
- [ ] Scan config, port list and scanner UUIDs in `bridge/.env` match your installation.
- [ ] `gvm-cli` flags and GMP responses confirmed against your Greenbone version.
- [ ] A real task appears in Greenbone and in the PrimeSEC task list.
- [ ] Day 5 scope (not built): detailed findings, remediation workflow, retest.

---

---

## Day 5: Greenbone findings, remediation and retest

Full detail: [day5-checklist.md](day5-checklist.md). It records work; it never changes a target.

- [x] Findings import (POST, origin-checked, role-gated, rate-limited), normalized and de-duplicated with stable `sha256(host|port|oid)` ids (100,000 findings, zero collisions; a renamed NVT keeps its history).
- [x] Bridge parser reads each GMP report once (the original doubled every result), supports both CVE shapes, and reports truncation instead of silently capping.
- [x] Remediation status, owner and notes. A status-only update no longer erases owner and notes (the original did). Edit conflicts (409) instead of lost updates; 40 concurrent edits all kept.
- [x] Close rule: only after a retest was requested, or by a SOC_Admin with a written justification.
- [x] Retest goes through the same scope, audit-before-launch and rate-limit path as every scan (the original skipped these guards and audited after the fact).
- [x] Per-host "latest report wins": a retest that no longer finds a vulnerability flags it **Not in latest scan**, never auto-closes it. Verified end to end in a real browser.
- [x] `/vapt/findings` UI (summary, multi-word search, filters, evidence, retest, paging). Sync, edit, retest, verify exercised in a real browser.
- [x] Shared `startAuthorizedScan()` now used by both the scan and retest routes; all earlier regression suites still pass, plus 55 new API checks and 71 new unit tests (144 in total).
- [x] The bridge now logs unexpected errors (with a traceback, never credentials). That found a real bug in the new parser on first use.
- [~] Verified against the `gvm-cli` test double and the demo bridge only.
- [ ] Greenbone report layout (`details`, `ignore_pagination`, `nvt/refs`, newest-first order) and timeouts confirmed against your Greenbone version (needs your Greenbone).
- [ ] Day 6 scope, if any (not defined).

---

## Day 6: Risk prioritisation and retest validation

Full detail: [day6-checklist.md](day6-checklist.md). Analysis only: it never scans, changes a host or closes a finding.

- [x] Explainable weighted risk score (5 factors) with **confidence** and a **range**: unknown inputs are never treated as zero.
- [x] Severity 0.0 (informational) is a known low score, capped at Low. *The original treated it as unknown, so an informational finding on a critical host could outrank real vulnerabilities.*
- [x] Ranking by score, then the top of the range. Resolved and Closed findings leave the queue. 3,000-input property test: raising severity never lowers a score.
- [x] Host criticality and exposure stored **once per host** (the original stored them per finding), audited with old and new values, conflict-safe.
- [x] Exploit evidence is now recorded by analysts (the original read fields nothing ever set, so 25% of the model was permanently unknown).
- [x] Report snapshots per Greenbone report, including clean (zero-result) scans; a capped import never marks a report complete; finished reports are frozen.
- [x] Comparison says **Fixed** only for a report Greenbone marked Done that also shows the host was **scanned**. A host that was down is Inconclusive, never Fixed (verified). Matching by stable finding id, not CVE list or name. Nothing is closed automatically (verified).
- [x] Bridge returns per-report status and hosts scanned (`reports`, `completedReports`); an older bridge degrades safely.
- [x] `/risk` UI exercised in a real browser: ranking, "why this score?", host context, comparison.
- [x] 96 new unit tests (240 in total) and 67 new end-to-end checks; every earlier suite and the real-Keycloak runs (21 + 9) still pass.
- [~] Verified against the `gvm-cli` test double and the demo bridge only.
- [ ] The "corroborating detection" factor (10%) has no automated source. It stays unknown. (Wazuh could supply it; not built.)
- [ ] `scan_run_status` and the per-host `<host><ip>/<end>` report entries confirmed against your Greenbone version (needs your Greenbone). If they differ, absence stays inconclusive.
- [ ] Day 7 scope, if any (not defined).

---

## Cross-cutting

### Security and quality
- [x] Dependencies pinned. Production `npm audit`: **0 vulnerabilities** (Next 15.5.28, next-auth 4.24.15, patched PostCSS via `overrides`). The next-auth update also fixes the OAuth state/PKCE cookie binding issue relevant to the Keycloak login.
- [x] Remaining audit findings: 5 dev-only (`braces`, via the linter). No patched release exists; nothing from it ships.
- [x] `tsc`, lint, production build and `npm test` (73 unit tests: scan-scope rules, audit reader, observable extraction) all pass on the upgraded stack.
- [x] Full API regression and a browser pass after the Next 15 upgrade: dashboard, globe, investigations, VAPT, role rules, no console errors.
- [x] README rewritten as one coherent document; per-day checklists in `docs/`.
- [x] gstack installed in `.claude/skills/gstack` (project-local, git-ignored).
- [x] **Independent code review of the whole Day 1-4 branch** (high effort): 10 findings, all confirmed and fixed (audit-before-launch, launch timeout, audit-failure handling, date picker, Keycloak sign-out, Wazuh token truncation, Manager/Indexer coupling, error logging, audit file reads, junk observables, bridge orphan cleanup, allow-list validation).
- [x] The audit log is read from the end of the file, so its cost does not grow with the file (tested against a naive reader on 4,000-line files with multi-byte characters split across read chunks).

### Verification
- [x] Real Keycloak login retest after the Next 15 / next-auth 4.24.15 upgrade and after the review fixes (21 role/flow checks + 9 sign-out checks, all passing).
- [x] Independent code review of the Day 2 to Day 4 code (see above).

## Day 7: CyberReasoner (local defensive analysis)
- [x] `/cyberreasoner`: analysis of one imported finding by a local Ollama model, plus a fixed workflow proposal. Takes only a finding id; SOC_Analyst/SOC_Admin; origin-checked, rate-limited, one run at a time, audited.
- [x] Fixes over the supplied package: finding data cannot leave the machine unless `OLLAMA_ALLOW_REMOTE=true`; redirects refused; model output strictly validated (the original crashed on `null`), capped and screened; upstream error text not leaked; asset context read from PrimeSEC's own stores (the original read fields that did not exist); concurrency lock.
- [x] 55 unit tests (fake Ollama), 25 API checks, and one real run on `qwen2.5:7b` (about 20 s warm; the first call after a cold load took over 90 s, so the default timeout is 180 s).
- [ ] JEV: the plan is a proposal only; no connection (the API contract was not supplied) and it is not stored.
- [ ] Output quality of a 7B model on real findings is unreviewed: treat as a drafting aid.

## Day 8: Observability (OpenTelemetry)
- [x] Opt-in tracing and metrics (`OTEL_ENABLED=true`) to a local Collector, Jaeger and Prometheus; spans and metrics for Wazuh, OpenCTI, Greenbone bridge and Ollama calls; `/observe` page. Verified live: 26 end-to-end checks, 23 unit tests, collector-down behaviour, query-string redaction.
- [x] Fixes over the supplied package: opt-in instead of default-on; loopback-only collector unless allowed; bounded labels; collector redaction; mismatched and vulnerable package versions; a collector image tag that no longer exists; a config option removed from current collectors; backend ports no longer published.
- [ ] No log export, Grafana dashboards, alerts or SLOs; Jaeger is in-memory; no TLS/auth to telemetry backends.

### Decisions and housekeeping that need you
- [~] **Port 8010 identified:** it is your **AgenticOS** FastAPI backend (`new project langdiify/backend` on your Desktop; routers for auth, agents, workflows, approvals, knowledge, memory, audit, billing, graph and evaluation; `/docs`, `/api/system/health`). It was not running when checked. **PrimeSEC does not call it**: all Wazuh/OpenCTI/Greenbone access goes straight from Next.js server-side.
- [ ] Decide what PrimeSEC should use the 8010 backend for (for example agent-assisted alert triage, a shared sign-in, or shared audit) before any integration is built.
- [x] `socadmin` password rotated (2026-10-21). The new value is in `C:\Users\Admin\.primesec\socadmin-password.txt` (outside the repo). The old one no longer works.
- [ ] Remove the DEMO lines from `.env` (and set `DEMO_LOGIN=false`) before any shared deployment.
- [ ] `git push` and a PR to `main`: not done on purpose; commits are local to `dev-kkrish`.

### Before any production use (known MVP limits)
- [ ] Replace the local JSON audit and scope files with a durable, append-only, access-controlled store.
- [ ] Persist rate limits and serialise scope-file writes across processes. Both are per-process today (fine for one Next.js process; with several, a concurrent approve/revoke could lose an update and the rate limit multiplies). Move scopes and audit into a database before running more than one process.
- [ ] Refresh-token rotation and periodic role re-check (roles are fixed for the 8-hour session).
- [ ] HTTPS everywhere, trusted certificates, secret rotation, rotate the realm's local client secret.
- [ ] Use a supported production Greenbone deployment (the container guide is for evaluation).
- [ ] Re-run the full suite against your real Wazuh, OpenCTI and Greenbone versions.
