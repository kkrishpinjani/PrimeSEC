# PrimeSEC project checklist (Day 1 to Day 4)

Last verified: 2026-10-21.

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

Everything that can be finished and verified without your platforms is finished.

---

## Day 1: Identity foundation

### Keycloak and sign-in
- [x] Keycloak container starts and imports the `primesoc` realm (realm discovery URL answers; realm survives a container recreate).
- [x] Original realm import bug fixed: the custom `clientScopes` block broke every sign-in with `invalid_scope`.
- [x] Real Keycloak users can sign in (`socadmin`, plus throwaway users in earlier test runs).
- [x] Roles `SOC_Admin` / `SOC_Analyst` / `SOC_ReadOnly` reach the app (`realm_access.roles`) and are shown in the dashboard.
- [x] A user with no PrimeSEC role is redirected to `/403` and gets 403 from every API.
- [x] `/dashboard` redirects to `/login` when signed out; sign-out returns to login.
- [x] `/api/health` returns 200.
- [x] Keycloak is bound to `127.0.0.1:8080`; post-logout redirect restricted to `/login` (was a wildcard).
- [x] `NEXTAUTH_SECRET` guard: authentication is refused when the secret is missing or still the placeholder.
- [x] Renamed to PrimeSEC everywhere user-visible (realm and client IDs `primesoc` / `primesoc-web` intentionally kept, since renaming breaks the import).
- [x] Frontend on port 3010 (`package.json`, `.env`, realm file, live Keycloak client).
- [x] "Try the demo" login (opt-in via `DEMO_LOGIN`, refused in production builds, role configurable).
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
- [x] Observables (IPv4, domains, MD5/SHA-1/SHA-256) extracted from the alert; OpenCTI searched per observable; matches are **exact**, not substring. `powershell.exe` is not mistaken for a domain.
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

### Bridge and UI
- [x] `/vapt` workspace (status, scopes, launch form, tasks, audit trail), linked from the dashboard and the Vulnerabilities tab. Forms exercised in a real browser.
- [~] Bridge (`bridge/server.py`) verified against the `gvm-cli` **test double**: token of 32+ chars required, strict target rules, optional independent allow-list, password kept out of the process list via a config file.
- [~] Demo bridge on `:9099` records "(demo)" tasks and scans nothing.
- [ ] Greenbone Community Edition deployed from its current official guide; feeds synced.
- [ ] gvmd socket reachable only by the bridge's service account (never world-writable).
- [ ] Scan config, port list and scanner UUIDs in `bridge/.env` match your installation.
- [ ] `gvm-cli` flags and GMP responses confirmed against your Greenbone version.
- [ ] A real task appears in Greenbone and in the PrimeSEC task list.
- [ ] Day 5 scope (not built): detailed findings, remediation workflow, retest.

---

## Cross-cutting

### Security and quality
- [x] Dependencies pinned. Production `npm audit`: **0 vulnerabilities** (Next 15.5.28, next-auth 4.24.15, patched PostCSS via `overrides`). The next-auth update also fixes the OAuth state/PKCE cookie binding issue relevant to the Keycloak login.
- [x] Remaining audit findings: 5 dev-only (`braces`, via the linter). No patched release exists; nothing from it ships.
- [x] `tsc`, lint, production build and `npm run test:vapt` all pass on the upgraded stack.
- [x] Full API regression and a browser pass after the Next 15 upgrade: dashboard, globe, investigations, VAPT, role rules, no console errors.
- [x] README rewritten as one coherent document; per-day checklists in `docs/`.
- [x] gstack installed in `.claude/skills/gstack` (project-local). `/review` was run once, on the Day 1 code.

### Verification still owed
- [ ] **Real Keycloak login retest after the Next 15 / next-auth 4.24.15 upgrade.** Docker was stopped, so the OAuth flow was re-verified only through the demo login. Start Docker, sign in as `socadmin`, and open `/dashboard`, `/vapt`, and run an investigation.
- [ ] An independent code review of the Day 2 to Day 4 code (gstack `/review`, once the work is committed and has a clean diff).

### Decisions and housekeeping that need you
- [ ] **What is the backend on port 8010?** Recorded as reserved; nothing calls it. All platform access currently goes straight from Next.js server-side.
- [ ] **Rotate the `socadmin` password.** It was shown in chat on 2026-10-19. (Keycloak admin console, realm `primesoc`, user `socadmin`.)
- [ ] Remove the DEMO lines from `.env` (and set `DEMO_LOGIN=false`) before any shared deployment.
- [ ] `git push` and a PR to `main`: not done on purpose; commits are local to `dev-kkrish`.

### Before any production use (known MVP limits)
- [ ] Replace the local JSON audit and scope files with a durable, append-only, access-controlled store.
- [ ] Persist rate limits (currently in-memory per process).
- [ ] Refresh-token rotation and periodic role re-check (roles are fixed for the 8-hour session).
- [ ] HTTPS everywhere, trusted certificates, secret rotation, rotate the realm's local client secret.
- [ ] Use a supported production Greenbone deployment (the container guide is for evaluation).
- [ ] Re-run the full suite against your real Wazuh, OpenCTI and Greenbone versions.
