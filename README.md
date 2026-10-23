# PrimeSEC

A security operations workspace: one sign-on, one dashboard over **Wazuh** (alerts, endpoints, vulnerabilities), **OpenCTI** (threat intelligence) and **Greenbone/OpenVAS** (authorized vulnerability scans), with a governed alert-investigation workflow and an audit trail.

Stack: Next.js 15 (pages router), React 18, TypeScript, NextAuth 4 (Keycloak OIDC), three.js (globe on real Natural Earth geography), Framer Motion, plain CSS. Greenbone is reached through a small Python bridge.

**Project status and what is still open:** [docs/PROJECT-CHECKLIST.md](docs/PROJECT-CHECKLIST.md).

## What's in it

| Area | What it does |
|---|---|
| **Sign-in** (`/login`) | Keycloak OIDC. Roles `SOC_Admin`, `SOC_Analyst`, `SOC_ReadOnly`. A user with no role is sent to `/403`. |
| **Dashboard** (`/dashboard`) | Full-screen SOC view: globe of geolocated alert sources, hourly alert volume, severity counts, a documented threat score, Threat Intel, Vulnerabilities and Investigations tabs. Live per section when a platform is connected; otherwise clearly labelled sample data. |
| **Investigations** | An **Investigate** button on each live Wazuh alert: re-reads the alert from Wazuh, looks up its IPs/domains/hashes in OpenCTI, shows potential matches for analyst review, and writes an audit event. Read-only: it never blocks or remediates anything. |
| **VAPT workspace** (`/vapt`) | `SOC_Admin` approves a scope with a written authorization reference and an expiry; scans can start only inside it. Every approval, revocation, launch and refusal is audited. |
| **Findings** (`/vapt/findings`) | Greenbone results imported and de-duplicated, with remediation status, owner and notes, a retest request, and a "not in latest scan" flag that helps verify fixes. It records work; it never changes a host. |
| **Risk & validation** (`/risk`) | An explainable risk-ranked remediation queue (with a "why this score?" breakdown, where unknown inputs stay unknown and widen a score range) and a retest comparison that says "fixed" only with proof. Analysis only: it never scans or closes anything. |
| **Landing page** (`/`) | Public page with the globe. |
| **Health** (`/api/health`) | Local health check. |

## Run locally

Requires Docker Desktop (running) and Node 20+.

```powershell
copy .env.example .env     # then run .\scripts\setup.ps1 (or ./scripts/setup.sh) to generate secrets
docker compose up -d       # Keycloak
npm install
npm run dev
```

| Service | URL |
|---|---|
| App | http://localhost:3010 |
| Keycloak admin | http://localhost:8080/admin (credentials in `.env`) |
| Health | http://localhost:3010/api/health |
| Your backend | port 8010: the AgenticOS FastAPI backend (`new project langdiify/backend`, docs at `/docs`). PrimeSEC does **not** call it yet |

Keycloak is bound to `127.0.0.1`. Changes to `.env` are picked up by the dev server; restart it if a change does not apply.

### First user
1. Keycloak admin console → realm `primesoc` → **Users → Create user**, set a non-temporary password under **Credentials**.
2. **Role mapping**: assign `SOC_Admin` or `SOC_Analyst`.
3. Open the app and choose **Continue with Keycloak**.

## Demo mode (no real platforms needed)

```powershell
npm run demo:integrations   # fake Wazuh, OpenCTI and Greenbone bridge on :9099, every record marked "(demo)"
npm run dev
```

The demo settings live under the DEMO headings in `.env` and are marked with `DEMO_INTEGRATIONS=true`, so the dashboard says **Demo data**. Nothing is scanned and nothing touches a network.

`DEMO_LOGIN=true` adds three buttons to `/login`, **Admin**, **Analyst** and **Read-only**, that sign in without Keycloak as `SOC_Admin`, `SOC_Analyst` or `SOC_ReadOnly`. Each is a separate identity (`demo-admin@`, `demo-analyst@`, `demo-readonly@primesec.local`), so audit entries and rate limits stay per role and you can switch roles by signing out, with no `.env` edits. The role can only be one of those three; anything else falls back to `DEMO_LOGIN_ROLE` (default `SOC_ReadOnly`). It is for local demos only, is ignored in production builds (a production server refuses it even with `DEMO_LOGIN=true`), and ships as `false` in `.env.example`.

To go real, replace the DEMO lines in `.env` with real URLs and read-only credentials, and set `DEMO_INTEGRATIONS=false`.

## Connecting real platforms

All platform calls happen **server-side**; credentials stay in `.env` and are never sent to the browser. Every integration route needs a session and a PrimeSEC role (401/403 otherwise) and is `no-store`.

### Wazuh and OpenCTI (Day 2)
Set the variables listed in `.env.example` (`WAZUH_API_*`, `WAZUH_INDEXER_*`, `OPENCTI_*`). Use dedicated **read-only** accounts. Self-signed TLS: trust the CA with `NODE_EXTRA_CA_CERTS=C:/certs/wazuh-ca.pem`; do not disable certificate checks.

What becomes real once connected:
- **Globe:** Natural Earth geography; markers are Wazuh alert sources (`data.srcip`) carrying Wazuh GeoIP data, with arcs to your SOC (`PRIMESEC_HOME_LAT/LON`). No sources, no markers: nothing is invented.
- **Alert volume / timeline:** hourly counts from the Wazuh Indexer. **Alerts by severity** uses Wazuh rule levels (Info 0-3, Low 4-6, Medium 7-11, High 12+).
- **Threat radar:** `1000 x (1 - e^(-load/2000))`, load = High x10 + Medium x2 + Low x0.5 + Info x0.1 over 24 h. Hover the card title for the formula.
- **Vulnerabilities:** Wazuh's Vulnerability Detector index (`wazuh-states-vulnerabilities-*`, Wazuh 4.8+).
- **Threat Intel:** OpenCTI indicators with scores and platform-wide totals.
- Scope chips are configured labels (`PRIMESEC_TEAM`, `PRIMESEC_REGION`), hidden when unset.

### Investigations (Day 3)
`POST /api/investigations` takes only an alert id (the browser never supplies alert contents), re-reads the alert from Wazuh, extracts IPv4/domain/hash observables, searches OpenCTI per observable and keeps indicators whose own observables **exactly** equal one of them. Results are labelled "Potential match: analyst validation required"; a no-match is not proof an alert is benign. Needs `SOC_Analyst`/`SOC_Admin`, rejects cross-origin requests, validates the id and is limited to 10 per minute per user. File names and code identifiers (`app.config`, `System.Net.Sockets`) are not treated as domains.

### Greenbone (Day 4)
**Only scan systems you are explicitly authorized to assess.** A scan starts only inside a scope a `SOC_Admin` approved (written authorization reference, expiry at most 90 days), enforced on the server before the bridge is called.

- **Audit first:** a launch is audited *before* Greenbone is called. If the audit log is unavailable the scan is not started; a failed or timed-out launch is audited too. Starting a scan has its own timeout (`GREENBONE_LAUNCH_TIMEOUT_MS`, default 120 s).
- Targets: IPv4, `/24` or narrower, no host bits set. Loopback, link-local (cloud metadata), multicast and reserved ranges can never be scanned. Public ranges need an explicit acknowledgement. Scopes can be revoked at any time. Launches are limited to 5 per 10 minutes per user.
- Real Greenbone: deploy Greenbone Community Edition from its **current** official guide (https://greenbone.github.io/docs/latest/22.4/container/), wait for the feeds to sync, give the bridge's service account (only) access to the gvmd socket, then `cd bridge && cp .env.example .env` and set a random `GREENBONE_BRIDGE_TOKEN` (32+ chars), the socket path, credentials (prefer `GVM_CLI_CONFIG`, a mode-0600 gvm-tools config file), your scan-config / port-list / scanner UUIDs and optionally `GREENBONE_ALLOWED_RANGES` (a second allow-list you control). Run `./run-bridge.sh`, then set `GREENBONE_BRIDGE_URL` and the same token in PrimeSEC's `.env`.
- `bridge/fake_gvm_cli.py` is a **test double** (not Greenbone): `GVM_CLI_PATH="python bridge/fake_gvm_cli.py"`.
- `bridge/fake_gvm_cli.py` also returns realistic reports for the findings workflow.

### Findings, remediation and retest (Day 5)
`/vapt/findings` imports recent Greenbone report results (**Sync Greenbone findings**, `SOC_Analyst`/`SOC_Admin`, a POST with origin check and rate limit) and keeps one record per vulnerability per host and port. Evidence is refreshed on every sync while **status, owner, notes and retest data always survive**.

- **Remediation:** status (`Open`, `In Progress`, `Resolved`, `Retest Required`, `Closed`), owner and notes. A finding can be closed only after a retest was requested for it, or by a `SOC_Admin` who writes a justification in the notes. Concurrent edits are detected (409) instead of overwritten.
- **Retest:** a request for a new authorized scan of the finding's host. It goes through the same scope, audit-before-launch and rate-limit path as any scan, so a host outside an approved scope is refused. Nothing is fixed or changed on the host.
- **Verifying a fix:** for each host only its most recent report counts as current. A finding that appeared in an older report but is absent from the host's latest one is flagged **Not in latest scan**. That is a hint to review the new report, then resolve; nothing is ever closed automatically.
- **Audit:** sync, edits (which fields changed, never the note text) and retests are audited. Findings live in `data/vapt-findings.json` (git-ignored), serialised within one server process.
- Try it with `npm run demo:integrations`: approve a scope, scan it, sync, then request a retest and sync again (then open `/risk`). The demo retest scan no longer reports the Apache and TLS 1.0 items, so those two get flagged.
- Checklist and limits: [docs/day5-checklist.md](docs/day5-checklist.md).

### Risk and validation (Day 6)
`/risk` ranks open findings by an **explainable weighted score**: severity 30%, exploit evidence 25%, asset criticality 20%, exposure 15%, corroborating detection 10%. It is a triage aid, not a probability of exploitation and not a CVSS replacement.

- **Unknown is not zero.** Missing factors are excluded and the rest renormalised, and each score shows its **confidence** (share of weight that is known) and a **range** (what it could be if every unknown were 0 or 100). Ranking uses the score, then the top of the range.
- **Informational findings** (severity 0.0) are capped at Low, so host importance alone never makes a non-vulnerability urgent.
- **Host context** (criticality and exposure) is set once per host by an analyst and applies to every finding on it. **Exploit evidence** is recorded per finding by an analyst (for example from CISA KEV or a vendor advisory). Both are audited. The "corroborating detection" factor has no automated source yet and stays unknown.
- **Report comparison:** after each Greenbone scan finishes, sync; PrimeSEC keeps a snapshot per report (including clean scans). Comparing a baseline with a retest reports **Fixed** only when the retest report is marked Done by Greenbone **and** shows the host was really scanned; a host that was down yields **Inconclusive**, never Fixed. Matching uses the stable finding id (host, port, NVT), so a renamed NVT or a new CVE does not hide a finding. Nothing is ever closed automatically: resolve findings yourself on the Findings page.
- The bridge now also returns per-report status and the hosts actually scanned (`reports`, `completedReports`). Checklist and limits: [docs/day6-checklist.md](docs/day6-checklist.md).

### Wazuh single sign-on
Wazuh uses SAML; PrimeSEC uses OIDC. They can share the Keycloak realm as separate clients. Set `WAZUH_DASHBOARD_URL` for the header link, then follow the version-matched guide: https://documentation.wazuh.com/current/user-manual/user-administration/single-sign-on/keycloak.html (it cannot be pre-configured without your Wazuh version, URL and certificates).

## Roles

| | `SOC_ReadOnly` | `SOC_Analyst` | `SOC_Admin` |
|---|---|---|---|
| View dashboard, audit lists, scopes | yes | yes | yes |
| Investigate alerts | - | yes | yes |
| Start a scan inside an approved scope | - | yes | yes |
| Approve / revoke scopes | - | - | yes |

## Tests

```powershell
npm test            # all unit tests (Node 22.6+): scan-scope rules (40), audit reader + observable extraction (33), findings (71), risk + assets (55), reports (41)
npm run test:vapt   # only the scan-scope safety rules
npm run test:lib    # only the audit reader and the observable extractor
npm run test:findings  # only findings normalization, sync, remediation and the close rule
npm run test:risk      # only the risk model and the host asset store
npm run test:reports   # only report snapshots and the comparison rules
npx tsc --noEmit
npm run lint
npm run build       # do not run while `npm run dev` is running: it corrupts the dev cache
```

## Security notes

- **Sign out ends the Keycloak session** as well as the app's own cookie (RP-initiated logout via `/api/logout-url`), so signing in again asks for a password. The Keycloak ID token used for this stays inside the encrypted session cookie and is never sent to the page.

- The realm JSON contains a local-only client secret (`primesoc-local-dev-secret-change-me`). Rotate it, and every default password, before any shared deployment.
- Roles are read once at sign-in and kept for the 8-hour session, so revoking a role in Keycloak takes effect after the user signs out. There is no refresh-token rotation yet.
- `NEXTAUTH_SECRET` is validated at request time: the app refuses to authenticate with a missing or placeholder secret.
- Audit events (`data/audit-events.jsonl`), scan scopes (`data/vapt-scopes.json`) findings (`data/vapt-findings.json`), host context (`data/vapt-assets.json`) and report snapshots (`data/vapt-report-snapshots.json`) are local files in the git-ignored `data/` folder. They are not tamper-proof or replicated; use a durable, access-controlled store before production.
- Rate limiting and scope-file write serialisation are per server process. Run a single Next.js process, or move scopes, audit and rate limits into a database first.
- Errors are logged on the server (`[primesec] ...` lines, never request bodies or credentials) and returned to the browser as generic messages.
- Never commit `.env` or `bridge/.env`. Use HTTPS and stable hostnames outside local development.
- Authorization must be enforced on every backend endpoint, not only in the UI.
- Dependencies are pinned. `npm audit` for production dependencies reports **0 vulnerabilities**: Next.js 15.5.28 and next-auth 4.24.15, plus an `overrides` entry that replaces Next's bundled PostCSS with a patched release. The remaining findings are dev-only linter tooling (`braces`, via `eslint-config-next`); no patched release exists and nothing from it ships in the app.

## Changes from the original Day 1 package
- **Realm import fix:** the original `primesoc-realm.json` defined a custom `clientScopes` block, which stopped Keycloak creating its built-in `profile`/`email` scopes and made every sign-in fail with `invalid_scope`. It was removed; Keycloak's built-in `roles` scope already emits `realm_access.roles`.
- Converted to TypeScript, moved the protected page to `/dashboard`, made `/` the public landing page.
- Day 2-4 packages were ported rather than dropped in, with hardening (exact-match correlation, strict CIDR rules, scope revocation, fail-closed expiry checks, audit of refused scans).

## Day 7: CyberReasoner (defensive, local model)

`/cyberreasoner` asks a **local** Ollama model to explain one imported finding and suggest remediation and safe checks, and drafts a fixed, policy-gated workflow proposal. It is advisory: it never scans, tests, exploits or changes anything, and takes only a finding id as input.

```
ollama pull qwen2.5:7b        # or: docker compose --profile ai up -d ollama
# .env: OLLAMA_BASE_URL=http://127.0.0.1:11434   CYBERREASONER_MODEL=qwen2.5:7b
```

Finding details are sent only to a loopback model unless you set `OLLAMA_ALLOW_REMOTE=true`. See [docs/day7-checklist.md](docs/day7-checklist.md) for what is verified, what is not (no JEV connection), and the limits.

## Day 8: Observability (OpenTelemetry, opt-in)

```
docker compose --profile observe up -d jaeger otel-collector prometheus
# .env: OTEL_ENABLED=true   then restart `npm run dev`
```

Then open `/observe` (reachability of Collector, Jaeger and Prometheus), Jaeger at http://localhost:16686 (service `primesec-web`) and Prometheus at http://localhost:9090 (`primesec_integration_calls_total`). Telemetry is off unless `OTEL_ENABLED=true`, never leaves the machine unless `OTEL_ALLOW_REMOTE=true`, and carries no URLs, hosts, tokens, prompts or finding details. See [docs/day8-checklist.md](docs/day8-checklist.md).
