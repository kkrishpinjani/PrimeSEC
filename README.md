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
| Backend | port 8010 (reserved; nothing calls it yet) |

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

`DEMO_LOGIN=true` adds a **Try the demo** button on `/login` that signs in without Keycloak, as the role in `DEMO_LOGIN_ROLE` (default `SOC_ReadOnly`; use `SOC_Analyst` to investigate or `SOC_Admin` to approve scopes). It is for local demos only, is ignored in production builds, and ships as `false` in `.env.example`.

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
- This build launches tasks and shows their status. Detailed findings, remediation and retest are not built yet.

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
npm test            # all unit tests (Node 22.6+): scan-scope rules (40), audit reader + observable extraction (33)
npm run test:vapt   # only the scan-scope safety rules
npm run test:lib    # only the audit reader and the observable extractor
npx tsc --noEmit
npm run lint
npm run build       # do not run while `npm run dev` is running: it corrupts the dev cache
```

## Security notes

- **Sign out ends the Keycloak session** as well as the app's own cookie (RP-initiated logout via `/api/logout-url`), so signing in again asks for a password. The Keycloak ID token used for this stays inside the encrypted session cookie and is never sent to the page.

- The realm JSON contains a local-only client secret (`primesoc-local-dev-secret-change-me`). Rotate it, and every default password, before any shared deployment.
- Roles are read once at sign-in and kept for the 8-hour session, so revoking a role in Keycloak takes effect after the user signs out. There is no refresh-token rotation yet.
- `NEXTAUTH_SECRET` is validated at request time: the app refuses to authenticate with a missing or placeholder secret.
- Audit events (`data/audit-events.jsonl`) and scan scopes (`data/vapt-scopes.json`) are local files in the git-ignored `data/` folder. They are not tamper-proof or replicated; use a durable, access-controlled store before production.
- Rate limiting and scope-file write serialisation are per server process. Run a single Next.js process, or move scopes, audit and rate limits into a database first.
- Errors are logged on the server (`[primesec] ...` lines, never request bodies or credentials) and returned to the browser as generic messages.
- Never commit `.env` or `bridge/.env`. Use HTTPS and stable hostnames outside local development.
- Authorization must be enforced on every backend endpoint, not only in the UI.
- Dependencies are pinned. `npm audit` for production dependencies reports **0 vulnerabilities**: Next.js 15.5.28 and next-auth 4.24.15, plus an `overrides` entry that replaces Next's bundled PostCSS with a patched release. The remaining findings are dev-only linter tooling (`braces`, via `eslint-config-next`); no patched release exists and nothing from it ships in the app.

## Changes from the original Day 1 package
- **Realm import fix:** the original `primesoc-realm.json` defined a custom `clientScopes` block, which stopped Keycloak creating its built-in `profile`/`email` scopes and made every sign-in fail with `invalid_scope`. It was removed; Keycloak's built-in `roles` scope already emits `realm_access.roles`.
- Converted to TypeScript, moved the protected page to `/dashboard`, made `/` the public landing page.
- Day 2-4 packages were ported rather than dropped in, with hardening (exact-match correlation, strict CIDR rules, scope revocation, fail-closed expiry checks, audit of refused scans).
