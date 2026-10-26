# PrimeSEC QA report (pre-handover test pass, 2026-10-26)

Tested as a client would receive it: from a clean clone of the repository, in development and production mode, with real Keycloak, a real local AI model, a real Collector/Jaeger/Prometheus/Grafana stack, and a real browser.

## Result
**Ready to hand over as a demonstration and pilot build. Not ready to connect to production systems without the items under "Before real use".**

## What was tested, and the outcome

| Area | Method | Result |
|---|---|---|
| Clean install | `git clone` → `npm ci` → `npm run build` → `npm test` in a fresh folder | Passed (build clean, 11 unit suites, 0 failures) |
| Unit tests | 40 + 33 + 71 + 55 + 41 + 22 + 55 + 23 + 60 + 51 + 70 | 521 checks passed |
| End-to-end API suites (fresh state, live app) | demo roles 21, findings 55, risk and reports 59, sample data 28, CyberReasoner 25 (real model), agent security 61, gateway and approvals 54, SAP 41 (real model), observability 26, reliability and alerts 27 | 397 checks passed |
| Authorization sweep | all 31 API routes × 5 HTTP methods, signed out; 23 state-changing routes as read-only; 9 admin-only routes as analyst; 23 routes with a hostile `Origin` | No holes found |
| Production build | `next start` with `DEMO_LOGIN=true` deliberately set | Demo sign-in is impossible; 36/36 checks incl. real Keycloak sign-in, all 8 screens and 11 APIs |
| Real Keycloak | sign-in, SSO session, sign-out ends the SSO session | 9/9 |
| Browser (real Chrome) | sign in, open all 8 screens, click every Agent security tab, run the evaluation, run a SAP assessment, history, knowledge search, sign out; plus phone width | 24 checks, no console errors, no failed requests |
| Dependencies | `npm audit` (production and dev) | 0 vulnerabilities |
| Static | TypeScript, ESLint | Clean |
| Docker | `docker compose config` for all profiles | Valid |

## Defects found in this pass and fixed
1. **No browser security headers.** Added `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, a framing/base/form CSP, and HSTS in production builds. Real Keycloak sign-in re-tested afterwards.
2. **Health endpoint reported a stale service name** (`primesec-day1`); now `primesec`.
3. **SAP form layout** was uneven and overflowed on a phone; fixed and re-checked in a browser.
4. **Stale wording** on the Agent security overview ("Test lab") after the tab was renamed.
5. Two test scripts were out of date (they expected three observability services after Grafana was added; a login button label). Test code only; the product was right.

## Known limitations (all documented in `docs/*-checklist.md`)
- Verified against demo integrations and a local model, **not** a real Wazuh, OpenCTI, Greenbone or SAP system.
- Alert rules are evaluated but **nothing is sent** when one fires (no Alertmanager/receiver is configured).
- Agent security **decides but does not enforce**: it only protects anything once an agent adapter calls the gateway and obeys it. No adapter is included.
- State (findings, scopes, agents, approvals, assessments, audit log) is local JSON files, correct for one server process, not for several instances. The audit log is not tamper-proof.
- The Content-Security-Policy does not restrict scripts (that needs a nonce set-up tested separately).
- AI output (CyberReasoner, SAP explanation) is advisory and can be wrong; a 7B local model was used.
- Jaeger keeps traces in memory only.

## Before real use
- Remove the `DEMO_*` lines from `.env` and set `DEMO_LOGIN=false`; rotate the Keycloak admin and client secrets and the Grafana password.
- Run behind HTTPS with trusted certificates (HSTS is already sent by production builds).
- Point `.env` at the real Wazuh, OpenCTI and Greenbone and repeat the suites against them.
- Move scopes, findings, approvals and the audit log to a durable, access-controlled database before running more than one process.
- Configure an approved alert receiver, and decide how agents will call the gateway.
