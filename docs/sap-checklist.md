# SAP configuration risk (from the "SAP AttackPath AI" package)

[x] = verified: 70 unit tests (`npm run test:sap`) and 41 end-to-end API checks against the running app across all three roles, including a real local-model explanation. Not verified: any real SAP system or real SAP configuration files, because none were available.

Page: `/sap` (Assess, History, Knowledge search). API: `POST /api/sap/assess`, `GET /api/sap/assessments` (list, `?id=`, `?q=`, `?demo=1`).

## What it is, and is not
Paste the text of an SAP router table (`saprouttab`), gateway profile parameters, `reginfo` and `secinfo`, and PrimeSEC lists configuration risks using seven fixed rules. **It is offline**: it never connects to an SAP system, scans an address, runs a transaction or tries a credential. A finding is a lead to verify against your exact SAP release and current SAP Security Notes, not proof of exploitability, and "no findings" does not mean "secure".

## How it was brought in
The package was a separate Python/FastAPI service with its own React/MUI app, Postgres, Redis and Keycloak adapters. PrimeSEC already has sign-in, roles, audit and storage, and the package itself says not to run a second auth system, so the detection logic, knowledge search and model explanation were **ported into PrimeSEC (TypeScript)** and use PrimeSEC's login, roles, audit log and UI. Not carried over: the Postgres/Redis/outbox/Keycloak adapters and the Material UI app (nothing to connect them to here), and the "Validation runs" and "Integrations" screens, which in the package were placeholders with no function.

## Fixes over the supplied rules
- [x] **Deny lines are no longer flagged.** The original flagged any `reginfo`/`secinfo` line containing `TP=*` and `HOST=*`, including the standard final `D TP=* HOST=*` deny-all, so a properly hardened file was reported as risky. Only permit (`P`) lines are flagged now.
- [x] **SNC names with spaces parse correctly.** Rule lines were split on whitespace, so `KP "p:CN=router, O=Example Corp" ...` was cut apart and the ordering check misread it. Quoted fields are kept whole.
- [x] **The ordering check looks for real overlap.** The original reported a gap for any broad permit followed by any SNC rule. It now requires the permit's destination and service to cover the SNC rule's (wildcard, equal or prefix).
- [x] **All matching lines are reported** (capped, with a note), not just the first.
- [x] Parameter names are case-insensitive, `false/off/no` and `true/on/yes` are understood, and an absent parameter is never treated as a finding.

## Safety and limits
- [x] SOC_Analyst/SOC_Admin only to assess; any role can read; origin-checked; 20 assessments per 10 minutes per user.
- [x] Input is bounded: 200,000 / 100,000 characters per field, 5,000 lines, 2,000 characters per line, text only, control characters stripped, asset id restricted to letters, digits and `. _ : -`.
- [x] **The pasted configuration is not stored or put in the audit log.** History keeps the findings, the matching lines and line counts; the audit event holds the asset id, counts and finding ids only.
- [x] **The AI explanation is optional, advisory and cannot change findings.** It uses the local model only (non-local endpoints are refused), treats findings as untrusted data, withholds replies that mention offensive tooling, times out cleanly, runs one at a time, and never fails the assessment: a note says why it is missing.
- [x] Knowledge search is a plain word match over three bundled notes in `knowledge/sap/`; results are plain text from files in this repository.

## Not done / limits
- [ ] Only seven specific patterns are checked, with heuristic parsing. This is not a full SAProuter/Gateway grammar parser, and it does not know your SAP release.
- [ ] No live validation, asset discovery or CMDB link, and findings are not fed into the Findings or Risk screens.
- [ ] Single-tenant: the package's per-tenant database isolation does not apply here. State is a local JSON file (last 100 assessments).
- [ ] The three knowledge notes are short summaries with links to SAP Help (some SAP Notes need an SAP login). Add more notes as `.md` files in `knowledge/sap/`.
