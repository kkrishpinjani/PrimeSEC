# Day 3 acceptance checklist (Investigation MVP)

Items marked [x] were verified against the local demo Wazuh/OpenCTI (`npm run demo:integrations`). Items marked "needs your instance" need real platforms.

## Workflow and guards
- [x] An Investigate action exists on each recent Wazuh alert (Investigations tab); it is disabled for sample alerts and for `SOC_ReadOnly`.
- [x] The browser submits only an alert id. The server re-reads the alert from the Wazuh Indexer; client-supplied alert contents are never trusted.
- [x] Malformed alert ids are rejected (400) before reaching any upstream query; unknown ids return 404.
- [x] `POST /api/investigations` requires a session (401) and `SOC_Analyst` or `SOC_Admin` (403 for `SOC_ReadOnly`); `GET` returns the audit list to any PrimeSEC role.
- [x] Cross-origin browser POSTs are rejected (403); responses are `no-store`.
- [x] Investigations are rate-limited per user (10 per minute, then 429).
- [x] No response or remediation action exists anywhere in this workflow.
- [x] No upstream credentials or tokens appear in any response.

## Correlation
- [x] Observables (IPv4, domains, MD5/SHA-1/SHA-256) are extracted from the alert (description, full log, `data`, `syscheck`) and from OpenCTI indicator names and patterns, and compared for **exact** equality (no substring matching).
- [x] File names such as `powershell.exe` and `app.config`, and mixed-case code identifiers such as `System.Net.Sockets`, are not treated as domains.
- [x] OpenCTI is searched per observable, so an indicator is found even if it is not among the latest few.
- [x] Every result is labelled "Potential match: analyst validation required"; a no-match result says it is not proof the alert is benign.
- [x] When OpenCTI is unreachable the result says no reliable correlation is possible.
- [ ] Search behaviour and field names confirmed against your OpenCTI version (needs your instance).
- [ ] Wazuh alert ids and `full_log`/`data` fields confirmed against your Wazuh version (needs your instance).

## Audit trail
- [x] Every successful investigation appends an event to `data/audit-events.jsonl` (git-ignored): actor, roles, alert summary, observables searched, matched indicators.
- [x] The Investigations tab lists recent audit events and refreshes after each investigation.
- [ ] Replace the local JSONL file with a durable store before production (see Known limitations).

## Known limitations
- Matching is deterministic and exact over extracted IPv4/domain/hash values. It is not a full STIX observable model and does not evaluate indicator confidence or validity windows.
- IPv6 addresses and URLs as whole values are not matched; the host inside a URL is.
- The audit log is a local file: not tamper-proof, not replicated, per-server-process rate limiting only.
- Native Wazuh/OpenCTI single sign-on is not established by this API integration.
