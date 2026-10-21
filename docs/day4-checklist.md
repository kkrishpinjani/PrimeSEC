# Day 4 acceptance checklist (Greenbone VAPT)

[x] = verified against the bridge running on a **test double** of `gvm-cli` (`bridge/fake_gvm_cli.py`) and the demo bridge (`npm run demo:integrations`). No real Greenbone was involved, and nothing was ever scanned.
"Needs your Greenbone" items can only be confirmed against a real deployment.

## Authorization model (the safety core)
- [x] A scan starts only inside a scope a **SOC_Admin** approved with a written authorization reference (min. 8 characters), a future expiry (max **90 days**) and at most 10 targets.
- [x] The scope check runs on the server before the bridge is called. Out-of-scope targets are refused (403) and the refusal is audited.
- [x] Expired, revoked, missing or **unparseable** expiry dates all deny (fail closed). *Bug found in the original package while porting: an unparseable expiry was treated as "not expired".*
- [x] Targets must be IPv4, `/24` or narrower, with **no host bits set**. `10.0.0.5/24` is rejected instead of silently widened to the whole /24.
- [x] Loopback, link-local (incl. the cloud metadata address), multicast, reserved and unspecified ranges can **never** be scanned, even if "approved".
- [x] Publicly routable ranges need an explicit written-authorization acknowledgement when a scope is approved, and are flagged on the scope.
- [x] A SOC_Admin can **revoke** a scope; it takes effect immediately.
- [x] SOC_ReadOnly can view the workspace but cannot scan or approve; SOC_Analyst can scan inside a scope but cannot approve or revoke.
- [x] 401 without a session; cross-origin writes are rejected; scan launches are limited to 5 per 10 minutes per user (per server process).
- [x] 40 unit tests of the scope rules pass (`npm run test:vapt`).

## Audit
- [x] Scope approval, revocation, scan launch **and refused launch attempts** are written to `data/audit-events.jsonl` and shown in the workspace. Revoking an already revoked scope does not log again.

## Bridge (`bridge/server.py`)
- [x] Refuses to start with a token shorter than 32 characters; all routes except `/health` need the bearer token.
- [x] Applies the same strict target rules, plus an optional independent allow-list (`GREENBONE_ALLOWED_RANGES`) owned by whoever runs Greenbone.
- [x] Supports a mode-0600 `gvm-tools` config file so the GMP password is **not** on the command line (visible in `ps`). The password mode still works and prints a warning.
- [x] Raw `gvm-cli` errors, command lines and credentials are never returned to the caller.
- [ ] Greenbone Community Edition deployed from its current official guide and feeds synchronised (needs your Greenbone).
- [ ] GMP socket access limited to the bridge's service account, never world-writable (needs your Greenbone).
- [ ] Scan config / port list / scanner UUIDs in `bridge/.env` exist in your installation (needs your Greenbone).
- [ ] `gvm-cli` flags and GMP responses verified against your Greenbone version (needs your Greenbone).
- [ ] A real task appears in Greenbone and in PrimeSEC's task list (needs your Greenbone).

## Known limitations
- IPv4 only. Findings are not imported: this build launches tasks and shows a task/status snapshot (detailed findings, remediation and retest are Day 5).
- Scope and audit records are local JSON files: not tamper-proof, not replicated. Use a durable, access-controlled store before production.
- Rate limiting is in-memory, per server process.
- Greenbone's container deployment is for evaluation; use a supported production deployment for real work.
