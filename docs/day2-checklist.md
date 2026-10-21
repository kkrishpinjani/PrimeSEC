# Day 2 acceptance checklist (Wazuh + OpenCTI)

Code-level behaviour below was verified against a mock Wazuh/OpenCTI. Items marked "needs your instance" can only be confirmed against the real platforms.

- [x] `/api/integrations/wazuh` and `/api/integrations/opencti` return 401 without a session.
- [x] Routes also return 403 for a signed-in user with no PrimeSEC role.
- [x] Upstream credentials and tokens never appear in API responses or dashboard HTML.
- [x] Unconfigured or unreachable platforms show as a status on the dashboard, not a broken page, and fall back to labelled sample data.
- [ ] Wazuh read-only account authenticates and agent count/rows match Wazuh (needs your instance).
- [ ] Wazuh Indexer returns 24h alert counts and recent alerts (needs your instance; separate credentials).
- [ ] OpenCTI token returns indicators, reports and threat actors (needs your instance).
- [ ] TLS verification stays enabled; self-signed CAs are trusted via `NODE_EXTRA_CA_CERTS`, not by disabling checks.
- [ ] Wazuh and OpenCTI native dashboards open from the configured URLs.
- [ ] Native-UI SSO tested separately (API integration does not imply SSO).

Everything on the dashboard now comes from Wazuh/OpenCTI when connected: globe sources (needs Wazuh GeoIP on srcip and `PRIMESEC_HOME_LAT/LON`), hourly trend and timeline, severity counts, the documented radar score, Wazuh Vulnerability Detector findings (Wazuh 4.8+), OpenCTI totals and scores. Unconnected sections show labelled sample data.
