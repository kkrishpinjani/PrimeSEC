# Day 9 acceptance checklist (reliability: Grafana dashboard, alert rules)

[x] = verified against a real Prometheus 2.55.1 and Grafana 11.4.0 in Docker with live application traffic. Not verified: alert *delivery* (no Alertmanager or receiver is configured, on purpose), a production deployment.

## Grafana (`http://localhost:3001`, `docker compose --profile observe up -d grafana`)
- [x] Bound to 127.0.0.1; anonymous access off; sign-up off; update checks and usage reporting off.
- [x] `GRAFANA_ADMIN_PASSWORD` has **no default**: compose refuses to start without it. Verified that `admin/admin` and a wrong password are refused and the configured one works. The password lives only in the git-ignored `.env`.
- [x] Provisioned (read-only, cannot be deleted from the UI): a Prometheus data source and the "PrimeSEC - Reliability & SLOs" dashboard (6 panels).
- [x] **Every panel's query evaluates**, and the label names they group by exist on the real series. *The supplied dashboard used `integration`/`outcome` labels and `primesoc_` metric names that this app does not produce, so every panel would have been empty.*

## Alert rules (`observability/prometheus/rules/primesec-alerts.yml`)
- [x] Five rules load, validate with `promtool check` and evaluate without error: app-metrics scrape down, Prometheus self-scrape down, integration error ratio above 10%, p95 latency above 5 s, no integration traffic.
- [x] **The error-rate alert reacts to a real failure.** With the demo integrations stopped and failing calls sent, the ratio rose above 10% and the alert went pending, and the Observe page showed it. *The supplied expression returned "no data" (not 0) when nothing had failed yet; fixed with `or vector(0)`.*
- [x] Prometheus no longer exposes the unauthenticated `--web.enable-lifecycle` reload endpoint (it was not needed).
- [ ] **No notifications.** Rules are evaluated and shown, but nothing is sent anywhere: that needs Alertmanager and an approved receiver. Thresholds are examples to tune against real traffic.

## Observe page
- [x] Shows Grafana as a fourth service, a count of firing/pending alerts and their names (only name, severity, state), and links to Grafana and Prometheus' alert page. Response still contains no URLs or ports.

## Notes on reading the numbers
- A Prometheus counter only produces a rate once it has increased between two scrapes. A single burst of traffic then silence shows a rate of 0; this is normal.
- The "SLO" in the dashboard is a starter view, not a contract: there is no error-budget calculation, no 30-day retention (Prometheus keeps 7 days) and no eligibility rules.
