# Phase II: what was built, in order

Source: `PhaseII.zip` (nine cumulative Python/FastAPI builds plus the Wazuh integration notes). Each build contained the one before it, so the last one (continuous sync v1.5) held everything. PrimeSEC already had Wazuh, OpenCTI, Greenbone, correlation, investigations and an action gateway, so only what was **new** was ported, to TypeScript, in the same style as the SAP module (JSON-file stores, no new dependencies).

| # | Package in the zip | In PrimeSEC | Where |
|---|---|---|---|
| 1 | Wazuh platform and full Wazuh connectivity | **New**: a read-only explorer for 21 fixed resources (manager and cluster state, agents, syscheck, rootcheck, SCA, OS, vulnerabilities, alerts, rules, decoders, groups, MITRE data), an optional agent allow-list, and a page for it. | `lib/wazuh.ts`, `/wazuh`, `/api/wazuh/[resource]` |
| 2 | OpenCTI connectivity | **New**: browse indicators, reports, threat actors, vulnerabilities and malware, observable search and entity detail, with a strict marking policy. | `lib/opencti.ts`, `/opencti`, `/api/opencti/[kind]` |
| 3 | Threat-intel correlation | **Extended**: alerts now also yield CVE ids (looked up in OpenCTI by exact id, with CISA's known-exploited flag) and MITRE technique ids. | `lib/correlation.ts`, `lib/investigate.ts` |
| 3b | Investigation / agentic SOC | **New**: investigation cases (owner, lifecycle, evidence, timeline), a rule-based plan, and response proposals tied to the case. | `lib/cases.ts`, `/cases`, `/api/cases/*` |
| 3c | OpenVAS console | **Extended**: a read-only view of scanners, scan configs, port lists, schedules, alert definitions (names only) and feed status. | `bridge/server.py`, `lib/vapt.ts`, `ScanPlatformPanel` |
| 4 | Unified asset intelligence v1.4 | **New**: canonical inventory, identity matching, vulnerability dedup, exposure score. | `lib/inventory.ts`, `/inventory`, `/api/inventory` |
| 5 | Continuous sync v1.5 | **New**: Wazuh, Greenbone-findings and OpenCTI sync with run history, watermarks and an overlap guard. | `lib/sync.ts`, `lib/syncSources.ts`, `/api/sync` |
| 6 | Governed response engine | **New**: proposals, separate approver, policy gates, idempotent execution, verify, rollback. **Execution is off.** The only adapter that ships acts inside PrimeSEC alone (`watch_asset`, see below). | `lib/response.ts`, `/response`, `/api/response/*` |
| 7 | Neo4j security graph | **New**: allow-listed labels, namespaced nodes, atomic upsert, exposure and path queries, projection from the inventory. | `lib/graph.ts`, `/inventory` (Graph tab), `/api/graph/*` |

Tests: `npm run test:inventory | test:sync | test:response | test:graph | test:cases | test:wazuh | test:opencti | test:investigate | test:bridge | test:scheduler` (about 420 checks). `npm test` runs all 21 suites.

## Deliberate differences from the Python packages

The packages were multi-tenant. PrimeSEC is single-organisation, so there is no tenant argument; the graph keeps a `tenant_id` namespace property (`NEO4J_NAMESPACE`) so a shared Neo4j cannot mix deployments.

Fixed rather than copied:

- **Criticality** defaulted to 3 and only ever went up, so a CMDB value of 2 was silently raised and a downgrade never applied. Now a source that does not know leaves it alone, each source's claim is tracked, and the asset takes the highest across sources. "Not rated" stays visible and is scored as 3.
- **Execute with a repeated `Idempotency-Key`** returned 409 after a success, because the policy check ran before the key lookup. The key is now checked first and returns the stored result.
- **A failed execution** left the proposal approved, so a retry with a new key could repeat a half-applied action. It is now locked as `execution_failed`; a person inspects it and proposes again.
- **Two concurrent executes** could both pass the policy check. The execution record and the `executing` state are now one atomic write.
- **Audit failure** now stops execution (the "requested" audit record is written before the adapter is called).
- **Reviewer** may not be the proposer (the package only checked the executor).
- **Sync failures** store a short sanitised message, never a URL or upstream body.

## Known limits (be honest about these)

- **Everything was run against real local instances** (Wazuh 4.14.9, Greenbone 22.7, OpenCTI 7.261030.1, Neo4j 5 Community), not only test doubles. That found real bugs, listed below. It does not prove behaviour on other versions, at scale, or with real traffic.
- **The same machine seen by two tools starts as two assets** (the package's policy: never merge on IP or hostname). An analyst now reconciles them on the Duplicates tab; there is no automatic undo for a merge.
- A source that stops reporting an asset, or a finding a scan stops reporting, is **flagged, never closed**: only an analyst closes a finding.
- The sync scheduler runs inside the Next.js server process and is off unless `SYNC_SCHEDULE_MINUTES` is set. With several instances each would run its own; overlap is refused in-process only.
- JSON-file stores suit one instance. Use a database before running more than one.
- OpenCTI marking enforcement needs `OPENCTI_ALLOWED_MARKINGS`; unset means no restriction.
- Graph projection copies assets and open vulnerabilities only. Alerts, indicators, actors and techniques have node types but nothing feeds them yet.
- **OpenCTI indicators are few**: only the 5 abuse.ch Feodo Tracker C2 addresses (see `scripts/import-feodo-indicators.mjs`). Every other free IOC feed needs an account key, so alert-to-indicator correlation can only match those until a keyed feed is added.
- **Investigation plans are rule-based checklists**, not AI. Technique ids from alerts are shown for context and are deliberately not used to match indicators.
- Wazuh and OpenCTI explorers and cases are visible to every PrimeSEC role; changing a case needs SOC_Analyst or SOC_Admin.
- Neo4j Community has no role-based access control: PrimeSEC uses its single built-in user, on a loopback-only port.

## The one adapter that ships: `watch_asset`

`lib/responseAdapters.ts` registers an adapter named `inventory-watch` the first time the response API is used. It supports a single action, `watch_asset`, whose target is an inventory asset id. Executing it adds the tag `watchlist` to that asset; verify checks the tag is present; rollback removes it, but only when that execution is the one that added it.

It touches no other system, and it is still inert until an administrator sets `RESPONSE_EXECUTION_ENABLED=true` and lists `watch_asset` in `RESPONSE_ALLOWED_ACTIONS`. The approval rules (a different admin approves, approvals expire, idempotency key required) apply to it like any other action. It exists so the whole Response page can be exercised end to end without any risk. Acting on real systems (blocking an address, isolating a host) still needs its own adapter.

## Turning on a real response action (do not do this casually)

1. Write an adapter implementing `ResponseAdapter` in `lib/response.ts` for one narrow action, with provider-side idempotency, a real `verify` and a real `rollback`.
2. Call `registerAdapter(...)` from server start-up code.
3. Set `RESPONSE_EXECUTION_ENABLED=true` and `RESPONSE_ALLOWED_ACTIONS=<that exact action>`.
4. Rehearse in a non-production environment first.

## Configuration added (`.env.example`)

`OPENCTI_ALLOWED_MARKINGS`, `RESPONSE_EXECUTION_ENABLED`, `RESPONSE_ALLOWED_ACTIONS`, `RESPONSE_MAX_TARGET_LENGTH`, `RESPONSE_APPROVAL_MAX_AGE_MINUTES`, `RESPONSE_REQUIRE_DUAL_CONTROL`, `NEO4J_HTTP_URL`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`, `NEO4J_DATABASE`, `NEO4J_NAMESPACE`.

## Local Wazuh test stack (real, free)

Lives in `infra/wazuh-docker/single-node` (official Wazuh v4.14.9 Docker setup, git-ignored because it holds private keys). Every port is bound to `127.0.0.1`; the dashboard is `https://localhost:8443`. Docker Desktop needs about 11 GB (`~/.wslconfig`: `memory=11GB`, plus `sysctl.vm.max_map_count=262144`).

- Start/stop: `docker compose up -d` / `docker compose down` in that folder. A test agent runs as the container `wazuh-agent-lab` (name `lab-ubuntu-01`).
- Wazuh's certificates are issued for `wazuh.manager` / `wazuh.indexer`, so the Windows hosts file needs `127.0.0.1 wazuh.manager wazuh.indexer wazuh.dashboard` (administrator, one time).
- The Manager API uses its own self-signed certificate, valid for `localhost`, so `.env` uses `https://localhost:55000` for it and `https://wazuh.indexer:9200` for the Indexer.
- Node reads `NODE_EXTRA_CA_CERTS` only at start-up, so run the app with `scripts/dev-real.ps1` (it trusts `ca-bundle.pem`: the stack's CA plus the API certificate). Certificate checks are never disabled. If the Wazuh volumes are recreated the API certificate changes; regenerate `ca-bundle.pem`.
- PrimeSEC uses two read-only accounts, `primesec-ro` (Manager API) and `primesec-idx` (Indexer). The stack's default admin passwords are unchanged but unreachable from the network.

## Local Greenbone test stack (real, free)

Lives in `infra/greenbone` (the official Greenbone Community Edition compose file, `compose.yaml`, plus `compose.bridge.yaml` which runs PrimeSEC's bridge beside it). Git-ignored: it holds secrets in `infra/greenbone/secrets/` (bridge token, the `primesec` GMP login, an admin password). Web UI: `https://127.0.0.1:443` (user `admin`, password in `secrets/admin-password`). Every port is bound to `127.0.0.1`.

- Start/stop: `docker compose -f compose.yaml -f compose.bridge.yaml up -d` / `down` in that folder. If the first `up` fails with "failed to mkdir ... gnupg: file exists" (a Docker race on nested volumes), run it again.
- The bridge runs as the non-root user `65534` (`gvm-cli` refuses root) and reads its token and GMP login from read-only files, never from the environment. `.env` in `infra/greenbone` sets `GREENBONE_ALLOWED_RANGES`, the bridge's own second allow-list; it is set to exactly the lab host (`192.168.16.19/32`). **The lab container's IP can change when it is recreated; update that value if so.**
- PrimeSEC's `.env`: `GREENBONE_BRIDGE_URL=http://127.0.0.1:8787` and `GREENBONE_BRIDGE_TOKEN` (same value as `secrets/bridge-token`).
- The scan target is the Wazuh test agent container `wazuh-agent-lab`, attached to Greenbone's network. An approved PrimeSEC scope covers only that one address; a neighbouring address is refused by PrimeSEC before the bridge is called.
- First feed load took a few minutes here (the scanner reported "Finished loading VTs" about two minutes after start); allow longer on slow disks.
- Result of the first scan: only low and informational items, because the container exposes no services. That is a true result, not a failure.
- The same machine appears twice in the inventory (`lab-ubuntu-01` from Wazuh, `192.168.16.19` from Greenbone). That is the documented identity policy; an analyst merge screen is not built.

## Local OpenCTI test stack (real, free)

Lives in `infra/opencti` (OpenCTI's official `docker-compose.yml` is kept as a reference; the file we run is `compose.primesec.yaml`: the platform, one worker, and three free keyless connectors, with OpenCTI's optional XTM One / composer / pgvector services and the import connectors left out to fit a laptop). Git-ignored; secrets are in `infra/opencti/.env`. Pinned to release `7.261030.1`. Web UI: `http://localhost:8081` (user `admin@primesec.local`, password in `infra/opencti/.env` as `OPENCTI_ADMIN_PASSWORD`); published on `127.0.0.1` only (8081, because Keycloak holds 8080).

- Start/stop: `docker compose -f compose.primesec.yaml up -d` / `stop`. Needs about 5 GB of Docker memory, so Greenbone (about 3 GB) was stopped while it runs; they do not both fit in 11 GB next to Wazuh.
- Feeds loaded: OpenCTI datasets (markings, identities, locations), MITRE ATT&CK, and CISA's Known Exploited Vulnerabilities list. **There are no indicators (IOCs) yet**, because every free IOC feed needs a free account key (abuse.ch URLhaus/ThreatFox, AlienVault OTX). Without indicators, alert investigations find no matches.
- PrimeSEC uses a dedicated user `primesec-ro` in the group `PrimeSEC read-only`, with a custom role that has only `KNOWLEDGE` (view), `APIACCESS` and `APIACCESS_USETOKEN`, and a 365-day token. OpenCTI 7 refuses any API token unless the user's role has `APIACCESS_USETOKEN`. Verified: it can read; creating an indicator and listing users are refused.
- The group may see only `TLP:CLEAR` and `TLP:GREEN` objects; PrimeSEC's `OPENCTI_ALLOWED_MARKINGS` is set to the same two. Anything else is invisible to the account.
- Bug found by running against the real platform and fixed: in OpenCTI 7 `objectMarking` is a plain list, not a paged connection (`lib/integrations.ts` now tries the list form, then the older connection form).

## Bugs found only by running against the real platforms

These all passed their unit tests first, which is why the live runs mattered.

- **OpenCTI 7 `objectMarking`** is a plain list, not a paged connection, so the first sync query failed. Both shapes are now tried.
- **OpenCTI 7 observables** have `created_at`/`updated_at`, not `created`/`modified`.
- **OpenCTI 7 refuses any API token** unless the user's role has `APIACCESS_USETOKEN`; the built-in `Default` role does not.
- **Wazuh 4.8+ removed the Manager API vulnerability endpoints**, so per-agent vulnerabilities come from the Indexer.
- **A least-privilege Wazuh account** needs a read policy per area (manager, syscheck, rootcheck, SCA, syscollector, rules, decoders, MITRE); `agent:read` alone returns 403 for most of the explorer.
- **A standalone Wazuh manager** answers cluster-node queries with 400. That is now reported as "not part of a cluster".
- **`gvm-cli` refuses to run as root**, so the bridge container runs as a non-root user.
- **The CISA connector option** `CISA_CREATE_VULNERABILITIES` does not exist (checked against the connector's source).
- **The marking rule in the package** showed an object if any of its markings was allowed (so TLP:CLEAR plus TLP:RED was visible). PrimeSEC hides it if any marking is outside the allow-list.

## Running everything at once, and what it costs

All four platforms run together in an 11 GB Docker allocation (`~/.wslconfig`: `memory=11GB`, `swap=4GB`). Measured with everything up plus the Dify stack and the other containers: about 8.4 GB (77%), nothing killed for memory.

| Stack | Memory | Notes |
|---|---|---|
| OpenCTI | about 3.1 GB | Capped: Elasticsearch heap 1 GB (`ELASTIC_MEMORY_SIZE` in `infra/opencti/.env`), Node 1.5 GB, and a `mem_limit` on each service in `compose.primesec.yaml`. Fine for thousands of objects; raise the caps for a large intelligence base. |
| Wazuh | about 1.7 GB | |
| Greenbone | about 1.5 GB idle (up to about 2.7 GB while loading feeds the first time) | |
| Neo4j | about 0.7 GB | capped at 1.2 GB |

- **Start or check everything:** `scripts\stacks.ps1 use-all` (idempotent: it also re-attaches the lab container at its fixed address `192.168.16.200` and keeps the Greenbone bridge allow-list at exactly that address). `status` shows what is running. `use-greenbone` / `use-opencti` swap one for the other if memory is ever short again.
- **Dashboard links:** the Platforms menu lists Wazuh, Greenbone, OpenCTI and Neo4j. Each is probed when the page loads and is greyed out, with the command to start it, if it is not running. Set `OPENCTI_DASHBOARD_URL` and `NEO4J_BROWSER_URL` (and the Wazuh/Greenbone ones) in `.env`.
- **Neo4j Browser:** open http://127.0.0.1:7474, connect to `bolt://localhost:7687` as `neo4j` (password in `infra/neo4j/.env`). Both ports are published on 127.0.0.1 only.
- **Scanning:** a SOC_Admin approves a PrimeSEC scope for `192.168.16.200` (done for 2 days on 2026-11-04); only then can VAPT launch a scan, and the bridge independently allows only that one address.

## Added in the final pass

- **Indicators with no key.** `node scripts/import-feodo-indicators.mjs` imports abuse.ch Feodo Tracker botnet C2 IPs (public, CC0) as TLP:CLEAR indicators through the OpenCTI API, using the local admin token. Idempotent. Verified end to end: a real Wazuh alert for SSH attempts from `50.16.16.211` was matched to "Feodo Tracker C2 50.16.16.211:443 (QakBot)" and opened as a case with that match.
- **Asset merge** (Inventory, Duplicates tab). Suggestions come from a shared IP or host name; any two assets can also be picked by hand, because an agent's address and a scanner's view often share nothing. Both need a written reason, which is recorded on the asset and in the audit log. A merge is refused when both assets are reported by the same source (that source already says they differ). The merged-away identity stays as an alias, so later reports of it land on the survivor. The source that created an asset owns its name; another source never renames it.
- **Staleness flags.** An asset is shown as "possibly gone" when a source has not reported it for `INVENTORY_STALE_DAYS` (default 7). A finding its source stopped reporting is marked "not in the latest sync". Both are display flags only.
- **Graph pruning.** Projecting the inventory now removes what an earlier projection created and the inventory no longer has (merged-away assets, closed findings), touching only nodes stamped `origin:"inventory"`; nodes added through the ingest API are never deleted.
- **Sync scheduler.** `SYNC_SCHEDULE_MINUTES` (5 to 1440) runs the same read-only syncs automatically, first pass a minute after start-up, recorded in history and audit as "scheduler". It never calls Greenbone and never starts a scan.
- **Wazuh text search** was returning 400 because OpenSearch rejects a multi-field query across mixed field types; it is now lenient.
- **Stack swapping and a fixed lab address.** `scripts\stacks.ps1 status | use-greenbone | use-opencti` swaps the two heavy stacks and, for Greenbone, attaches the lab container at the fixed address `192.168.16.200` on a subnet declared in `compose.bridge.yaml` (Docker only allows a fixed address on a network with an explicit subnet, so the network was recreated once; volumes were kept) and sets the bridge allow-list to exactly that address. Verified: the address survives a container restart. A SOC_Admin must still approve a PrimeSEC scope for it before anything is scanned.

## Final frontend pass

- **Wazuh in the Platforms menu** is now checked with a plain TCP connect to the dashboard port (an HTTPS probe would reject its self-signed certificate), so it greys out like the others when the stack is down.
- **Graph tab** draws the connections from an asset as a diagram (`components/GraphDiagram.tsx`, plain SVG, no dependency), with the text form kept under "Show as text".
