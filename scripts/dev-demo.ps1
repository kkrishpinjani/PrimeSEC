# Starts PrimeSEC in RICH DEMO mode, beside the normal setup and without touching it.
#
#   * a synthetic Wazuh / OpenCTI / Greenbone on :9099 (scripts\demo-integrations.js): ~54 agents, ~2,500 alerts a day from 44 cities,
#     multi-step incidents, ~500 vulnerabilities, ~300 threat-intel indicators, four weeks of scan history
#   * its own data folder (data-demo\), build folder (.next-demo\) and Neo4j namespace (primesec-demo): the real ones are never read or written
#   * the app on http://localhost:3011 (the normal app can keep running on 3010)
#
# Usage:  .\scripts\dev-demo.ps1            start (seeds the demo data the first time)
#         .\scripts\dev-demo.ps1 -Reseed    rebuild the demo data from scratch
param([int]$Port = 3011, [switch]$Reseed)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$demoPort = 9099

# --- environment for everything started below (process env wins over .env) ---
$env:DEMO_INTEGRATIONS = "true"
$env:DEMO_LOGIN = "true"
$env:PRIMESEC_DATA_DIR = "data-demo"
$env:NEXT_DIST_DIR = ".next-demo"
$env:NEO4J_NAMESPACE = "primesec-demo"
$env:NEXTAUTH_URL = "http://localhost:$Port"
$env:WAZUH_API_URL = "http://localhost:$demoPort/wazuh"; $env:WAZUH_API_USERNAME = "demo-wazuh"; $env:WAZUH_API_PASSWORD = "demo-wazuh-pass"
$env:WAZUH_INDEXER_URL = "http://localhost:$demoPort/indexer"; $env:WAZUH_INDEXER_USERNAME = "demo-indexer"; $env:WAZUH_INDEXER_PASSWORD = "demo-indexer-pass"
$env:OPENCTI_URL = "http://localhost:$demoPort/opencti"; $env:OPENCTI_API_TOKEN = "demo-opencti-token"
$env:GREENBONE_BRIDGE_URL = "http://localhost:$demoPort/greenbone"; $env:GREENBONE_BRIDGE_TOKEN = "demo-greenbone-bridge-token"
$env:OPENCTI_ALLOWED_MARKINGS = "TLP:CLEAR,TLP:GREEN"
$env:RESPONSE_EXECUTION_ENABLED = "true"
$env:RESPONSE_ALLOWED_ACTIONS = "watch_asset,isolate_endpoint,block_ip,disable_user,quarantine_file,run_scan"
$env:PRIMESEC_TEAM = "Meridian Group SOC"
$env:PRIMESEC_REGION = "Global"
$env:SYNC_SCHEDULE_MINUTES = "0"
$env:DEMO_QUIET = "true"
Remove-Item Env:NODE_EXTRA_CA_CERTS -ErrorAction SilentlyContinue

# --- demo integrations server ---
$alive = $false
try { $alive = (Invoke-RestMethod "http://127.0.0.1:$demoPort/health" -TimeoutSec 2).ok } catch {}
if (-not $alive) {
  Write-Host "Starting the demo integrations server on :$demoPort ..."
  Start-Process -FilePath "node" -ArgumentList "scripts/demo-integrations.js" -WindowStyle Hidden | Out-Null
  for ($i = 0; $i -lt 30 -and -not $alive; $i++) { Start-Sleep -Milliseconds 500; try { $alive = (Invoke-RestMethod "http://127.0.0.1:$demoPort/health" -TimeoutSec 2).ok } catch {} }
  if (-not $alive) { throw "The demo integrations server did not start." }
}

# --- demo data ---
$seedArgs = @("--experimental-strip-types", "--no-warnings", "scripts/seed-demo.mjs")
if ($Reseed) { $seedArgs += "--reset" }
& node @seedArgs
if ($LASTEXITCODE -ne 0) { throw "Seeding failed." }

Write-Host "`nPrimeSEC demo: http://localhost:$Port  (sign in with the Admin / Analyst / Read-only demo buttons)`n"
try {
  npx next dev -p $Port
} finally {
  # Next rewrites next-env.d.ts to point at the demo build folder; put the tracked file back when the demo stops.
  git checkout -- next-env.d.ts 2>$null
}
