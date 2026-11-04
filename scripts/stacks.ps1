<#
  Swaps the two heavy local test stacks that do not fit in Docker's 11 GB together, and keeps the Greenbone bridge's scan allow-list
  pointing at the lab container.

    .\scripts\stacks.ps1 status
    .\scripts\stacks.ps1 use-all         # run EVERYTHING at once (OpenCTI is capped so all four fit in 11 GB; see infra\opencti\compose.primesec.yaml)
    .\scripts\stacks.ps1 use-greenbone    # stop OpenCTI, start Greenbone, give the lab container a FIXED address, refresh the bridge allow-list
    .\scripts\stacks.ps1 use-opencti      # stop Greenbone, start OpenCTI

  Stopping keeps all data. Wazuh and Neo4j are not touched. Nothing here starts a scan.
  After use-greenbone, a SOC_Admin must still approve a PrimeSEC scope for the lab address before anything can be scanned.
#>
param([Parameter(Mandatory = $true)][ValidateSet("status", "use-all", "use-greenbone", "use-opencti")][string]$Action)

# Docker writes progress to stderr; in Windows PowerShell 5.1 that would become a terminating error under "Stop", so errors are judged by exit code instead.
$ErrorActionPreference = "Continue"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$gb = Join-Path $root "infra\greenbone"
$octi = Join-Path $root "infra\opencti"
$labContainer = "wazuh-agent-lab"
$gbNetwork = "greenbone-community-edition_default"
# A fixed address inside Greenbone's network (192.168.16.0/20), far from the dynamic range, so a restart cannot change it.
$labIp = if ($env:LAB_FIXED_IP) { $env:LAB_FIXED_IP } else { "192.168.16.200" }
$gbCompose = @("compose", "-f", "compose.yaml", "-f", "compose.bridge.yaml")

function Running($pattern) { @(docker ps --format "{{.Names}}" | Where-Object { $_ -match $pattern }).Count }

function Show-Status {
    "Wazuh      : {0} containers running" -f (Running "wazuh")
    "OpenCTI    : {0} containers running" -f (Running "primesec-opencti")
    "Greenbone  : {0} containers running" -f (Running "greenbone-community")
    "Neo4j      : {0} containers running" -f (Running "neo4j")
    $mem = docker info --format "{{.MemTotal}}"
    "Docker memory: {0:N1} GB" -f ([double]$mem / 1GB)
}

switch ($Action) {
    "status" { Show-Status }

    "use-opencti" {
        Push-Location $gb;   try { $null = docker @gbCompose stop 2>&1 } finally { Pop-Location }
        Push-Location $octi; try { $null = docker compose -f compose.primesec.yaml start 2>&1 } finally { Pop-Location }
        "Greenbone stopped, OpenCTI started."
        Show-Status
    }

    { $_ -in "use-greenbone", "use-all" } {
        # use-greenbone frees memory by stopping OpenCTI; use-all keeps it (it is memory-capped) and starts it afterwards.
        if ($Action -eq "use-greenbone") { Push-Location $octi; try { $null = docker compose -f compose.primesec.yaml stop 2>&1 } finally { Pop-Location } }
        Push-Location $gb
        try {
            # A first `up` can hit a Docker race on nested volumes ("failed to mkdir ... gnupg: file exists"); one retry clears it.
            $null = docker @gbCompose up -d 2>&1
            if ($LASTEXITCODE -ne 0) { $null = docker @gbCompose up -d 2>&1 }
            $ready = $false
            foreach ($i in 1..40) {
                try { if ((Invoke-WebRequest -Uri "http://127.0.0.1:8787/health" -UseBasicParsing -TimeoutSec 5).StatusCode -eq 200) { $ready = $true; break } } catch { }
                Start-Sleep 6
            }
            if (-not $ready) { throw "The Greenbone bridge did not become healthy. Check: docker compose logs primesec-bridge" }

            # Give the lab container a fixed address on Greenbone's network.
            function Attach-Lab {
                $cur = docker inspect $labContainer --format "{{with index .NetworkSettings.Networks `"$gbNetwork`"}}{{.IPAddress}}{{end}}" 2>$null
                if ($cur -eq $labIp) { return "already" }
                if ($cur) { $null = docker network disconnect $gbNetwork $labContainer 2>&1 }
                $null = docker network connect --ip $labIp $gbNetwork $labContainer 2>&1
                if ($LASTEXITCODE -eq 0) { return "attached (was: $(if ($cur) { $cur } else { 'not connected' }))" }
                return $null
            }
            $result = Attach-Lab
            if (-not $result) {
                # The network was created without an explicit subnet (older runs). Recreate it once from the compose files: volumes and data are kept.
                "Recreating Greenbone's network with an explicit subnet (one-time; data is kept)..."
                $null = docker network disconnect $gbNetwork $labContainer 2>&1
                $null = docker @gbCompose down 2>&1
                $null = docker @gbCompose up -d 2>&1
                if ($LASTEXITCODE -ne 0) { $null = docker @gbCompose up -d 2>&1 }
                foreach ($i in 1..40) {
                    try { if ((Invoke-WebRequest -Uri "http://127.0.0.1:8787/health" -UseBasicParsing -TimeoutSec 5).StatusCode -eq 200) { break } } catch { }
                    Start-Sleep 6
                }
                $result = Attach-Lab
                if (-not $result) { throw "Could not attach $labContainer at $labIp. Is it inside the Greenbone network's subnet (192.168.16.0/24)?" }
            }
            "Lab container at ${labIp}: $result."

            # Refresh the bridge's own allow-list so it can scan exactly that one address and nothing else.
            $envFile = Join-Path $gb ".env"
            $want = "GREENBONE_ALLOWED_RANGES=$labIp/32"
            $have = if (Test-Path $envFile) { (Get-Content $envFile -Raw).Trim() } else { "" }
            if ($have -ne $want) {
                Set-Content $envFile -Value $want -Encoding ascii
                $null = docker @gbCompose up -d primesec-bridge 2>&1
                "Bridge allow-list set to $labIp/32."
            } else { "Bridge allow-list already $labIp/32." }
        } finally { Pop-Location }
        if ($Action -eq "use-all") {
            Push-Location $octi; try { $null = docker compose -f compose.primesec.yaml up -d 2>&1 } finally { Pop-Location }
            "Greenbone and OpenCTI are both running."
        } else { "OpenCTI stopped, Greenbone running." }
        "A SOC_Admin must approve a PrimeSEC scope for $labIp before it can be scanned."
        Show-Status
    }
}
