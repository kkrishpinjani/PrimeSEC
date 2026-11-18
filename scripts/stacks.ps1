<#
  Swaps the two heavy local test stacks that do not fit in Docker's 11 GB together, and keeps the Greenbone bridge's scan allow-list
  pointing at the lab container.

    .\scripts\stacks.ps1 status
    .\scripts\stacks.ps1 lab            # (re)start SSH and syslog inside the lab container, so login attempts against it reach Wazuh
    .\scripts\stacks.ps1 use-all         # run EVERYTHING at once (OpenCTI is capped so all four fit in 11 GB; see infra\opencti\compose.primesec.yaml)
    .\scripts\stacks.ps1 use-greenbone    # stop OpenCTI, start Greenbone, give the lab container a FIXED address, refresh the bridge allow-list
    .\scripts\stacks.ps1 use-opencti      # stop Greenbone, start OpenCTI

  Stopping keeps all data. Wazuh and Neo4j are not touched. Nothing here starts a scan.
  After use-greenbone, a SOC_Admin must still approve a PrimeSEC scope for the lab address before anything can be scanned.
#>
param([Parameter(Mandatory = $true)][ValidateSet("status", "lab", "use-all", "use-greenbone", "use-opencti")][string]$Action)

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

# The lab container's startup command runs only the Wazuh agent, so after any restart its SSH server and syslog service are down and login attempts
# against it are either refused or never logged. This starts what is missing (rsyslog supplies the line format Wazuh's SSH rules read).
function Lab-Services($mode) {
    $script = Join-Path $PSScriptRoot "lab-services.sh"
    (Get-Content -Raw $script) -replace "`r`n", "`n" | docker exec -i $labContainer sh -s -- $mode 2>&1
}

function Start-LabServices {
    if (-not (Running "^$labContainer$")) { "Lab container is not running; nothing to start."; return }
    $up = Lab-Services "start"
    if ("$up" -match "yes") { "Lab container: SSH and syslog running." } else { "WARNING: SSH or syslog is not running in the lab container; Wazuh will not see login attempts." }
}

function Show-Status {
    "Wazuh      : {0} containers running" -f (Running "wazuh")
    "OpenCTI    : {0} containers running" -f (Running "primesec-opencti")
    "Greenbone  : {0} containers running" -f (Running "greenbone-community")
    "Neo4j      : {0} containers running" -f (Running "neo4j")
    $mem = docker info --format "{{.MemTotal}}"
    "Docker memory: {0:N1} GB" -f ([double]$mem / 1GB)
    if (Running "^$labContainer$") {
        $up = Lab-Services "check"
        "Lab host   : {0}" -f $(if ("$up" -match "yes") { "SSH and syslog running" } else { "SSH or syslog DOWN (run: .\scripts\stacks.ps1 lab)" })
    }
}

switch ($Action) {
    "status" { Show-Status }

    "lab" { Start-LabServices }

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
                # No quotes inside the template: Windows PowerShell 5.1 strips them when calling docker, which used to make this lookup fail
                # and send every run down the (slow, disruptive) recreate path below.
                $all = "$(docker inspect $labContainer --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}};{{end}}' 2>$null)"
                $cur = if ($all -match "(?:^|;)$([regex]::Escape($gbNetwork))=([0-9.]*);") { $Matches[1] } else { "" }
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

            # The page behind the dashboard's one-click Greenbone sign-in has to live in Greenbone's own web volume (its web root is mounted
            # read-only, so it cannot be a compose mount). Copying it is idempotent and survives a Greenbone image upgrade that clears the volume.
            $handoff = (Resolve-Path (Join-Path $PSScriptRoot "..\bridge\primesec-handoff.html")).Path
            $null = docker run --rm -v greenbone-community-edition_gsa_data_vol:/v -v "${handoff}:/src/h.html:ro" alpine sh -c "cp /src/h.html /v/primesec-handoff.html && chmod 644 /v/primesec-handoff.html" 2>&1
            if ($LASTEXITCODE -eq 0) { "One-click sign-in page installed in Greenbone." } else { "WARNING: could not install the one-click sign-in page; Greenbone will ask for its login." }
        } finally { Pop-Location }
        if ($Action -eq "use-all") {
            Push-Location $octi; try { $null = docker compose -f compose.primesec.yaml up -d 2>&1 } finally { Pop-Location }
            "Greenbone and OpenCTI are both running."
        } else { "OpenCTI stopped, Greenbone running." }
        Start-LabServices
        "A SOC_Admin must approve a PrimeSEC scope for $labIp before it can be scanned."
        Show-Status
    }
}
