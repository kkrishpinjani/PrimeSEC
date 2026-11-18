<#
  Brings the whole PrimeSEC lab back after a PC restart, in the right order, and is safe to run again when things are already up:

    1. Docker Desktop (started if it is not running; waits until its engine answers)
    2. Wazuh, OpenCTI, Greenbone and Neo4j        (scripts\stacks.ps1 use-all: also re-attaches the lab host and restarts its SSH + syslog)
    3. The PrimeSEC app on http://localhost:3010   (scripts\dev-real.ps1, so it trusts the local Wazuh certificate)

    .\scripts\start-all.ps1                    # start everything
    .\scripts\start-all.ps1 -NoApp             # only Docker and the platforms
    .\scripts\start-all.ps1 -InstallAutostart  # run this automatically, a minute after you sign in to Windows
    .\scripts\start-all.ps1 -RemoveAutostart   # undo that

  Nothing here starts a scan or changes any data.
#>
param([switch]$NoApp, [switch]$InstallAutostart, [switch]$RemoveAutostart)

$ErrorActionPreference = "Continue"
$taskName = "PrimeSEC start-all"
$self = $MyInvocation.MyCommand.Path

if ($RemoveAutostart) {
    schtasks /Delete /TN $taskName /F 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { "Autostart removed." } else { "No autostart task was found." }
    return
}
if ($InstallAutostart) {
    $action = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$self`""
    schtasks /Create /TN $taskName /TR $action /SC ONLOGON /DELAY 0001:00 /RL LIMITED /F 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { "Autostart installed: PrimeSEC will start about a minute after you sign in to Windows. Remove it with: .\scripts\start-all.ps1 -RemoveAutostart" }
    else { "Could not create the scheduled task. Try from an administrator PowerShell." }
    return
}

function Say($m) { "[{0:HH:mm:ss}] {1}" -f (Get-Date), $m }

# docker can hang while its engine is stuck, so every probe runs in a job with a timeout.
function Test-Docker {
    $job = Start-Job { docker info --format "{{.ServerVersion}}" 2>&1 }
    if (-not (Wait-Job $job -Timeout 20)) { Stop-Job $job; Remove-Job $job -Force; return $false }
    $out = "$(Receive-Job $job)"; Remove-Job $job -Force
    return ($out -match "^\d+\.\d+")
}

# ---- 1. Docker Desktop ----
if (Test-Docker) { Say "Docker is already running." }
else {
    $exe = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    if (-not (Test-Path $exe)) { Say "Docker Desktop was not found at $exe. Install it or start it yourself, then run this again."; return }
    if (-not (Get-Process "Docker Desktop" -ErrorAction SilentlyContinue)) { Say "Starting Docker Desktop..."; Start-Process $exe }
    $up = $false
    foreach ($i in 1..40) {
        if (Test-Docker) { $up = $true; break }
        Start-Sleep 6
    }
    if (-not $up) {
        Say "Docker's engine did not answer after about 5 minutes."
        "  If it keeps saying '500 Internal Server Error': quit Docker Desktop (tray icon > Quit), run  wsl --shutdown  and then run this script again."
        return
    }
    Say "Docker is up."
}

# ---- 2. the platforms ----
Say "Starting Wazuh, OpenCTI, Greenbone and Neo4j (this can take a few minutes)..."
& (Join-Path $PSScriptRoot "stacks.ps1") use-all

# ---- 3. the app ----
if ($NoApp) { Say "Skipping the app (-NoApp)."; return }
$listening = Get-NetTCPConnection -LocalPort 3010 -State Listen -ErrorAction SilentlyContinue
if ($listening) { Say "The PrimeSEC app is already running." }
else {
    Say "Starting the PrimeSEC app..."
    Start-Process powershell -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $PSScriptRoot "dev-real.ps1") -WindowStyle Minimized
}
$ready = $false
foreach ($i in 1..40) {
    try { if ((Invoke-WebRequest -Uri "http://localhost:3010/login" -UseBasicParsing -TimeoutSec 8).StatusCode -eq 200) { $ready = $true; break } } catch { }
    Start-Sleep 4
}

""
if ($ready) {
    Say "Ready."
    "  PrimeSEC   http://localhost:3010   (Platforms menu opens Wazuh, Greenbone, OpenCTI and Neo4j already signed in)"
} else {
    Say "The app has not answered yet. It can need another minute on the first page load; if it never does, run .\scripts\dev-real.ps1 in a terminal to see why."
}
"  Check later with: .\scripts\stacks.ps1 status"
