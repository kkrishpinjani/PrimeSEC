$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
foreach ($cmd in 'docker', 'node') {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { Write-Error "$cmd is required. Install it and retry."; exit 1 }
}
docker compose version | Out-Null
if (-not (Test-Path .env)) { Copy-Item .env.example .env }

function New-RandomBytes([int]$n) {
  $b = New-Object byte[] $n
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  $b
}

$env = Get-Content .env -Raw
if ($env -match 'replace-with-a-long-random-secret') {
  $secret = [Convert]::ToBase64String((New-RandomBytes 48))
  $env = $env.Replace('replace-with-a-long-random-secret-generated-by-setup-script', $secret)
}
if ($env -match 'replace-this-local-admin-password') {
  $pass = -join ((New-RandomBytes 16) | ForEach-Object { $_.ToString('x2') })
  $env = $env.Replace('replace-this-local-admin-password', $pass)
  Write-Host 'Generated a local Keycloak admin password and saved it in .env. Keep that file private.'
}
[System.IO.File]::WriteAllText((Join-Path (Get-Location) '.env'), $env)
Write-Host "`nEnvironment prepared. Next run:`n  docker compose up -d`n  npm install`n  npm run dev`n"
