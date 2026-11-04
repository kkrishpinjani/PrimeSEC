# Starts PrimeSEC trusting the local Wazuh test stack's CA (Node reads NODE_EXTRA_CA_CERTS only at process start,
# so it cannot live in .env). Needs the hosts entries for wazuh.manager / wazuh.indexer (see docs/phase2.md).
$ca = Join-Path $PSScriptRoot "..\infra\wazuh-docker\single-node\config\wazuh_indexer_ssl_certs\ca-bundle.pem"
$env:NODE_EXTRA_CA_CERTS = (Resolve-Path $ca).Path
Set-Location (Join-Path $PSScriptRoot "..")
npm run dev
