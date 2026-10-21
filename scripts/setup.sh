#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v docker >/dev/null 2>&1; then echo "ERROR: Docker is required. Install Docker Desktop and retry." >&2; exit 1; fi
if ! docker compose version >/dev/null 2>&1; then echo "ERROR: Docker Compose v2 is required." >&2; exit 1; fi
if ! command -v node >/dev/null 2>&1; then echo "ERROR: Node.js 20 LTS or newer is required." >&2; exit 1; fi
if ! command -v openssl >/dev/null 2>&1; then echo "ERROR: openssl is required to generate local secrets." >&2; exit 1; fi
if [ ! -f .env ]; then cp .env.example .env; fi
if grep -q 'replace-with-a-long-random-secret' .env; then
  SECRET="$(openssl rand -base64 48 | tr -d '\n')"
  if [[ "$OSTYPE" == "darwin"* ]]; then sed -i '' "s|replace-with-a-long-random-secret-generated-by-setup-script|$SECRET|" .env; else sed -i "s|replace-with-a-long-random-secret-generated-by-setup-script|$SECRET|" .env; fi
fi
if grep -q 'replace-this-local-admin-password' .env; then
  PASS="$(openssl rand -hex 16)"
  if [[ "$OSTYPE" == "darwin"* ]]; then sed -i '' "s|replace-this-local-admin-password|$PASS|" .env; else sed -i "s|replace-this-local-admin-password|$PASS|" .env; fi
  echo "Generated a local Keycloak admin password and saved it in .env. Keep that file private."
fi
printf '\nEnvironment prepared. Next run:\n  docker compose up -d\n  npm install\n  npm run dev\n\n';
