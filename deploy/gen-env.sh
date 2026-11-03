#!/bin/bash
# Crée .env à partir de .env.example en générant chaque secret vide (phase 3 : secrets).
# N'écrase jamais un .env existant. Usage : bash deploy/gen-env.sh
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .env ]; then echo ".env existe déjà : rien n'est modifié."; exit 0; fi

secret() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c "${1:-32}"; }

umask 077
cp .env.example .env
for key in OWNER_DB_PASSWORD INGEST_DB_PASSWORD MCP_DB_PASSWORD APP_DB_PASSWORD \
           OBSERVIA_MCP_TOKEN OBSERVIA_CONSOLE_JWT_SECRET OBSERVIA_IMMUDB_PASSWORD; do
  len=32; [ "$key" = OBSERVIA_CONSOLE_JWT_SECRET ] && len=48
  sed -i "s|^${key}=\$|${key}=$(secret $len)|" .env
done
chmod 600 .env
echo ".env créé (droits 600). Secrets générés pour les comptes de base, le jeton MCP et la console."
echo "À compléter à la main : SMTP, SMS, destinataires, OIDC (sinon secret HS256 du pilote), CONSOLE_BASE_URL."
grep -nE '^(OBSERVIA_SMTP_HOST|OBSERVIA_EMAIL_RECIPIENTS|OBSERVIA_SMS_GATEWAY_URL|OBSERVIA_SMS_RECIPIENTS|OBSERVIA_CONSOLE_BASE_URL)=' .env
