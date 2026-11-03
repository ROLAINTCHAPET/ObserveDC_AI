#!/bin/bash
# Comptes de connexion par rôle (feuille de route, phase 4) : écriture (ingestion),
# lecture seule (outils MCP), application. Exécuté une seule fois, à l'initialisation
# du volume. Les droits sont accordés aux rôles de groupe par migrations/002.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v ingest_pw="$INGEST_DB_PASSWORD" -v mcp_pw="$MCP_DB_PASSWORD" -v app_pw="$APP_DB_PASSWORD" <<'SQL'
CREATE ROLE observia_ingest_role NOLOGIN;
CREATE ROLE observia_reader_role NOLOGIN;
CREATE ROLE observia_app_role NOLOGIN;
CREATE ROLE observia_ingest LOGIN PASSWORD :'ingest_pw' IN ROLE observia_ingest_role;
CREATE ROLE observia_mcp    LOGIN PASSWORD :'mcp_pw'    IN ROLE observia_reader_role;
CREATE ROLE observia_app    LOGIN PASSWORD :'app_pw'    IN ROLE observia_app_role;
SQL
