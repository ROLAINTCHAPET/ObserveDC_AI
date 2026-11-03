#!/bin/bash
# Construit et démarre la plateforme (phases 4 à 9), en mode ombre, sur CPU.
# Usage : bash deploy/up.sh            (relançable sans risque)
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || bash deploy/gen-env.sh
set -a; . ./.env; set +a
MODEL="${OBSERVIA_MODEL_NAME:-qwen2.5:7b-instruct}"
EMBED="${OBSERVIA_EMBED_MODEL:-nomic-embed-text}"

step() { echo; echo "=== $*"; }

step "1/5 Construction de l'image applicative"
docker compose build

step "2/5 Base de données, politiques, logs, modèle (sans les services applicatifs)"
docker compose up -d db opa loki ollama
docker compose run --rm migrate
echo "Migrations appliquées."

step "3/5 Modèles locaux ($MODEL, $EMBED) — premier lancement : plusieurs Go à télécharger"
docker compose --profile setup run --rm -e MODEL="$MODEL" -e EMBED_MODEL="$EMBED" ollama-pull

step "4/5 Services ObservIA"
docker compose up -d

step "5/5 Vérifications"
sleep 10
docker compose ps --format 'table {{.Service}}\t{{.Status}}'
fail=0
for svc in ingestion detection mcp agent notifier knowledge console-api; do
  state=$(docker compose ps --format '{{.Service}} {{.State}}' | awk -v s="$svc" '$1==s {print $2}')
  [ "$state" = running ] && echo "  [OK] $svc" || { echo "  [KO] $svc ($state) : docker compose logs $svc"; fail=1; }
done
curl -sf http://localhost:8000/healthz >/dev/null && echo "  [OK] ingestion /healthz" || { echo "  [KO] ingestion /healthz"; fail=1; }
curl -sf http://localhost:8080/healthz >/dev/null && echo "  [OK] console-api /healthz" || { echo "  [KO] console-api /healthz"; fail=1; }
[ $fail = 0 ] && echo "Plateforme démarrée. Étape suivante : bash deploy/smoke.sh" || { echo "Des services sont en échec."; exit 1; }
