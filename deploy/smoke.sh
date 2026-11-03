#!/bin/bash
# Essai de bout en bout sur la plateforme déployée (feuille de route, test T1), sans doublure :
#   relevés de surchauffe → incident → investigation par le vrai modèle → décision du garde-fou
#   → notification → retour à la normale → clôture → vérification de la chaîne d'audit.
# Utilise une baie de test dédiée (smoke-rack-01, environnement TEST) et une source dédiée,
# désactivées à la fin pour ne pas déclencher d'alerte « source / équipement muet ».
# Durée : 10 à 20 min sur CPU (investigation + stabilisation avant clôture).
# Usage : bash deploy/smoke.sh
set -uo pipefail
cd "$(dirname "$0")/.."
EQ=smoke-rack-01
SRC="smoke-$(date +%Y%m%d%H%M)"
PASS=0; FAIL=0
ok() { echo "  [OK] $*"; PASS=$((PASS + 1)); }
ko() { echo "  [KO] $*"; FAIL=$((FAIL + 1)); }
sql() { docker compose exec -T db psql -U observia -d observia -tAc "$1"; }
admin() { docker compose run --rm -T migrate python -m shared.admin "$@"; }
send() {  # $1 = température de base ; ±0–2 °C pour ne pas déclencher la règle « valeur figée » (S3)
  local value=$(( $1 + RANDOM % 3 ))
  curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8000/ingest/events \
    -H "X-Source-Key: $KEY" -H 'Content-Type: application/json' \
    -d "[{\"equipment\":\"$EQ\",\"metric\":\"temperature\",\"value\":$value,\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}]"
}
wait_for() {  # $1 = description, $2 = requête SQL non vide attendue, $3 = délai max (s), $4 = température à envoyer
  local deadline=$((SECONDS + $3)) value=""
  while [ $SECONDS -lt $deadline ]; do
    [ -n "${4:-}" ] && send "$4" >/dev/null
    value=$(sql "$2")
    [ -n "$value" ] && { echo "$value"; return 0; }
    sleep 10
  done
  return 1
}

echo "=== 1. Baie et source de test"
admin add-equipment "$EQ" rack LOW TEST --zone SMOKE >/dev/null && ok "équipement $EQ"
KEY=$(admin add-source "$SRC" IOT | tail -1)
[ -n "$KEY" ] && ok "source $SRC" || { ko "création de la source"; exit 1; }

echo "=== 2. Surchauffe à 40 °C (règle rack_temperature_critical : > 35 °C pendant 60 s)"
code=$(send 40); [ "$code" = 200 ] && ok "ingestion acceptée" || ko "ingestion : HTTP $code"
INC=$(wait_for "incident" "SELECT i.id FROM obs.incident i JOIN obs.equipment e ON e.id = i.equipment_id
      JOIN obs.detection_rule r ON r.id = i.detection_rule WHERE e.code = '$EQ'
      AND r.name = 'rack_temperature_critical' AND i.status <> 'RESOLVED'" 180 40)
[ -n "$INC" ] && ok "incident ouvert : $INC ($(sql "SELECT severity FROM obs.incident WHERE id = '$INC'"))" \
  || { ko "aucun incident en 3 min : docker compose logs detection"; exit 1; }

echo "=== 3. Investigation par le modèle local (plusieurs minutes sur CPU)"
STATUS=$(wait_for "agent" "SELECT status FROM obs.agent_run WHERE incident_id = '$INC' AND status <> 'RUNNING'" 600 40)
if [ -n "$STATUS" ]; then
  ok "investigation terminée : $STATUS"
  sql "SELECT 'étapes ' || steps || ', jetons ' || tokens || ', durée ' || round(extract(epoch FROM ended_at - started_at)) || ' s'
       FROM obs.agent_run WHERE incident_id = '$INC' ORDER BY started_at DESC LIMIT 1" | sed 's/^/       /'
  sql "SELECT '       outil ' || st.seq || ' : ' || st.tool || ' (' || st.duration_ms || ' ms)' FROM obs.agent_step st
       JOIN obs.agent_run r ON r.id = st.run_id WHERE r.incident_id = '$INC' ORDER BY st.seq"
  sql "SELECT '       diagnostic : ' || coalesce(output->'conclusion'->>'diagnostic', output->>'reason')
       FROM obs.agent_run WHERE incident_id = '$INC' ORDER BY started_at DESC LIMIT 1"
  [ "$STATUS" = DEGRADED ] && echo "       (mode dégradé : modèle injoignable ou trop lent — docker compose logs agent ollama)"
else ko "pas de fin d'investigation en 10 min : docker compose logs agent"; fi
DEC=$(sql "SELECT q.action_id || ' sur ' || q.target || ' → ' || q.decision || ' (niveau ' || q.effective_level || ')'
           FROM obs.action_request q JOIN obs.agent_run r ON r.id = q.run_id WHERE r.incident_id = '$INC' LIMIT 1")
[ -n "$DEC" ] && ok "décision du garde-fou : $DEC" || echo "       (aucune action proposée : diagnostic ou escalade seuls)"
KINDS=$(sql "SELECT string_agg(DISTINCT payload->>'kind', ', ') FROM obs.outbox WHERE payload->>'incident_id' = '$INC'
             OR payload->>'request_id' IN (SELECT q.id::text FROM obs.action_request q JOIN obs.agent_run r
             ON r.id = q.run_id WHERE r.incident_id = '$INC')")
[ -n "$KINDS" ] && ok "notifications produites : $KINDS" || ko "aucune notification pour l'incident (BR-03)"

echo "=== 4. Retour à la normale (20 °C) : clôture après stabilisation (M4, 5 min)"
CLOSED=$(wait_for "clôture" "SELECT closed_at FROM obs.incident WHERE id = '$INC' AND status = 'RESOLVED'" 480 20)
[ -n "$CLOSED" ] && ok "incident clos à $CLOSED" || ko "incident non clos en 8 min"

echo "=== 5. Journal d'audit"
admin verify-audit | grep -q VALIDE && ok "chaîne d'audit valide" || ko "chaîne d'audit ROMPUE"

echo "=== 6. Nettoyage"
sql "UPDATE obs.source SET status = 'DISABLED' WHERE name = '$SRC'" >/dev/null && ok "source $SRC désactivée"
sql "INSERT INTO obs.maintenance_window (equipment_id, starts_at, ends_at, reason, created_by)
     SELECT id, now(), now() + interval '25 hours', 'fin d''essai de bout en bout', 'deploy/smoke.sh'
     FROM obs.equipment WHERE code = '$EQ'" >/dev/null && ok "baie $EQ en maintenance 25 h (pas d'alerte « muet »)"

echo; echo "=== Bilan : $PASS réussite(s), $FAIL échec(s)"
[ $FAIL = 0 ]
