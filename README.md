# ObservIA-DC — V1.0 (MVP, mode ombre)

AI agent for the observability of GANDAL datacenter.

Agent d'observabilité IA pour datacenter, borné par un garde-fou formel. Implémentation du
SAD (architecture) et du SPSD (exigences) ; le déploiement suit la feuille de route.

En V1.0, le système ingère, détecte, investigue, propose, applique la politique, notifie et
audite **sans rien exécuter** (mode ombre), avec kill switch et validation humaine du niveau 3.

**Modèle : local, servi par Ollama, avec RAG.** L'hypothèse H1 (sortie de données autorisée) est
invalidée ; la décision D2 est rejouée (règle R4) au profit du modèle local. Aucune donnée ne
quitte le site ; la pseudonymisation devient optionnelle (désactivée par défaut).

## Structure (SAD §6)

```
observia/
  ingestion/     API FastAPI : clés de source, schéma, normalisation, quarantaine, adaptateur Telegraf
  detection/     pré-détection sans IA : règles gabarits (templates.py), moteur à états (engine.py),
                 service avec échec sûr (worker.py) — voir « Pré-détection » ci-dessous
  agent/         boucle plafonnée, passerelle Ollama (API OpenAI), préchargement RAG, mode dégradé
  knowledge/     RAG : découpage, plongements Ollama, recherche pgvector, indexation des runbooks
                 et des incidents résolus ayant un verdict humain
  mcp_server/    outils de lecture assainis (dont search_knowledge) + propose_action
  guardrail/     catalogue, OPA / moteur local, verrous, quotas, kill switch, validations N3
  executor/      file d'exécution (op_id) ; worker désactivé jusqu'à la V1.1
  notification/  SMS + e-mail (N3 sur deux canaux), webhook optionnel, relances et expirations
  audit/         journal chaîné par hachage + réplicateur immudb
  console_api/   API de la console : RBAC, validations, kill switch, niveaux, mode ombre, audit
  shared/        configuration, base, file outbox, migrations, CLI d'administration
  migrations/    schéma obs (SAD §7), rétention, rôles, règles initiales
policies/        catalog.yaml + guardrail.rego + tests (versionnés Git, testés en CI)
knowledge/       runbooks Markdown indexés pour le RAG (exemples de départ, à remplacer)
```

## Pré-détection

Mise en œuvre du document « Règles de pré-détection V1.0 ». Une règle est une ligne de
`obs.detection_rule` : un **type gabarit** et ses paramètres, sans SQL à écrire (sauf `CUSTOM_SQL`).

| Type | Paramètres | Exemple |
|---|---|---|
| `THRESHOLD` | `metric`, `op` (`>`, `<`, `outside`…), `threshold`, `clear_threshold`, `aggregate` | température > 30 °C, normale sous 28 °C |
| `STATE` | `metric`, `equals` | ventilateur = 0, fuite = 1 |
| `RATE` | `levels`, `measure` (`ratio`/`count`), `threshold` | > 5 % de lignes ERROR |
| `SLOPE` | `metric`, `rise`, `clear_rise` | + 5 °C en 10 min |
| `FROZEN` | `metric` (+ `min_data_points` = relevés identiques) | capteur bloqué |
| `SILENT_SOURCE` / `SILENT_EQUIPMENT` | `multiplier`, `default_interval_s` | source ou équipement muet |
| `CUSTOM_SQL` | `query` renvoyant un `status` par clé | rejets de schéma (S4) |

Règles du moteur en place : M1 persistance (`for_s`), M2 comptage, M3 hystérésis, M4 clôture
stable, M6 maintenance (`SUPPRESS`/`DEGRADE`/`IGNORE`), M7 tempête, M8 sévérité = max(règle,
criticité), M9 donnée absente ≠ normal, M10 échec sûr, M12 contexte, M13 versions auditées
(déclencheur SQL), M14 règles en ombre, M15 surveillance externe (service de notification).

Règles chargées : celles dont la métrique est connue sont actives (température, pente,
ventilateur, taux d'erreurs, CRITICAL, S1–S4) ; les autres (humidité, fuite, fumée, onduleur, PDU,
CPU, mémoire, disque) sont **désactivées** jusqu'à confirmation des métriques par les sources (H5).

```sql
UPDATE obs.detection_rule SET enabled = TRUE, params = params || '{"metric": "hum_pct"}'
 WHERE name = 'humidity_out_of_range';   -- version + 1 et trace d'audit automatiques
```

### Gestion des règles par l'administrateur (API de la console)

| Méthode | Route | Rôle | Effet |
|---|---|---|---|
| GET | `/rules`, `/rules/{nom}`, `/rules/{nom}/history` | lecture | définition, santé (M15), incidents ouverts, versions |
| GET | `/rules/types` | lecture | types et schéma JSON de leurs paramètres (formulaires) |
| POST | `/rules/preview` | admin, ops_manager | ce que la règle détecterait maintenant, sans rien créer |
| POST | `/rules` | admin, ops_manager | création (validée puis exécutée à blanc), **en ombre par défaut** |
| GET | `/rules/{nom}/shadow` | lecture | rapport de calibration : détections en ombre par jour et par équipement |
| POST | `/rules/{nom}/promote` | admin, ops_manager | mise en service ; avant 24 h d'observation : `force` + motif |
| PATCH | `/rules/{nom}` | admin, ops_manager | modification ; `version` attendue obligatoire (409 si périmée) |
| DELETE | `/rules/{nom}?close_incidents=` | admin, ops_manager | archivage ; refusé s'il reste des incidents ouverts, sauf demande explicite |
| POST | `/rules/{nom}/restore` | admin, ops_manager | restauration, désactivée |

Exemple :

```bash
curl -X POST https://console/rules -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "name": "salle_chaude", "rule_type": "THRESHOLD", "window_s": 120, "check_interval_s": 10,
  "for_s": 120, "severity_hint": "HIGH",
  "params": {"metric": "room_temp", "op": ">", "threshold": 30, "clear_threshold": 28}}'
```

Traçabilité : toute version (API ou SQL direct) est conservée dans `detection_rule_history`
avec le nom de la personne et reportée dans le journal d'audit. Le service de détection est
notifié de chaque changement (`LISTEN observia_rules`) et le prend en compte en 1 s environ ;
un rechargement toutes les 30 s reste en filet de sécurité. `CUSTOM_SQL` : une seule requête `SELECT`,
exécutée en lecture seule et sous le rôle `observia_mcp`, qui ne voit ni l'audit ni les clés.
**Calibration (M14)** : une règle créée par l'API démarre en ombre. Elle enregistre ce qu'elle
aurait détecté (`obs.rule_shadow_hit`) sans créer d'incident ni réveiller l'agent. Le rapport
`/rules/{nom}/shadow` distingue les détections de la version courante (un seuil modifié remet le
compteur de la version à zéro). Après `OBSERVIA_RULE_SHADOW_MIN_S` (24 h par défaut),
`/promote` la met en service ; avant, il faut `force: true` et un motif, tracés dans l'audit.
Une règle de sûreté urgente (fuite, fumée) peut être créée directement avec `"shadow": false`.

Maintenance (M6) : `GET|POST /maintenance`, `POST /maintenance/{id}/end` (7 jours au plus).

## RAG

- **Corpus** : runbooks de `knowledge/runbooks/` (relus comme le catalogue) et incidents résolus
  dont la proposition a reçu un **verdict humain** (mode ombre ou validation). Les conclusions de
  l'agent non vérifiées ne sont jamais indexées : pas d'auto-renforcement sur ses erreurs.
- **Plongements** : `nomic-embed-text` via Ollama ; stockage et recherche dans PostgreSQL
  (pgvector, index HNSW) : pas de service supplémentaire à opérer.
- **Utilisation** : recherche d'office au début de chaque investigation, puis outil MCP
  `search_knowledge` à la demande. Les passages restent balisés `<donnee_non_fiable>` (BR-04) :
  ils orientent l'agent, ils ne fixent ni l'action ni le niveau (le garde-fou reste seul juge).

Règle d'isolation : `agent` n'importe jamais `executor` ; seul `guardrail` l'appelle
(`scripts/check_isolation.py`).

## Démarrage (pilote Docker Compose)

```bash
cp .env.example .env          # renseigner mots de passe, jeton MCP, passerelle modèle, SMTP/SMS
docker compose up -d
docker compose --profile setup run --rm ollama-pull                    # qwen2.5:7b-instruct + nomic-embed-text
docker compose run --rm migrate python -m shared.admin demo-seed        # ou add-equipment …
docker compose run --rm migrate python -m shared.admin add-source iot-main IOT   # affiche la clé une fois
```

Envoi d'un événement :

```bash
curl -X POST http://localhost:8000/ingest/events -H "X-Source-Key: $KEY" -H 'Content-Type: application/json' \
  -d '[{"equipment":"B12","metric":"temperature","value":34.2,"timestamp":"2026-11-03T10:00:00Z"}]'
```

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -e "observia[dev]"   # ou les dépendances de pyproject.toml
scripts/ci.sh                                                         # isolation + opa test + pytest

# Intégration (base JETABLE, le schéma obs est recréé) :
docker run -d --name obs-db -e POSTGRES_USER=observia -e POSTGRES_PASSWORD=observia -p 127.0.0.1:55432:5432 timescale/timescaledb-ha:pg16-ts2.17
docker run -d --name obs-opa -p 127.0.0.1:58181:8181 -v "$PWD/policies:/policies:ro" openpolicyagent/opa:1.4.2 run --server --addr=0.0.0.0:8181 /policies
cd observia && OBSERVIA_TEST_DSN=postgresql://observia:observia@127.0.0.1:55432/observia \
  OBSERVIA_POLICY_ENGINE=opa OBSERVIA_OPA_URL=http://127.0.0.1:58181 OBSERVIA_TEST_OPA_URL=http://127.0.0.1:58181 \
  ../.venv/bin/python -m pytest -q
```

Les tests n'appellent pas Ollama : modèle scripté et plongements déterministes. Ils exigent pgvector.
Les tests d'intégration couvrent les tests de recette T1, T2, T4 à T8 et T12 de la feuille de route,
et la parité OPA / moteur local sur tous les cas de politique.

## Écarts et choix à valider

| Point | Choix retenu | Pourquoi |
|---|---|---|
| Ordre quota / mode ombre (SAD §9.2) | Suivi à la lettre : quota dépassé → PENDING_APPROVAL même en mode ombre | À confirmer : on pourrait ne pas appliquer le quota aux propositions ombre |
| TimescaleDB | Requise en production ; les migrations tolèrent son absence (repli D4 « PostgreSQL seul ») | Requêtes portables (`date_bin`) |
| Logs sans Loki | Message conservé dans `obs.event.payload` | Garde `get_logs` utilisable en profil réduit |
| Hachage d'audit | Inclut aussi `event_type` et `ref` | Plus strict que la formule du SAD §7.5 |
| Actions hors catalogue | Tracées dans l'audit, sans ligne `action_request` | Clé étrangère vers le catalogue |
| Cibles | Code d'équipement, `zone:<Z>` ou `site:<S>` (toujours N3) | BR-06 |
| Budget de l'agent | 180 s / 90 s par appel au lieu de 30 s (NFR-06) | Inférence CPU ; à recalibrer au PoC modèle |
| Modèle par défaut | `qwen2.5:7b-instruct` (appel d'outils fiable, français correct) | Remplaçable par variable d'environnement |
| Image de base | `timescaledb-ha` (TimescaleDB + pgvector) | Un seul PostgreSQL ; tag à figer et vérifier |

## Reste à faire

- **Pré-détection, hors V1.0 du document** : M5 (état UNSTABLE, anti-clignotement au-delà de
  l'hystérésis), M11 (rattachement aux incidents parents ; à limiter d'abord aux règles SILENT_*),
  FORECAST, COUNT_PATTERN (décider LogQL ou extraction de motifs à l'ingestion), S5 (retard
  d'ingestion : stocker l'heure de réception), règles P4, F2, L1, L5, L6 ; A1/A2 à soumettre au RSSI
  (données personnelles).

- **PoC modèle local** (SAD §3.6, à rejouer avec Ollama) : 30 à 50 incidents rejoués, diagnostics
  corrects ≥ 90 %, sorties conformes ≥ 99 %, durée de boucle mesurée sur le matériel réel.
- **Dimensionnement** (feuille de route §4) : ajouter environ 6 Go de RAM et 4 vCPU pour un
  modèle 7B quantifié sur CPU, ou prévoir un GPU ; sinon un modèle 3B (moins fiable).

- **Console Next.js** (D13) : file des décisions, validations, actions, contrôle de l'autonomie,
  et écrans de gestion des règles (l'API ci-dessus est prête).
- **V1.1** : exécuteur Ansible (D10), rollback (FR-19), vérification post-action (FR-20),
  anomalies z-score (FR-06), méta-observabilité Prometheus/Grafana (FR-23).
- Validation [CLI]/[RSSI] du catalogue réel (20 actions) et des seuils des règles.
- PoC de la feuille de route : protocole de la carte physique (H5), modèle sur incidents rejoués (D2),
  charge à 5 000 événements/s (D4, D6, D8).
