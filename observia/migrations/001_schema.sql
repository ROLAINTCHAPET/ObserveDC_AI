-- ObservIA-DC — schéma principal (SAD §7). Horodatages en UTC (TIMESTAMPTZ).
-- Pas de suppression logique sur les faits décisionnels : statuts + audit immuable.

-- TimescaleDB attendu (D4) ; repli documenté « PostgreSQL seul » si l'extension est absente.
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS timescaledb;
EXCEPTION WHEN OTHERS THEN
  RAISE WARNING 'TimescaleDB indisponible (%), repli PostgreSQL seul (D4)', SQLERRM;
END $$;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS obs;

-- 7.1 Sources et équipements ------------------------------------------------

CREATE TABLE obs.source (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name       TEXT NOT NULL UNIQUE,
  kind       TEXT NOT NULL CHECK (kind IN ('IOT', 'CARD', 'SOFTWARE')),
  auth_ref   TEXT NOT NULL,             -- sha256 de la clé d'API (jamais la clé en clair)
  status     TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DISABLED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE obs.equipment (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code        TEXT NOT NULL UNIQUE,
  type        TEXT NOT NULL,
  zone        TEXT,
  rack        TEXT,
  criticality TEXT NOT NULL CHECK (criticality IN ('LOW', 'MED', 'HIGH', 'CRITICAL')),
  env         TEXT NOT NULL CHECK (env IN ('TEST', 'PROD')),
  expected_interval_s INTEGER CHECK (expected_interval_s > 0)  -- règle SILENT_EQUIPMENT (S2)
);

CREATE TABLE obs.equipment_dependency (
  parent_id UUID NOT NULL REFERENCES obs.equipment(id),
  child_id  UUID NOT NULL REFERENCES obs.equipment(id),
  PRIMARY KEY (parent_id, child_id),
  CHECK (parent_id <> child_id)
);

-- 7.2 Événements et incidents -----------------------------------------------

CREATE TABLE obs.event (
  time           TIMESTAMPTZ NOT NULL,
  source_id      UUID NOT NULL REFERENCES obs.source(id),
  equipment_id   UUID NOT NULL REFERENCES obs.equipment(id),
  metric         TEXT NOT NULL,
  value          DOUBLE PRECISION,
  level          TEXT,
  payload        JSONB,
  correlation_id UUID
);
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    PERFORM create_hypertable('obs.event', 'time', if_not_exists => TRUE);
  END IF;
END $$;
CREATE INDEX ON obs.event (equipment_id, metric, time DESC);
CREATE INDEX ON obs.event (source_id, time DESC);   -- règle « source silencieuse »

-- UC-01 : schéma invalide → quarantaine + alerte
CREATE TABLE obs.quarantine (
  id          BIGSERIAL PRIMARY KEY,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  source_id   UUID REFERENCES obs.source(id),
  reason      TEXT NOT NULL,
  raw         JSONB NOT NULL
);

-- Règles de pré-détection (document « Règles de pré-détection V1.0 ») : une règle est une ligne
-- de configuration. Les types gabarits génèrent leur SQL dans detection/templates.py ; CUSTOM_SQL
-- reste une échappatoire et doit renvoyer un statut par clé (M9).
CREATE TABLE obs.detection_rule (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name             TEXT NOT NULL UNIQUE,
  rule_type        TEXT NOT NULL CHECK (rule_type IN ('THRESHOLD', 'STATE', 'RATE', 'SILENT_SOURCE',
                     'SILENT_EQUIPMENT', 'FROZEN', 'SLOPE', 'CUSTOM_SQL', 'SYSTEM')),
  version          INTEGER NOT NULL DEFAULT 1,           -- M13 : incrémentée par déclencheur
  params           JSONB NOT NULL DEFAULT '{}'::jsonb,   -- paramètres du gabarit (métrique, seuils…)
  query            TEXT,                                 -- CUSTOM_SQL seulement
  window_s         INTEGER NOT NULL CHECK (window_s > 0),
  check_interval_s INTEGER NOT NULL CHECK (check_interval_s BETWEEN 10 AND 300),  -- FR-05
  for_s            INTEGER NOT NULL DEFAULT 0 CHECK (for_s >= 0),            -- M1 : persistance
  min_data_points  INTEGER NOT NULL DEFAULT 1 CHECK (min_data_points >= 1),  -- M9
  severity_hint    TEXT NOT NULL CHECK (severity_hint IN ('LOW', 'MED', 'HIGH', 'CRITICAL')),
  stability_s      INTEGER NOT NULL DEFAULT 120,                             -- M4
  maintenance_mode TEXT NOT NULL DEFAULT 'SUPPRESS'
                   CHECK (maintenance_mode IN ('SUPPRESS', 'DEGRADE', 'IGNORE')),  -- M6
  shadow           BOOLEAN NOT NULL DEFAULT FALSE,                           -- M14
  shadow_since     TIMESTAMPTZ,   -- début de l'observation en ombre (posé par le déclencheur)
  enabled          BOOLEAN NOT NULL DEFAULT TRUE,
  description      TEXT,
  archived_at      TIMESTAMPTZ,   -- « suppression » : la règle reste référencée par ses incidents et l'audit
  archived_by      TEXT,
  CHECK ((rule_type = 'CUSTOM_SQL') = (query IS NOT NULL)),
  CHECK (archived_at IS NULL OR NOT enabled)
);

-- M13 : tout changement de définition incrémente la version et laisse une trace, même s'il est
-- fait en SQL direct ; le service de détection reporte chaque trace dans le journal d'audit.
CREATE TABLE obs.detection_rule_history (
  id         BIGSERIAL PRIMARY KEY,
  rule_id    UUID NOT NULL,
  version    INTEGER NOT NULL,
  changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  changed_by TEXT NOT NULL,       -- personne (API, via observia.actor) ou compte de base (SQL direct)
  definition JSONB NOT NULL,
  audited    BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE FUNCTION obs.detection_rule_versioning() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF (to_jsonb(NEW) - 'version' - 'shadow_since') IS NOT DISTINCT FROM (to_jsonb(OLD) - 'version' - 'shadow_since') THEN
      RETURN NEW;
    END IF;
    NEW.version := OLD.version + 1;
  END IF;
  -- M14 : l'observation en ombre commence quand la règle y entre, et se termine à sa promotion
  IF NEW.shadow AND (TG_OP = 'INSERT' OR NOT OLD.shadow) THEN
    NEW.shadow_since := now();
  ELSIF NOT NEW.shadow THEN
    NEW.shadow_since := NULL;
  END IF;
  INSERT INTO obs.detection_rule_history (rule_id, version, changed_by, definition)
  VALUES (NEW.id, NEW.version, coalesce(nullif(current_setting('observia.actor', true), ''), current_user), to_jsonb(NEW));
  -- Réveille le service de détection (LISTEN observia_rules) : prise en compte immédiate
  PERFORM pg_notify('observia_rules', NEW.name);
  RETURN NEW;
END $$;
CREATE TRIGGER detection_rule_versioning BEFORE INSERT OR UPDATE ON obs.detection_rule
  FOR EACH ROW EXECUTE FUNCTION obs.detection_rule_versioning();

CREATE TABLE obs.incident (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  equipment_id       UUID REFERENCES obs.equipment(id),
  source_id          UUID REFERENCES obs.source(id),
  opened_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  status             TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'INVESTIGATING', 'RESOLVED')),
  severity           TEXT NOT NULL CHECK (severity IN ('LOW', 'MED', 'HIGH', 'CRITICAL')),  -- M8
  detection_rule     UUID NOT NULL REFERENCES obs.detection_rule(id),
  rule_version       INTEGER,                                 -- M12
  summary            TEXT NOT NULL,
  context            JSONB NOT NULL DEFAULT '{}'::jsonb,      -- M12 : pourquoi la règle s'est déclenchée
  dedup_key          TEXT NOT NULL,
  occurrence_count   INTEGER NOT NULL DEFAULT 1,              -- M2
  last_true_at       TIMESTAMPTZ NOT NULL DEFAULT now(),      -- dernière évaluation vraie (last_seen)
  cleared_at         TIMESTAMPTZ,      -- retour à la normale constaté : stabilisation en cours (M4)
  data_missing_since TIMESTAMPTZ,      -- M9 : données absentes, l'incident n'est jamais fermé pour autant
  maintenance        BOOLEAN NOT NULL DEFAULT FALSE,          -- M6 : ouvert pendant une maintenance (DEGRADE)
  closed_at          TIMESTAMPTZ
);
-- FR-07 / M2 : un seul incident ouvert par clé (équipement + règle), garanti par la base
CREATE UNIQUE INDEX incident_open_dedup ON obs.incident (dedup_key) WHERE status <> 'RESOLVED';
CREATE INDEX incident_opened_at ON obs.incident (opened_at);  -- M7 : plafond de création

-- État par clé entre deux évaluations : persistance (M1), hystérésis (M3), marques uniques
CREATE TABLE obs.rule_state (
  rule_id       UUID NOT NULL REFERENCES obs.detection_rule(id),
  dedup_key     TEXT NOT NULL,
  pending_since TIMESTAMPTZ,       -- condition vraie depuis, sans incident encore ouvert
  last_status   TEXT NOT NULL,     -- FIRING, BETWEEN, OK, NO_DATA
  last_value    DOUBLE PRECISION,
  marked_at     TIMESTAMPTZ,       -- déclenchement ombre ou suppression maintenance déjà tracé
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (rule_id, dedup_key)
);

-- M14 : ce qu'une règle en ombre aurait détecté (une ligne par épisode et par clé)
CREATE TABLE obs.rule_shadow_hit (
  id           BIGSERIAL PRIMARY KEY,
  rule_id      UUID NOT NULL REFERENCES obs.detection_rule(id),
  rule_version INTEGER NOT NULL,
  dedup_key    TEXT NOT NULL,
  equipment_id UUID REFERENCES obs.equipment(id),
  source_id    UUID REFERENCES obs.source(id),
  fired_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  value        DOUBLE PRECISION,
  detail       TEXT NOT NULL,
  context      JSONB NOT NULL
);
CREATE INDEX ON obs.rule_shadow_hit (rule_id, fired_at DESC);

-- M15 : santé du détecteur (dernier passage par règle), surveillée hors du service de détection
CREATE TABLE obs.rule_status (
  rule_id              UUID PRIMARY KEY REFERENCES obs.detection_rule(id),
  last_eval_at         TIMESTAMPTZ,
  duration_ms          INTEGER,
  status               TEXT CHECK (status IN ('OK', 'FIRING', 'NO_DATA', 'ERROR', 'TIMEOUT')),
  last_error           TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  alerted_at           TIMESTAMPTZ,   -- M10 : dernière alerte d'échec envoyée
  stale_alerted_at     TIMESTAMPTZ,   -- M15 : dernière alerte « règle non évaluée »
  firing_keys          INTEGER NOT NULL DEFAULT 0,
  no_data_keys         INTEGER NOT NULL DEFAULT 0,
  shadow_hits          INTEGER NOT NULL DEFAULT 0
);

-- Journal des évaluations : seulement les changements de statut (volume maîtrisé)
CREATE TABLE obs.rule_eval_log (
  id           BIGSERIAL PRIMARY KEY,
  rule_id      UUID NOT NULL REFERENCES obs.detection_rule(id),
  evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  duration_ms  INTEGER,
  status       TEXT NOT NULL,
  detail       TEXT
);

-- M6 : maintenance déclarée
CREATE TABLE obs.maintenance_window (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  equipment_id UUID NOT NULL REFERENCES obs.equipment(id),
  starts_at    TIMESTAMPTZ NOT NULL,
  ends_at      TIMESTAMPTZ NOT NULL,
  reason       TEXT NOT NULL,
  created_by   TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (ends_at > starts_at)
);
CREATE INDEX ON obs.maintenance_window (equipment_id, ends_at);

CREATE TABLE obs.incident_event (
  incident_id UUID NOT NULL REFERENCES obs.incident(id),
  event_time  TIMESTAMPTZ NOT NULL,
  event_ref   TEXT NOT NULL
);

-- 7.3 Agent, actions et décisions -------------------------------------------

CREATE TABLE obs.agent_run (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id UUID NOT NULL REFERENCES obs.incident(id),
  model       TEXT NOT NULL,
  started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at    TIMESTAMPTZ,
  status      TEXT NOT NULL DEFAULT 'RUNNING'
              CHECK (status IN ('RUNNING', 'PROPOSED', 'CONCLUDED', 'ESCALATED', 'DEGRADED')),
  steps       INTEGER NOT NULL DEFAULT 0,
  tokens      INTEGER NOT NULL DEFAULT 0,
  cost        NUMERIC(12, 6) NOT NULL DEFAULT 0,
  output      JSONB                        -- sortie validée par schéma (SAD §13.2)
);

CREATE TABLE obs.agent_step (
  id          BIGSERIAL PRIMARY KEY,
  run_id      UUID NOT NULL REFERENCES obs.agent_run(id),
  seq         INTEGER NOT NULL,
  tool        TEXT NOT NULL,
  args        JSONB NOT NULL,
  result_ref  TEXT,
  duration_ms INTEGER NOT NULL,
  UNIQUE (run_id, seq)
);

CREATE TABLE obs.action_catalog (
  action_id       TEXT PRIMARY KEY,
  params_schema   JSONB NOT NULL,
  base_level      SMALLINT NOT NULL CHECK (base_level IN (1, 2, 3)),
  allowed_targets JSONB NOT NULL,
  reversible      BOOLEAN NOT NULL,
  rollback_ref    TEXT
);

CREATE TABLE obs.action_request (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id          UUID NOT NULL REFERENCES obs.agent_run(id),
  action_id       TEXT NOT NULL REFERENCES obs.action_catalog(action_id),
  target          TEXT NOT NULL,
  params          JSONB NOT NULL,
  justification   TEXT NOT NULL,
  confidence      REAL,
  effective_level SMALLINT NOT NULL CHECK (effective_level IN (1, 2, 3)),
  decision        TEXT NOT NULL
                  CHECK (decision IN ('EXECUTE', 'PENDING_APPROVAL', 'REFUSED', 'SHADOW')),
  reasons         JSONB NOT NULL DEFAULT '[]'::jsonb,
  decided_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE obs.approval (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id   UUID NOT NULL UNIQUE REFERENCES obs.action_request(id),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,
  reminded_at  TIMESTAMPTZ,
  status       TEXT NOT NULL DEFAULT 'PENDING'
               CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED')),
  decided_by   TEXT,
  decision     TEXT CHECK (decision IN ('APPROVE', 'REJECT')),
  decided_at   TIMESTAMPTZ,
  comment      TEXT
);

CREATE TABLE obs.execution (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id  UUID NOT NULL REFERENCES obs.action_request(id),
  op_id       UUID NOT NULL UNIQUE,     -- FR-14 : idempotence
  started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  status      TEXT NOT NULL DEFAULT 'QUEUED'
              CHECK (status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
  result      JSONB,
  verified    BOOLEAN,
  rolled_back BOOLEAN NOT NULL DEFAULT FALSE
);

-- 7.4 Contrôle, notification, audit -----------------------------------------

CREATE TABLE obs.autonomy_state (
  level        SMALLINT PRIMARY KEY CHECK (level IN (1, 2, 3)),
  enabled      BOOLEAN NOT NULL DEFAULT FALSE,
  opened_by    TEXT,
  opened_at    TIMESTAMPTZ,
  shadow_score REAL
);
INSERT INTO obs.autonomy_state (level) VALUES (1), (2), (3);

-- Historique en ajout seul : l'état courant est la dernière ligne
CREATE TABLE obs.kill_switch (
  id         BIGSERIAL PRIMARY KEY,
  active     BOOLEAN NOT NULL,
  changed_by TEXT NOT NULL,
  changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reason     TEXT NOT NULL
);

CREATE TABLE obs.rate_counter (
  scope        TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  count        INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (scope, window_start)
);

CREATE TABLE obs.shadow_comparison (
  request_id   UUID PRIMARY KEY REFERENCES obs.action_request(id),
  agent_action JSONB NOT NULL,
  human_action JSONB,
  match        BOOLEAN,
  noted_at     TIMESTAMPTZ,
  noted_by     TEXT
);

CREATE TABLE obs.notification_log (
  id         BIGSERIAL PRIMARY KEY,
  outbox_id  BIGINT,                    -- message d'origine : pas de double envoi lors d'une reprise
  request_id UUID REFERENCES obs.action_request(id),
  incident_id UUID REFERENCES obs.incident(id),
  channel    TEXT NOT NULL,
  recipient  TEXT NOT NULL,
  status     TEXT NOT NULL CHECK (status IN ('SENT', 'FAILED')),
  error      TEXT,
  sent_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Audit : tampon transactionnel chaîné par hachage, répliqué vers immudb (D12)
CREATE TABLE obs.audit_log (
  id         BIGSERIAL PRIMARY KEY,
  ts         TIMESTAMPTZ NOT NULL,
  actor      TEXT NOT NULL,
  event_type TEXT NOT NULL,
  ref        TEXT,
  payload    JSONB NOT NULL,
  prev_hash  TEXT NOT NULL,
  hash       TEXT NOT NULL UNIQUE
);
CREATE INDEX ON obs.audit_log (ref);
REVOKE UPDATE, DELETE, TRUNCATE ON obs.audit_log FROM PUBLIC;

-- Défense en profondeur : même le propriétaire ne peut ni modifier ni supprimer
CREATE FUNCTION obs.audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'obs.audit_log est en ajout seul';
END $$;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON obs.audit_log
  FOR EACH ROW EXECUTE FUNCTION obs.audit_log_immutable();

CREATE TABLE obs.audit_replication (
  target  TEXT PRIMARY KEY,
  last_id BIGINT NOT NULL DEFAULT 0
);
INSERT INTO obs.audit_replication (target) VALUES ('immudb');

-- File d'incidents, validations et notifications (D6 : outbox PostgreSQL, SKIP LOCKED)
CREATE TABLE obs.outbox (
  id           BIGSERIAL PRIMARY KEY,
  topic        TEXT NOT NULL CHECK (topic IN ('incidents.new', 'approvals.pending', 'notifications.out')),
  payload      JSONB NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  attempts     INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  processed_at TIMESTAMPTZ,
  dead         BOOLEAN NOT NULL DEFAULT FALSE,
  last_error   TEXT
);
CREATE INDEX outbox_pending ON obs.outbox (topic, id) WHERE processed_at IS NULL AND NOT dead;
