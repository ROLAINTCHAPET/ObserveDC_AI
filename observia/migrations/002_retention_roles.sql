-- FR-04 : rétention et compression des événements (valeurs de départ, à ajuster au disque mesuré).
-- Profil A− : rétention 14 jours → SELECT remove_retention_policy('obs.event'); puis add_… 14 days.
-- Bloc tolérant : l'édition Apache de TimescaleDB n'offre pas la compression (licence, SAD D4).
DO $$
BEGIN
  ALTER TABLE obs.event SET (timescaledb.compress, timescaledb.compress_segmentby = 'equipment_id, metric');
  PERFORM add_compression_policy('obs.event', INTERVAL '2 days', if_not_exists => TRUE);
  PERFORM add_retention_policy('obs.event', INTERVAL '90 days', if_not_exists => TRUE);
EXCEPTION WHEN OTHERS THEN
  RAISE WARNING 'compression/rétention TimescaleDB indisponible : %', SQLERRM;
END $$;

-- Phase 4 de la feuille de route : rôles écriture (ingestion), lecture seule (MCP), application.
-- Rôles de groupe NOLOGIN ; les comptes de connexion sont créés par deploy/db-init.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'observia_ingest_role') THEN
    CREATE ROLE observia_ingest_role NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'observia_reader_role') THEN
    CREATE ROLE observia_reader_role NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'observia_app_role') THEN
    CREATE ROLE observia_app_role NOLOGIN;
  END IF;
END $$;

GRANT USAGE ON SCHEMA obs TO observia_ingest_role, observia_reader_role, observia_app_role;

-- Ingestion : lit sources/équipements, écrit événements et quarantaine, journalise les rejets
GRANT SELECT ON obs.source, obs.equipment TO observia_ingest_role;
GRANT INSERT ON obs.event, obs.quarantine, obs.audit_log, obs.outbox TO observia_ingest_role;
GRANT SELECT ON obs.audit_log TO observia_ingest_role;
GRANT SELECT (id) ON obs.outbox TO observia_ingest_role;  -- INSERT … RETURNING id (alerte de quarantaine)
GRANT USAGE ON SEQUENCE obs.quarantine_id_seq, obs.audit_log_id_seq, obs.outbox_id_seq TO observia_ingest_role;

-- Outils MCP de lecture : lecture seule, sans accès aux tables de contrôle
GRANT SELECT ON obs.event, obs.equipment, obs.equipment_dependency, obs.incident,
  obs.incident_event, obs.agent_run, obs.action_request, obs.execution, obs.detection_rule
  TO observia_reader_role;

-- Requêtes de détection (gabarits et CUSTOM_SQL saisi par l'API) : même rôle lecture seule,
-- avec en plus les seules colonnes utiles de source et quarantaine (jamais auth_ref)
GRANT SELECT (id, name, kind, status) ON obs.source TO observia_reader_role;
GRANT SELECT (source_id, received_at, reason) ON obs.quarantine TO observia_reader_role;

-- Services applicatifs (détection, agent, garde-fou, notification, console)
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA obs TO observia_app_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA obs TO observia_app_role;
REVOKE UPDATE ON obs.audit_log, obs.kill_switch FROM observia_app_role;
-- Seule suppression autorisée : l'état transitoire de persistance des règles (M1), pas un fait décisionnel
GRANT DELETE ON obs.rule_state TO observia_app_role;
