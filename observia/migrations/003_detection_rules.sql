-- Règles initiales du pilote (document « Règles de pré-détection V1.0 », §5 et §6).
-- Seuils = exemples à calibrer pendant le mode ombre. Les règles dont la métrique n'est pas
-- encore confirmée par les sources (hypothèse H5) sont chargées DÉSACTIVÉES : les activer
-- quand le nom réel de la métrique est connu (UPDATE … SET enabled = TRUE, params = …).
--
-- Colonnes : type, params (gabarit), fenêtre, intervalle, persistance for_s (M1), relevés
-- minimum (M9), sévérité, stabilité avant clôture (M4), maintenance (M6).

INSERT INTO obs.detection_rule
  (name, rule_type, params, window_s, check_interval_s, for_s, min_data_points, severity_hint, stability_s,
   maintenance_mode, enabled, description)
VALUES
-- Environnement --------------------------------------------------------------------------
('rack_temperature_high', 'THRESHOLD',
 '{"metric": "temperature", "op": ">", "threshold": 30, "clear_threshold": 28}',
 120, 10, 120, 1, 'HIGH', 300, 'SUPPRESS', TRUE, 'E1 : température > 30 °C pendant 2 min ; normale sous 28 °C'),
('rack_temperature_critical', 'THRESHOLD',
 '{"metric": "temperature", "op": ">", "threshold": 35, "clear_threshold": 33}',
 120, 10, 60, 1, 'CRITICAL', 300, 'IGNORE', TRUE, 'E2 : température > 35 °C ; signalée même en maintenance'),
('temperature_rising_fast', 'SLOPE',
 '{"metric": "temperature", "rise": 5, "clear_rise": 2}',
 600, 30, 0, 5, 'CRITICAL', 600, 'IGNORE', TRUE, 'E2 : hausse > 5 °C en 10 min (pente simple, sans z-score)'),
('humidity_out_of_range', 'THRESHOLD',
 '{"metric": "humidity", "op": "outside", "low": 20, "high": 80, "clear_low": 25, "clear_high": 75}',
 300, 30, 300, 1, 'MED', 600, 'SUPPRESS', FALSE, 'E3 : humidité hors de 20 à 80 % pendant 5 min [métrique à confirmer, H5]'),
('water_leak', 'STATE', '{"metric": "water_leak", "equals": 1}',
 60, 10, 0, 1, 'CRITICAL', 300, 'IGNORE', FALSE, 'E4 : fuite d''eau, immédiat [métrique à confirmer, H5]'),
('smoke_detected', 'STATE', '{"metric": "smoke", "equals": 1}',
 60, 10, 0, 1, 'CRITICAL', 300, 'IGNORE', FALSE, 'E4 : fumée, immédiat [métrique à confirmer, H5]'),

-- Énergie --------------------------------------------------------------------------------
('ups_on_battery', 'STATE', '{"metric": "ups_on_battery", "equals": 1}',
 60, 10, 0, 1, 'HIGH', 300, 'IGNORE', FALSE, 'P1 : bascule sur onduleur [métrique à confirmer, H5]'),
('ups_runtime_low', 'THRESHOLD', '{"metric": "ups_runtime_min", "op": "<", "threshold": 15, "clear_threshold": 20}',
 120, 10, 0, 1, 'CRITICAL', 300, 'IGNORE', FALSE, 'P2 : autonomie onduleur < 15 min [métrique à confirmer, H5]'),
('pdu_load_high', 'THRESHOLD', '{"metric": "pdu_load_pct", "op": ">", "threshold": 80, "clear_threshold": 75}',
 300, 30, 300, 1, 'MED', 600, 'SUPPRESS', FALSE, 'P3 : charge PDU > 80 % [métrique à confirmer, H5]'),

-- Refroidissement ------------------------------------------------------------------------
('fan_stopped', 'STATE', '{"metric": "fan_rpm", "equals": 0}',
 60, 10, 30, 2, 'HIGH', 120, 'SUPPRESS', TRUE, 'F1 : ventilateur à l''arrêt sur 2 relevés consécutifs'),

-- Logiciel et logs -----------------------------------------------------------------------
('cpu_high', 'THRESHOLD', '{"metric": "cpu_pct", "op": ">", "threshold": 90, "clear_threshold": 80, "aggregate": "min"}',
 600, 60, 0, 10, 'MED', 600, 'SUPPRESS', FALSE, 'L2 : CPU > 90 % pendant 10 min [métrique à confirmer, H5]'),
('memory_high', 'THRESHOLD', '{"metric": "mem_pct", "op": ">", "threshold": 90, "clear_threshold": 85}',
 300, 60, 300, 1, 'MED', 600, 'SUPPRESS', FALSE, 'L3 : mémoire > 90 % [métrique à confirmer, H5]'),
('disk_usage_high', 'THRESHOLD', '{"metric": "disk_used_pct", "op": ">", "threshold": 85, "clear_threshold": 80}',
 600, 60, 0, 1, 'MED', 900, 'SUPPRESS', FALSE, 'L4 : disque > 85 % [métrique à confirmer, H5]'),
('disk_usage_critical', 'THRESHOLD', '{"metric": "disk_used_pct", "op": ">", "threshold": 95, "clear_threshold": 90}',
 600, 60, 0, 1, 'HIGH', 900, 'SUPPRESS', FALSE, 'L4 : disque > 95 % [métrique à confirmer, H5]'),
('error_rate_high', 'RATE', '{"metric": "log", "levels": ["ERROR", "CRITICAL"], "threshold": 0.05, "clear_threshold": 0.02}',
 600, 30, 0, 20, 'MED', 600, 'SUPPRESS', TRUE, 'Taux d''erreurs > 5 % sur 10 min (au moins 20 lignes)'),
('log_critical', 'RATE', '{"metric": "log", "levels": ["CRITICAL"], "measure": "count", "threshold": 0}',
 300, 30, 0, 1, 'HIGH', 300, 'SUPPRESS', TRUE, 'L7 : message de gravité CRITICAL'),

-- Santé du pipeline (§5) -----------------------------------------------------------------
('source_silent', 'SILENT_SOURCE', '{}',
 120, 30, 0, 1, 'HIGH', 60, 'IGNORE', TRUE, 'S1 : aucune donnée de la source depuis 2 min'),
('equipment_silent', 'SILENT_EQUIPMENT', '{"default_interval_s": 60, "multiplier": 3}',
 180, 30, 0, 1, 'MED', 60, 'SUPPRESS', TRUE, 'S2 : équipement qui émettait, muet depuis 3 intervalles attendus'),
('temperature_frozen', 'FROZEN', '{"metric": "temperature"}',
 900, 60, 0, 20, 'MED', 300, 'SUPPRESS', TRUE, 'S3 : 20 relevés de température identiques (capteur bloqué)');

-- S4 : taux de rejet de schéma par source, en SQL libre (statut renvoyé pour chaque source, M9)
INSERT INTO obs.detection_rule
  (name, rule_type, query, window_s, check_interval_s, for_s, min_data_points, severity_hint, stability_s,
   maintenance_mode, description)
VALUES ('ingestion_rejects', 'CUSTOM_SQL', $q$
SELECT NULL::uuid AS equipment_id, s.id AS source_id, t.total AS n, t.rate AS value,
       CASE WHEN t.total < 20 THEN 'NO_DATA'
            WHEN t.rate > 0.01 THEN 'FIRING'
            WHEN t.rate > 0.005 THEN 'BETWEEN'
            ELSE 'OK' END AS status,
       'rejets de schéma ' || round(100 * coalesce(t.rate, 0)::numeric, 2) || ' % (' || t.rejected
         || ' sur ' || t.total || ') pour ' || s.name AS detail
  FROM obs.source s
  CROSS JOIN LATERAL (
    SELECT q.n AS rejected, q.n + e.n AS total, q.n::float8 / nullif(q.n + e.n, 0) AS rate
      FROM (SELECT count(*) AS n FROM obs.quarantine
             WHERE source_id = s.id AND received_at > now() - make_interval(secs => $1)) q,
           (SELECT count(*) AS n FROM obs.event
             WHERE source_id = s.id AND time > now() - make_interval(secs => $1)) e
  ) t
 WHERE s.status = 'ACTIVE'
$q$, 300, 30, 0, 1, 'MED', 300, 'IGNORE', 'S4 : rejets de schéma > 1 % sur 5 min');

-- Règle système support des incidents « tempête » (M7) : jamais évaluée
INSERT INTO obs.detection_rule (name, rule_type, window_s, check_interval_s, severity_hint, enabled, description)
VALUES ('incident_storm', 'SYSTEM', 60, 60, 'CRITICAL', FALSE, 'M7 : regroupement des alertes au-delà du plafond');
