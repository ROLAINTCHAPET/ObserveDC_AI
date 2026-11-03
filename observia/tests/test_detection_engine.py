"""Moteur de pré-détection sur PostgreSQL réel : tests du §10 du document « Règles de
pré-détection V1.0 » (M1, M3, M6, M7, M9, M10, M12, M15) et règles M4, M13, M14, S2, S3.

Nécessite OBSERVIA_TEST_DSN (base JETABLE). Chaque test crée ses propres règles et
équipements, sur des métriques dédiées, pour rester indépendant des autres.
"""
import itertools
import json
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import TEST_DSN

pytestmark = pytest.mark.skipif(not TEST_DSN, reason="OBSERVIA_TEST_DSN non défini")

if TEST_DSN:
    from detection.engine import Rule, evaluate, load_rules
    from detection.worker import audit_rule_changes, ensure_status_rows, run_rule
    from notification.worker import sweep_detector_health
    from shared.admin import add_equipment, add_source
    from shared.config import get_settings
    from shared.db import get_pool
    from shared.migrate import migrate

_ids = itertools.count(1)


@pytest.fixture(scope="module")
async def pool():
    import asyncpg

    conn = await asyncpg.connect(TEST_DSN)
    await conn.execute("DROP SCHEMA IF EXISTS obs CASCADE; DROP TABLE IF EXISTS public.observia_migrations")
    await conn.close()
    await migrate(TEST_DSN)
    p = await get_pool(TEST_DSN)
    async with p.acquire() as c:
        await add_source(c, "src", "IOT")
    return p


async def equipment(pool, criticality="MED", env="TEST", **kw) -> tuple[str, object]:
    code = f"eq-{next(_ids)}"
    async with pool.acquire() as c:
        await add_equipment(c, code, "rack", criticality, env)
    return code, await pool.fetchval("SELECT id FROM obs.equipment WHERE code = $1", code)


async def rule(pool, rule_type, params=None, *, query=None, **cols) -> Rule:
    name = f"r{next(_ids)}"
    values = {"window_s": 120, "check_interval_s": 10, "for_s": 0, "min_data_points": 1, "severity_hint": "MED",
              "stability_s": 60, "maintenance_mode": "SUPPRESS", "shadow": False, **cols}
    await pool.execute(
        f"INSERT INTO obs.detection_rule (name, rule_type, params, query, {', '.join(values)}) "
        f"VALUES ($1, $2, $3, $4, {', '.join(f'${i + 5}' for i in range(len(values)))})",
        name, rule_type, params or {}, query, *values.values())
    return await reload(pool, name)


async def reload(pool, name) -> Rule:
    rules, _ = await load_rules(pool)
    found = {r.name: r for r in rules}[name]
    await ensure_status_rows(pool, [found.id])
    return found


async def events(pool, eq_id, metric, values, step_s=10, end_ago_s=0):
    src = await pool.fetchval("SELECT id FROM obs.source LIMIT 1")
    now = datetime.now(timezone.utc) - timedelta(seconds=end_ago_s)
    rows = [(now - timedelta(seconds=step_s * (len(values) - 1 - i)), src, eq_id, metric, float(v))
            for i, v in enumerate(values)]
    await pool.executemany("INSERT INTO obs.event (time, source_id, equipment_id, metric, value) VALUES ($1, $2, $3, $4, $5)", rows)


async def clear_metric(pool, metric):
    await pool.execute("DELETE FROM obs.event WHERE metric = $1", metric)


async def ev(pool, r):
    return (await evaluate(pool, r, get_settings())).stats


async def incidents(pool, r):
    return await pool.fetch("SELECT * FROM obs.incident WHERE detection_rule = $1 ORDER BY opened_at", r.id)


async def backdate(pool, table, column, seconds):
    await pool.execute(f"UPDATE obs.{table} SET {column} = {column} - make_interval(secs => $1)", float(seconds))


THRESH = {"op": ">", "threshold": 30, "clear_threshold": 28}


# --- §10 : un pic isolé plus court que for_s ne crée aucun incident (M1) ---------------

async def test_short_spike_creates_no_incident_m1(pool):
    _, eq = await equipment(pool)
    r = await rule(pool, "THRESHOLD", {"metric": "m1", **THRESH}, for_s=60)
    await events(pool, eq, "m1", [35])
    assert (await ev(pool, r))["pending"] == 1
    await events(pool, eq, "m1", [25])  # retour à la normale avant for_s
    assert (await ev(pool, r))["pending"] == 0
    await backdate(pool, "rule_state", "pending_since", 120)
    await ev(pool, r)
    assert await incidents(pool, r) == []


# --- §10 : un capteur qui oscille autour du seuil crée 1 incident, pas 50 (M3) ---------

async def test_oscillating_sensor_creates_one_incident_m3(pool):
    _, eq = await equipment(pool)
    r = await rule(pool, "THRESHOLD", {"metric": "m3", **THRESH})
    for value in [31, 29.5, 30.5, 29, 31, 28.5, 30.2, 29.8] * 6:  # 48 évaluations dans la bande
        await clear_metric(pool, "m3")
        await events(pool, eq, "m3", [value])
        await ev(pool, r)
    rows = await incidents(pool, r)
    assert len(rows) == 1 and rows[0]["status"] != "RESOLVED"
    assert rows[0]["occurrence_count"] == 24  # M2 : 24 évaluations au-dessus de 30


# --- M4 : fermeture seulement après stability_s sous le seuil de retour ---------------

async def test_closure_after_stability_m4(pool):
    _, eq = await equipment(pool)
    r = await rule(pool, "THRESHOLD", {"metric": "m4", **THRESH}, stability_s=60)
    await events(pool, eq, "m4", [35])
    await ev(pool, r)
    await clear_metric(pool, "m4")
    await events(pool, eq, "m4", [20])
    await ev(pool, r)
    [inc] = await incidents(pool, r)
    assert inc["cleared_at"] is not None and inc["status"] == "OPEN"
    await backdate(pool, "incident", "cleared_at", 61)
    assert (await ev(pool, r))["resolved"] == 1


# --- M9 : donnée absente ≠ normal -------------------------------------------------------

async def test_missing_data_never_closes_incident_m9(pool):
    _, eq = await equipment(pool)
    r = await rule(pool, "THRESHOLD", {"metric": "m9", **THRESH}, stability_s=10, min_data_points=1)
    await events(pool, eq, "m9", [36])
    await ev(pool, r)
    await clear_metric(pool, "m9")  # le capteur meurt pendant l'incident
    for _ in range(3):
        stats = await ev(pool, r)
        await backdate(pool, "incident", "last_true_at", 3600)
    [inc] = await incidents(pool, r)
    assert stats["no_data"] == 1 and stats["resolved"] == 0
    assert inc["status"] == "OPEN" and inc["data_missing_since"] is not None and inc["cleared_at"] is None


async def test_not_enough_points_does_not_open_m9(pool):
    _, eq = await equipment(pool)
    r = await rule(pool, "THRESHOLD", {"metric": "m9b", **THRESH}, min_data_points=3)
    await events(pool, eq, "m9b", [40, 40])
    assert (await ev(pool, r))["no_data"] == 1
    assert await incidents(pool, r) == []


# --- §10 : 500 événements anormaux → au plus X incidents + 1 « tempête » (M7) -----------

async def test_storm_cap_m7(pool):
    cap = get_settings().storm_max_per_min
    await pool.execute("UPDATE obs.incident SET opened_at = opened_at - interval '1 hour'")  # isole le test
    r = await rule(pool, "THRESHOLD", {"metric": "m7", **THRESH})
    queued_before = await pool.fetchval("SELECT count(*) FROM obs.outbox WHERE topic = 'incidents.new'")
    for _ in range(25):
        _, eq = await equipment(pool)
        await events(pool, eq, "m7", [40] * 20, step_s=1)  # 500 événements anormaux
    stats = await ev(pool, r)
    assert stats["opened"] == cap and stats["storm"] == 25 - cap
    storm = await pool.fetchrow("SELECT * FROM obs.incident WHERE dedup_key = 'storm' AND status <> 'RESOLVED'")
    assert storm["severity"] == "CRITICAL" and len(storm["context"]["keys"]) == 25 - cap
    # L'agent n'est réveillé que pour les incidents ouverts, pas pour chaque alerte de la tempête
    queued = await pool.fetchval("SELECT count(*) FROM obs.outbox WHERE topic = 'incidents.new'")
    assert queued - queued_before == cap
    assert await pool.fetchval("SELECT count(*) FROM obs.outbox WHERE payload->>'subject' LIKE 'Tempête%'") == 1
    await ev(pool, r)  # réévaluation : pas de doublon dans la tempête
    assert len((await pool.fetchrow("SELECT context FROM obs.incident WHERE id = $1", storm["id"]))["context"]["keys"]) == 25 - cap
    await pool.execute("UPDATE obs.incident SET opened_at = opened_at - interval '1 hour'")


# --- §10 : une règle cassée lève une alerte interne, jamais « normal » (M10) ------------

async def test_broken_rule_raises_internal_alert_m10(pool):
    _, eq = await equipment(pool)
    r = await rule(pool, "CUSTOM_SQL", query=(
        "SELECT equipment_id, NULL::uuid AS source_id, 1 AS n, value, 'FIRING' AS status, 'x' AS detail "
        "FROM obs.event WHERE metric = 'm10' AND time > now() - make_interval(secs => $1)"), stability_s=0)
    await events(pool, eq, "m10", [1])
    await run_rule(pool, r, get_settings())
    [inc] = await incidents(pool, r)
    # La règle est cassée (table inexistante) : son incident ne doit pas être fermé
    await pool.execute("UPDATE obs.detection_rule SET query = 'SELECT * FROM obs.table_inexistante WHERE $1 > 0' WHERE id = $1", r.id)
    broken = await reload(pool, r.name)
    for _ in range(2):
        assert await run_rule(pool, broken, get_settings()) is None
    status = await pool.fetchrow("SELECT * FROM obs.rule_status WHERE rule_id = $1", r.id)
    assert status["status"] == "ERROR" and status["consecutive_failures"] == 2
    assert await pool.fetchval("SELECT status FROM obs.incident WHERE id = $1", inc["id"]) == "OPEN"
    alerts = await pool.fetch("SELECT payload FROM obs.outbox WHERE payload->>'kind' = 'INTERNAL' "
                              "AND payload->>'subject' LIKE $1", f"%{r.name}%")
    assert len(alerts) == 1 and alerts[0]["payload"]["level"] == 3  # une alerte, pas une par échec


async def test_misconfigured_rule_is_reported_not_ignored_m10(pool):
    await pool.execute(
        "INSERT INTO obs.detection_rule (name, rule_type, params, window_s, check_interval_s, severity_hint) "
        "VALUES ('mal_parametree', 'THRESHOLD', '{\"metric\": \"x\", \"op\": \">\"}', 60, 10, 'LOW')")
    _, invalid = await load_rules(pool)
    assert any(name == "mal_parametree" and "paramètres invalides" in err for _, name, err in invalid)
    await pool.execute("UPDATE obs.detection_rule SET enabled = FALSE WHERE name = 'mal_parametree'")


# --- §10 : une baie en maintenance ne crée pas d'incident (M6) --------------------------

async def test_maintenance_modes_m6(pool):
    results = {}
    for mode in ("SUPPRESS", "DEGRADE", "IGNORE"):
        _, eq = await equipment(pool, criticality="HIGH")
        await pool.execute("INSERT INTO obs.maintenance_window (equipment_id, starts_at, ends_at, reason, created_by) "
                           "VALUES ($1, now() - interval '1 h', now() + interval '1 h', 'test', 'tests')", eq)
        r = await rule(pool, "THRESHOLD", {"metric": f"m6{mode}", **THRESH}, maintenance_mode=mode)
        await events(pool, eq, f"m6{mode}", [40])
        await ev(pool, r)
        await ev(pool, r)
        results[mode] = (r, await incidents(pool, r))
    assert results["SUPPRESS"][1] == []
    suppressed = await pool.fetchval("SELECT count(*) FROM obs.audit_log WHERE event_type = 'INCIDENT_SUPPRESSED_MAINTENANCE' "
                                     "AND ref LIKE $1", f"{results['SUPPRESS'][0].name}:%")
    assert suppressed == 1  # tracé une fois, pas à chaque évaluation
    [degraded] = results["DEGRADE"][1]
    assert degraded["severity"] == "LOW" and degraded["maintenance"] is True
    assert not await pool.fetchval("SELECT count(*) FROM obs.outbox WHERE topic = 'incidents.new' "
                                   "AND payload->>'incident_id' = $1", str(degraded["id"]))
    [ignored] = results["IGNORE"][1]
    assert ignored["severity"] == "HIGH" and ignored["maintenance"] is False  # M8 : criticité HIGH


# --- §10 : chaque incident contient son contexte complet (M12) --------------------------

async def test_incident_context_m12(pool):
    _, eq = await equipment(pool, criticality="CRITICAL")
    r = await rule(pool, "THRESHOLD", {"metric": "m12", **THRESH}, severity_hint="MED")
    await events(pool, eq, "m12", [33])
    await ev(pool, r)
    [inc] = await incidents(pool, r)
    ctx = inc["context"]
    assert inc["severity"] == "CRITICAL" and inc["rule_version"] == 1  # M8
    assert ctx["rule"] == r.name and ctx["params"]["threshold"] == 30 and ctx["window_s"] == 120
    assert ctx["first"]["value"] == 33 and ctx["first"]["status"] == "FIRING" and ctx["equipment_criticality"] == "CRITICAL"


# --- §10 : une règle non évaluée depuis 3 intervalles lève une alerte (M15) -------------

async def test_stale_rule_alert_m15(pool):
    r = await rule(pool, "THRESHOLD", {"metric": "m15", **THRESH})
    await run_rule(pool, r, get_settings())
    await backdate(pool, "detection_rule_history", "changed_at", 3600)
    await pool.execute("UPDATE obs.rule_status SET last_eval_at = now() - interval '1 hour'")
    stale = await sweep_detector_health(pool, 900)
    assert r.name in stale
    assert await sweep_detector_health(pool, 900) == []  # pas de répétition dans l'intervalle
    note = await pool.fetchval("SELECT payload FROM obs.outbox WHERE payload->>'subject' LIKE 'Pré-détection :%' "
                               "ORDER BY id DESC LIMIT 1")
    assert note["kind"] == "INTERNAL" and r.name in note["body"]
    await pool.execute("UPDATE obs.detection_rule SET enabled = FALSE WHERE id <> $1", r.id)


# --- M13 : versionnement et audit des changements ---------------------------------------

async def test_rule_changes_are_versioned_and_audited_m13(pool):
    r = await rule(pool, "THRESHOLD", {"metric": "m13", **THRESH})
    await pool.execute("UPDATE obs.detection_rule SET params = jsonb_set(params, '{threshold}', '32') WHERE id = $1", r.id)
    await pool.execute("UPDATE obs.detection_rule SET params = params WHERE id = $1", r.id)  # sans effet
    assert (await reload(pool, r.name)).version == 2
    await audit_rule_changes(pool)
    versions = await pool.fetch("SELECT payload FROM obs.audit_log WHERE event_type = 'RULE_VERSION' AND ref = $1 "
                                "ORDER BY id", f"rule:{r.name}")
    assert [v["payload"]["version"] for v in versions] == [1, 2]
    assert versions[1]["payload"]["definition"]["params"]["threshold"] == 32


# --- M14 : règle en mode ombre ----------------------------------------------------------

async def test_shadow_rule_logs_without_incident_m14(pool):
    _, eq = await equipment(pool)
    r = await rule(pool, "THRESHOLD", {"metric": "m14", **THRESH}, shadow=True)
    await events(pool, eq, "m14", [40])
    for _ in range(3):
        await ev(pool, r)
    assert await incidents(pool, r) == []
    hit = await pool.fetchrow("SELECT * FROM obs.rule_shadow_hit WHERE rule_id = $1", r.id)
    assert hit["equipment_id"] == eq and hit["value"] == 40 and hit["context"]["rule"] == r.name
    assert await pool.fetchval("SELECT count(*) FROM obs.rule_shadow_hit WHERE rule_id = $1", r.id) == 1
    assert await pool.fetchval("SELECT shadow_hits FROM obs.rule_status WHERE rule_id = $1", r.id) == 1


# --- S2, S3 : équipement muet, valeur figée ----------------------------------------------

async def test_silent_equipment_s2(pool):
    _, eq = await equipment(pool)
    await pool.execute("UPDATE obs.equipment SET expected_interval_s = 30 WHERE id = $1", eq)
    r = await rule(pool, "SILENT_EQUIPMENT", {"default_interval_s": 60, "multiplier": 3}, window_s=180)
    await events(pool, eq, "s2", [1], end_ago_s=60)
    await ev(pool, r)
    assert all(i["equipment_id"] != eq for i in await incidents(pool, r))  # 60 s < 3 × 30 s
    await pool.execute("UPDATE obs.event SET time = time - interval '5 min' WHERE equipment_id = $1", eq)
    await ev(pool, r)
    assert any(i["equipment_id"] == eq for i in await incidents(pool, r))


async def test_frozen_value_s3(pool):
    _, eq = await equipment(pool)
    _, eq2 = await equipment(pool)
    r = await rule(pool, "FROZEN", {"metric": "s3"}, window_s=600, min_data_points=20, check_interval_s=60)
    await events(pool, eq, "s3", [24.5] * 20)
    await events(pool, eq2, "s3", [24.5, 24.6] * 10)
    await ev(pool, r)
    assert [i["equipment_id"] for i in await incidents(pool, r)] == [eq]
