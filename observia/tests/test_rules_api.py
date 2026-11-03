"""API de gestion des règles (console) : création, aperçu, modification, archivage, sécurité.

Nécessite OBSERVIA_TEST_DSN (base JETABLE, avec droit de créer un rôle de connexion).
"""
import os
import time
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest

from tests.conftest import TEST_DSN

pytestmark = pytest.mark.skipif(not TEST_DSN, reason="OBSERVIA_TEST_DSN non défini")

if TEST_DSN:
    from console_api.main import app
    from detection import admin as rules_admin
    from detection.engine import evaluate, load_rules
    from shared.admin import add_equipment, add_source
    from shared.config import get_settings
    from shared.db import get_pool
    from shared.migrate import migrate


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
        await add_equipment(c, "R1", "rack", "MED", "TEST")
    return p


def token(*roles, user="alice"):
    claims = {"sub": user, "roles": list(roles), "exp": int(time.time()) + 300}
    return {"Authorization": "Bearer " + jwt.encode(claims, os.environ["OBSERVIA_CONSOLE_JWT_SECRET"], "HS256")}


@pytest.fixture
async def api():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://console") as c:
        yield c


ADMIN = token("admin")
THRESHOLD = {"name": "salle_chaude", "rule_type": "THRESHOLD", "window_s": 120, "check_interval_s": 10,
             "severity_hint": "HIGH", "shadow": False, "params": {"metric": "room_temp", "op": ">", "threshold": 30, "clear_threshold": 28},
             "description": "Salle trop chaude"}


async def hot_events(pool, metric="room_temp", value=33.0):
    src = await pool.fetchval("SELECT id FROM obs.source LIMIT 1")
    eq = await pool.fetchval("SELECT id FROM obs.equipment WHERE code = 'R1'")
    await pool.execute("INSERT INTO obs.event (time, source_id, equipment_id, metric, value) VALUES ($1, $2, $3, $4, $5)",
                       datetime.now(timezone.utc), src, eq, metric, value)


async def test_rbac(pool, api):
    assert (await api.post("/rules", json=THRESHOLD)).status_code == 401
    assert (await api.post("/rules", json=THRESHOLD, headers=token("viewer"))).status_code == 403
    assert (await api.post("/rules", json=THRESHOLD, headers=token("oncall"))).status_code == 403
    types = (await api.get("/rules/types", headers=token("viewer"))).json()
    assert "threshold" in types["THRESHOLD"]["properties"] and "CUSTOM_SQL" in types


async def test_preview_creates_nothing(pool, api):
    await hot_events(pool)
    body = {k: v for k, v in THRESHOLD.items() if k != "name"}
    r = await api.post("/rules/preview", json=body, headers=ADMIN)
    assert r.status_code == 200, r.text
    assert r.json()["by_status"] == {"FIRING": 1} and "room_temp = 33" in r.json()["sample"][0]["detail"]
    assert await pool.fetchval("SELECT count(*) FROM obs.detection_rule WHERE params->>'metric' = 'room_temp'") == 0


async def test_create_is_validated_versioned_and_attributed(pool, api):
    r = await api.post("/rules", json=THRESHOLD, headers=token("ops_manager", user="bob"))
    assert r.status_code == 201, r.text
    assert r.json()["rule"]["version"] == 1 and r.json()["dry_run"]["keys"] == 1
    history = (await api.get("/rules/salle_chaude/history", headers=ADMIN)).json()
    assert [(h["version"], h["changed_by"]) for h in history] == [(1, "bob")]  # la personne, pas le compte SQL
    assert await pool.fetchval("SELECT actor FROM obs.audit_log WHERE event_type = 'RULE_VERSION' "
                               "AND ref = 'rule:salle_chaude'") == "bob"
    rules, _ = await load_rules(pool)
    assert "salle_chaude" in {x.name for x in rules}  # prise en compte par le service de détection


@pytest.mark.parametrize("change,expected", [
    ({"params": {"metric": "x", "op": ">"}}, "threshold requis"),
    ({"params": {"metric": "x", "op": ">", "threshold": 1, "inconnu": 2}}, "paramètres invalides"),
    ({"check_interval_s": 5}, None),
    ({"rule_type": "SYSTEM"}, None),
    ({"query": "SELECT 1"}, "query n'est accepté"),
])
async def test_invalid_rules_rejected(pool, api, change, expected):
    r = await api.post("/rules", json={**THRESHOLD, "name": "invalide", **change}, headers=ADMIN)
    assert r.status_code == 422, r.text
    if expected:
        assert expected in r.text


async def test_name_conflicts(pool, api):
    assert (await api.post("/rules", json=THRESHOLD, headers=ADMIN)).status_code == 409
    assert (await api.post("/rules", json={**THRESHOLD, "name": "incident_storm"}, headers=ADMIN)).status_code == 409


CUSTOM = {"name": "regle_sql", "rule_type": "CUSTOM_SQL", "window_s": 300, "check_interval_s": 30, "severity_hint": "MED"}
VALID_SQL = ("SELECT equipment_id, NULL::uuid AS source_id, count(*) AS n, max(value) AS value, "
             "CASE WHEN max(value) > 32 THEN 'FIRING' ELSE 'OK' END AS status, 'max ' || max(value) AS detail "
             "FROM obs.event WHERE metric = 'room_temp' AND time > now() - make_interval(secs => $1) GROUP BY equipment_id")


@pytest.mark.parametrize("query,reason", [
    ("SELECT 1 FROM obs.event WHERE $1 > 0; DROP TABLE obs.event", "une seule requête"),
    ("DELETE FROM obs.event WHERE $1 > 0", "SELECT ou WITH"),
    ("SELECT 1 AS n", "$1"),
    # Requête d'écriture déguisée en SELECT : bloquée par la transaction en lecture seule
    ("WITH d AS (DELETE FROM obs.event WHERE $1 > 0 RETURNING equipment_id) SELECT equipment_id FROM d", "read-only"),
    ("SELECT equipment_id, 1 AS n FROM obs.event WHERE $1 > 0", "status"),  # M9 : statut obligatoire
])
async def test_custom_sql_guards(pool, api, query, reason):
    r = await api.post("/rules", json={**CUSTOM, "query": query}, headers=ADMIN)
    assert r.status_code == 422 and reason in r.text, r.text
    assert await pool.fetchval("SELECT count(*) FROM obs.event WHERE metric = 'room_temp'") >= 1


async def test_custom_sql_valid(pool, api):
    r = await api.post("/rules", json={**CUSTOM, "query": VALID_SQL}, headers=ADMIN)
    assert r.status_code == 201, r.text
    assert r.json()["dry_run"]["by_status"] == {"FIRING": 1}


async def test_custom_sql_runs_under_read_only_role(pool):
    """Avec le vrai rôle lecture seule, une règle ne lit ni l'audit ni les clés des sources."""
    await pool.execute("DROP ROLE IF EXISTS t_reader")
    await pool.execute("CREATE ROLE t_reader LOGIN PASSWORD 't_reader' IN ROLE observia_reader_role")
    dsn = TEST_DSN.replace("observia:observia@", "t_reader:t_reader@")
    settings = get_settings().model_copy(update={"db_reader_dsn": dsn})
    def custom(query):
        definition = rules_admin.RuleDefinition(**{k: v for k, v in CUSTOM.items() if k != "name"}, query=query)
        return rules_admin.build_rule("lecture", definition.model_dump())

    ok = custom(VALID_SQL)
    assert (await rules_admin.dry_run(ok, settings))["keys"] == 1  # la télémétrie reste lisible
    for forbidden in ("SELECT NULL::uuid AS equipment_id, NULL::uuid AS source_id, 1 AS n, 'OK' AS status "
                      "FROM obs.audit_log WHERE $1 > 0",
                      "SELECT NULL::uuid AS equipment_id, id AS source_id, 1 AS n, auth_ref AS detail, 'OK' AS status "
                      "FROM obs.source WHERE $1 > 0"):
        rule = custom(forbidden)
        with pytest.raises(rules_admin.RuleError, match="permission denied"):
            await rules_admin.dry_run(rule, settings)


async def test_update_with_optimistic_concurrency(pool, api):
    patch = {"version": 1, "params": {**THRESHOLD["params"], "threshold": 31}}
    r = await api.patch("/rules/salle_chaude", json=patch, headers=ADMIN)
    assert r.status_code == 200 and r.json()["rule"]["version"] == 2
    # Un second administrateur qui modifie à partir de la version 1 ne doit rien écraser
    stale = await api.patch("/rules/salle_chaude", json={**patch, "params": {**patch["params"], "threshold": 99}},
                            headers=token("admin", user="carol"))
    assert stale.status_code == 409
    assert (await api.get("/rules/salle_chaude", headers=ADMIN)).json()["rule"]["params"]["threshold"] == 31
    # Modification invalide : refusée, version inchangée
    bad = await api.patch("/rules/salle_chaude", json={"version": 2, "params": {"metric": "x"}}, headers=ADMIN)
    assert bad.status_code == 422
    assert (await api.get("/rules/salle_chaude", headers=ADMIN)).json()["rule"]["version"] == 2


async def test_delete_archives_and_protects_open_incidents(pool, api):
    rules, _ = await load_rules(pool)
    rule = {x.name: x for x in rules}["salle_chaude"]
    await evaluate(pool, rule, get_settings())
    incident = await pool.fetchval("SELECT id FROM obs.incident WHERE detection_rule = $1", rule.id)
    assert incident

    r = await api.delete("/rules/salle_chaude", headers=ADMIN)
    assert r.status_code == 409 and "incident(s) ouvert(s)" in r.text
    r = await api.delete("/rules/salle_chaude", params={"close_incidents": "true"}, headers=ADMIN)
    assert r.json() == {"archived": "salle_chaude", "closed_incidents": 1}
    assert await pool.fetchval("SELECT status FROM obs.incident WHERE id = $1", incident) == "RESOLVED"
    assert await pool.fetchval("SELECT count(*) FROM obs.audit_log WHERE event_type = 'INCIDENT_CLOSED_RULE_ARCHIVED'") == 1
    # Archivée : plus évaluée, masquée, mais l'historique et l'incident gardent leur référence
    rules, _ = await load_rules(pool)
    assert "salle_chaude" not in {x.name for x in rules}
    assert "salle_chaude" not in {x["name"] for x in (await api.get("/rules", headers=ADMIN)).json()}
    listed = (await api.get("/rules", params={"include_archived": "true"}, headers=ADMIN)).json()
    assert next(x for x in listed if x["name"] == "salle_chaude")["archived_by"] == "alice"
    assert (await api.patch("/rules/salle_chaude", json={"version": 3, "enabled": True}, headers=ADMIN)).status_code == 409
    again = await api.post("/rules", json=THRESHOLD, headers=ADMIN)
    assert again.status_code == 409 and "restaurer" in again.text

    restored = await api.post("/rules/salle_chaude/restore", headers=ADMIN)
    assert restored.json()["rule"]["enabled"] is False  # réactivation explicite ensuite
    versions = [h["version"] for h in (await api.get("/rules/salle_chaude/history", headers=ADMIN)).json()]
    assert versions == [4, 3, 2, 1]


# --- Calibration en ombre (M14) puis promotion --------------------------------------

SHADOWED = {"rule_type": "THRESHOLD", "window_s": 120, "check_interval_s": 10, "severity_hint": "MED",
            "params": {"metric": "room_temp", "op": ">", "threshold": 32, "clear_threshold": 30}}


async def evaluate_named(pool, name):
    rules, _ = await load_rules(pool)
    return (await evaluate(pool, {x.name: x for x in rules}[name], get_settings())).stats


async def test_new_rule_starts_in_shadow_and_reports_hits(pool, api):
    r = await api.post("/rules", json={**SHADOWED, "name": "ombre_a"}, headers=ADMIN)
    assert r.status_code == 201, r.text
    assert r.json()["rule"]["shadow"] is True and r.json()["rule"]["shadow_since"] is not None
    for _ in range(3):
        await evaluate_named(pool, "ombre_a")
    rule_id = r.json()["rule"]["id"]
    assert await pool.fetchval("SELECT count(*) FROM obs.incident WHERE detection_rule = $1", rule_id) == 0
    report = (await api.get("/rules/ombre_a/shadow", headers=token("viewer"))).json()
    assert report["hits"] == 1 and report["hits_current_version"] == 1 and report["distinct_keys"] == 1
    assert report["by_key"][0]["subject"] == "R1" and "room_temp = 33" in report["recent"][0]["detail"]
    assert report["ready"] is False and report["min_observation_s"] == 86400

    # Seuil modifié : les détections de l'ancienne version ne comptent plus pour la version courante
    patched = await api.patch("/rules/ombre_a", json={"version": 1, "params": {**SHADOWED["params"], "threshold": 32.5}},
                              headers=ADMIN)
    assert patched.status_code == 200
    report = (await api.get("/rules/ombre_a/shadow", headers=ADMIN)).json()
    assert report["version"] == 2 and report["hits"] == 1 and report["hits_current_version"] == 0


async def test_promotion_guards_and_forced_promotion(pool, api):
    early = await api.post("/rules/ombre_a/promote", json={"version": 2}, headers=ADMIN)
    assert early.status_code == 409 and "trop courte" in early.text
    no_reason = await api.post("/rules/ombre_a/promote", json={"version": 2, "force": True}, headers=ADMIN)
    assert no_reason.status_code == 422
    stale = await api.post("/rules/ombre_a/promote", json={"version": 1, "force": True, "reason": "test"}, headers=ADMIN)
    assert stale.status_code == 409
    assert (await api.post("/rules/ombre_a/promote", json={"version": 2}, headers=token("oncall"))).status_code == 403

    ok = await api.post("/rules/ombre_a/promote", json={"version": 2, "force": True, "reason": "incident réel en cours"},
                        headers=token("ops_manager", user="dana"))
    assert ok.status_code == 200, ok.text
    assert ok.json()["rule"]["shadow"] is False and ok.json()["rule"]["version"] == 3
    promoted = await pool.fetchrow("SELECT actor, payload FROM obs.audit_log WHERE event_type = 'RULE_PROMOTED'")
    assert promoted["actor"] == "dana" and promoted["payload"]["forced"] is True
    assert promoted["payload"]["reason"] == "incident réel en cours"
    # En service : la condition toujours vraie ouvre maintenant un incident
    assert (await evaluate_named(pool, "ombre_a"))["opened"] == 1
    assert (await api.post("/rules/ombre_a/promote", json={"version": 3}, headers=ADMIN)).status_code == 409


async def test_promotion_after_observation_period(pool, api):
    created = await api.post("/rules", json={**SHADOWED, "name": "ombre_b"}, headers=ADMIN)
    assert created.status_code == 201
    await pool.execute("UPDATE obs.detection_rule SET shadow_since = now() - interval '25 hours' WHERE name = 'ombre_b'")
    report = (await api.get("/rules/ombre_b/shadow", headers=ADMIN)).json()
    assert report["ready"] is True
    ok = await api.post("/rules/ombre_b/promote", json={"version": report["version"]}, headers=ADMIN)
    assert ok.status_code == 200 and ok.json()["rule"]["shadow"] is False


async def test_explicit_live_rule_and_back_to_shadow(pool, api):
    r = await api.post("/rules", json={**SHADOWED, "name": "fuite_immediate", "shadow": False}, headers=ADMIN)
    assert r.json()["rule"]["shadow"] is False and r.json()["rule"]["shadow_since"] is None
    back = await api.patch("/rules/fuite_immediate", json={"version": 1, "shadow": True}, headers=ADMIN)
    assert back.json()["rule"]["shadow_since"] is not None  # nouvelle période d'observation


async def test_rule_change_is_notified_to_detection(pool, api):
    """Le service de détection écoute observia_rules : prise en compte immédiate, sans attendre 30 s."""
    import asyncio

    import asyncpg

    received: asyncio.Queue = asyncio.Queue()
    conn = await asyncpg.connect(TEST_DSN)
    await conn.add_listener("observia_rules", lambda _c, _pid, _ch, payload: received.put_nowait(payload))
    try:
        current = (await api.get("/rules/ombre_b", headers=ADMIN)).json()["rule"]["version"]
        await api.patch("/rules/ombre_b", json={"version": current, "for_s": 30}, headers=ADMIN)
        assert await asyncio.wait_for(received.get(), 2) == "ombre_b"
    finally:
        await conn.close()


async def test_detection_listener_flags_reload(pool, api):
    import asyncio

    from detection.worker import RuleChangeListener

    listener = RuleChangeListener(TEST_DSN)
    await listener.ensure()
    try:
        assert listener.consume() is False
        current = (await api.get("/rules/ombre_b", headers=ADMIN)).json()["rule"]["version"]
        await api.patch("/rules/ombre_b", json={"version": current, "for_s": 60}, headers=ADMIN)
        await asyncio.wait_for(listener.changed.wait(), 2)
        assert listener.consume() is True and listener.consume() is False
    finally:
        await listener.conn.close()
