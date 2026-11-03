"""Chaîne complète sous les VRAIS rôles de base (feuille de route, phase 4 : « test de
permissions réussi »), comme en production : ingestion (écriture), outils MCP et requêtes
de détection (lecture seule), services applicatifs (app).

Les autres tests se connectent en propriétaire, qui a tous les droits : ce module est le
seul à détecter un droit manquant avant le déploiement.
Nécessite OBSERVIA_TEST_DSN (base JETABLE, droit de créer des rôles).
"""
import json
import os
import time
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest

from tests.conftest import TEST_DSN

pytestmark = pytest.mark.skipif(not TEST_DSN, reason="OBSERVIA_TEST_DSN non défini")

if TEST_DSN:
    import asyncpg

    from agent.gateway import ChatResult, ToolCall
    from agent.worker import AgentService, MCPToolClient
    from audit import log as audit
    from console_api.main import app as console_app
    from detection.engine import evaluate, load_rules
    from detection.worker import audit_rule_changes, ensure_status_rows, run_rule
    from ingestion import main as ingestion
    from knowledge import indexer
    from knowledge.embedder import set_embedder
    from mcp_server.main import server as mcp_server
    from notification.worker import sweep_approvals, sweep_detector_health
    from shared import outbox
    from shared.admin import DEMO, add_equipment, add_source
    from shared.config import get_settings
    from shared.db import get_pool
    from shared.migrate import migrate
    from tests.test_integration import HashEmbedder

ROLES = {"t_ingest": "observia_ingest_role", "t_mcp": "observia_reader_role", "t_app": "observia_app_role"}
STATE: dict = {}


def dsn_for(user: str) -> str:
    return TEST_DSN.replace("observia:observia@", f"{user}:{user}@")


@pytest.fixture(scope="module")
async def owner():
    conn = await asyncpg.connect(TEST_DSN)
    await conn.execute("DROP SCHEMA IF EXISTS obs CASCADE; DROP TABLE IF EXISTS public.observia_migrations")
    for user in ROLES:
        await conn.execute(f"DROP ROLE IF EXISTS {user}")
    await conn.close()
    await migrate(TEST_DSN)
    p = await get_pool(TEST_DSN)
    for user, group in ROLES.items():  # comme deploy/db-init/00-users.sh
        await p.execute(f"CREATE ROLE {user} LOGIN PASSWORD '{user}' IN ROLE {group}")
    async with p.acquire() as c:
        for row in DEMO:
            await add_equipment(c, *row)
        STATE["key"] = await add_source(c, "iot-main", "IOT")

    # Les services lisent leurs DSN dans la configuration, comme dans docker-compose.yml
    saved = {k: os.environ.get(k) for k in ("OBSERVIA_DB_DSN", "OBSERVIA_DB_READER_DSN", "OBSERVIA_DB_INGEST_DSN")}
    os.environ.update(OBSERVIA_DB_DSN=dsn_for("t_app"), OBSERVIA_DB_READER_DSN=dsn_for("t_mcp"),
                      OBSERVIA_DB_INGEST_DSN=dsn_for("t_ingest"))
    get_settings.cache_clear()
    set_embedder(HashEmbedder())
    yield p
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    get_settings.cache_clear()


@pytest.fixture(scope="module")
async def app_pool(owner):
    return await get_pool(dsn_for("t_app"))


def token(*roles, user="alice"):
    claims = {"sub": user, "roles": list(roles), "exp": int(time.time()) + 300}
    return {"Authorization": "Bearer " + jwt.encode(claims, os.environ["OBSERVIA_CONSOLE_JWT_SECRET"], "HS256")}


async def test_ingestion_under_ingest_role(owner):
    assert get_settings().ingest_dsn.startswith("postgresql://t_ingest:")
    now = datetime.now(timezone.utc)
    events = [{"equipment": "B12", "metric": "temperature", "value": 34.0,
               "timestamp": (now - timedelta(seconds=s)).isoformat()} for s in (60, 30, 0)]
    events += [{"equipment": "B12", "metric": "fan_rpm", "value": 0, "timestamp": (now - timedelta(seconds=s)).isoformat()}
               for s in (10, 0)]
    events += [{"equipment": "B12", "metric": "log", "level": "ERROR", "timestamp": now.isoformat(), "message": "fan3 stalled"},
               {"equipment": "INCONNU", "metric": "temperature", "value": 1, "timestamp": now.isoformat()}]
    ingestion.app.state.http = httpx.AsyncClient()
    ingestion.cache.loaded_at = 0.0
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=ingestion.app), base_url="http://i") as c:
        r = await c.post("/ingest/events", json=events, headers={"X-Source-Key": STATE["key"]})
        assert r.status_code == 200, r.text
        assert (await c.post("/ingest/events", json=[], headers={"X-Source-Key": "faux"})).status_code == 401
    assert r.json() == {"accepted": 6, "quarantined": 1}


async def test_detection_under_app_and_reader_roles(owner, app_pool):
    settings = get_settings()
    await audit_rule_changes(app_pool)  # UPDATE de l'historique (M13)
    rules, invalid = await load_rules(app_pool)
    assert invalid == []
    await ensure_status_rows(app_pool, [r.id for r in rules])
    for rule in rules:  # chaque règle active, requête sous le rôle lecture seule
        assert await run_rule(app_pool, rule, settings) is not None, rule.name
    failed = await owner.fetch("SELECT r.name, s.last_error FROM obs.rule_status s JOIN obs.detection_rule r "
                               "ON r.id = s.rule_id WHERE s.status IN ('ERROR', 'TIMEOUT')")
    assert failed == []

    by_name = {r.name: r for r in rules}
    # Chemin de suppression de rule_state (M1) : persistance commencée puis interrompue
    assert (await evaluate(app_pool, by_name["rack_temperature_high"], settings)).stats["pending"] == 1
    src = await owner.fetchval("SELECT id FROM obs.source LIMIT 1")
    eq = await owner.fetchval("SELECT id FROM obs.equipment WHERE code = 'B12'")
    await owner.execute("INSERT INTO obs.event (time, source_id, equipment_id, metric, value) "
                        "VALUES (now() + interval '1 s', $1, $2, 'temperature', 20)", src, eq)
    assert (await evaluate(app_pool, by_name["rack_temperature_high"], settings)).stats["pending"] == 0
    # Ouverture d'incident : incident + file + audit
    await owner.execute("UPDATE obs.rule_state SET pending_since = pending_since - interval '5 min'")
    assert (await evaluate(app_pool, by_name["fan_stopped"], settings)).stats["opened"] == 1
    STATE["incident"] = await owner.fetchval("SELECT id FROM obs.incident WHERE dedup_key LIKE 'fan_stopped:%'")


async def test_knowledge_indexing_under_app_role(owner, app_pool):
    stats = await indexer.index_runbooks(app_pool, HashEmbedder(), get_settings().knowledge_dir)
    assert stats["indexed"] == 4


async def test_mcp_read_tools_under_reader_role(owner):
    assert get_settings().reader_dsn.startswith("postgresql://t_mcp:")
    async with MCPToolClient(mcp_server) as tools:
        for name, args in [("get_logs", {"equipment": "B12"}),
                           ("get_metrics", {"equipment": "B12", "metric": "temperature"}),
                           ("get_topology", {"equipment": "B12"}),
                           ("get_incident_history", {"equipment": "B12"}),
                           ("search_knowledge", {"query": "ventilateur arrêté"})]:
            text = await tools.call(name, args)
            assert text.startswith("<donnee_non_fiable"), f"{name} : {text[:300]}"


def call(name, args, cid):
    return ChatResult(None, [ToolCall(cid, name, json.dumps(args))], 10)


class Scripted:
    def __init__(self, script):
        self.script = list(script)

    async def chat(self, messages, tools):
        return self.script.pop(0)


async def test_agent_and_guardrail_under_app_role(owner, app_pool):
    gw = Scripted([
        call("get_incident_history", {"equipment": "B12"}, "a"),
        call("submit_conclusion", {"diagnostic": "ventilateur arrêté", "cause_probable": "panne", "confiance": 0.9,
                                   "preuves": [], "action": {"action_id": "power_cut_rack", "cible": "B12", "parametres": {}}}, "b"),
    ])
    out = await AgentService(app_pool, get_settings(), gw, mcp_server).handle(STATE["incident"])
    assert out.status == "PROPOSED" and out.decision["decision"] == "PENDING_APPROVAL", (out.reason, out.decision)
    msgs = await outbox.claim(app_pool, outbox.TOPIC_NOTIFICATIONS, limit=50)
    assert msgs
    for m in msgs:
        await outbox.ack(app_pool, m)


async def test_console_flows_under_app_role(owner, app_pool):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=console_app), base_url="http://c") as c:
        [pending] = (await c.get("/approvals", headers=token("viewer"))).json()
        r = await c.post(f"/approvals/{pending['id']}/decision",
                         json={"decision": "APPROVE", "confirm_id": pending["id"]}, headers=token("admin"))
        assert r.status_code == 200, r.text
        for active in (True, False):
            r = await c.post("/killswitch", json={"active": active, "reason": "essai"}, headers=token("admin"))
            assert r.status_code == 200, r.text
        rule = {"name": "role_test", "rule_type": "THRESHOLD", "window_s": 120, "check_interval_s": 10,
                "severity_hint": "LOW", "params": {"metric": "temperature", "op": ">", "threshold": 50}}
        r = await c.post("/rules", json=rule, headers=token("admin"))
        assert r.status_code == 201, r.text
        r = await c.post("/rules/role_test/promote", json={"version": 1, "force": True, "reason": "essai"},
                         headers=token("admin"))
        assert r.status_code == 200, r.text
        r = await c.delete("/rules/role_test", headers=token("admin"))
        assert r.status_code == 200, r.text
        m = {"equipment": "B12", "starts_at": "2026-01-01T00:00:00Z", "ends_at": "2026-01-01T01:00:00Z", "reason": "essai"}
        assert (await c.post("/maintenance", json=m, headers=token("oncall"))).status_code == 201
        for path in ("/incidents", "/decisions", "/rules", "/shadow/report", "/autonomy/levels", "/maintenance"):
            assert (await c.get(path, headers=token("viewer"))).status_code == 200, path
        view = (await c.get("/audit", headers=token("auditor"))).json()
        assert view["chain"]["valid"] is True


async def test_sweeps_under_app_role(owner, app_pool):
    await sweep_approvals(app_pool)
    await sweep_detector_health(app_pool, 900)
    async with app_pool.acquire() as conn:
        assert (await audit.verify_chain(conn)).valid


@pytest.mark.parametrize("user,sql", [
    ("t_app", "UPDATE obs.audit_log SET actor = 'x'"),
    ("t_app", "DELETE FROM obs.incident"),
    ("t_app", "UPDATE obs.kill_switch SET active = TRUE"),
    ("t_mcp", "INSERT INTO obs.equipment (code, type, criticality, env) VALUES ('x', 'x', 'LOW', 'TEST')"),
    ("t_mcp", "SELECT auth_ref FROM obs.source"),
    ("t_mcp", "SELECT * FROM obs.audit_log"),
    ("t_ingest", "UPDATE obs.incident SET summary = 'x'"),
    ("t_ingest", "SELECT * FROM obs.approval"),
])
async def test_least_privilege(owner, user, sql):
    conn = await asyncpg.connect(dsn_for(user))
    try:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(sql)
    finally:
        await conn.close()
