"""Essai de bout en bout avec un vrai modèle Ollama (feuille de route, phase 8 : « rejouer un
incident de test »). Base JETABLE : le schéma obs est recréé.

  OBSERVIA_DB_DSN=postgresql://... OBSERVIA_OLLAMA_URL=http://localhost:11434 \\
  OBSERVIA_MODEL_GATEWAY_URL=http://localhost:11434/v1 OBSERVIA_MODEL_NAME=qwen2.5:7b-instruct \\
  OBSERVIA_POLICY_ENGINE=local python scripts/smoke_ollama.py

Chaîne réelle : ingestion → détection → indexation RAG (plongements Ollama) → investigation
par le modèle via MCP → décision du garde-fou. Affiche les étapes et la durée de chaque phase.
"""
import asyncio
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "observia"))

import asyncpg  # noqa: E402
import httpx  # noqa: E402

from agent.gateway import ModelGateway  # noqa: E402
from agent.worker import AgentService  # noqa: E402
from detection.engine import evaluate, load_rules  # noqa: E402
from ingestion import main as ingestion  # noqa: E402
from knowledge import indexer  # noqa: E402
from knowledge import store as knowledge  # noqa: E402
from knowledge.embedder import get_embedder  # noqa: E402
from mcp_server.main import server as mcp_server  # noqa: E402
from shared.admin import DEMO, add_equipment, add_source  # noqa: E402
from shared.config import get_settings  # noqa: E402
from shared.db import get_pool  # noqa: E402
from shared.migrate import migrate  # noqa: E402


def step(title: str, started: float) -> float:
    now = time.monotonic()
    print(f"  ✓ {title} ({now - started:.1f} s)")
    return now


async def main() -> None:
    s = get_settings()
    print(f"Modèle : {s.model_name} ; plongements : {s.embed_model} ; Ollama : {s.ollama_url}")
    t = time.monotonic()

    conn = await asyncpg.connect(s.db_dsn)
    await conn.execute("DROP SCHEMA IF EXISTS obs CASCADE; DROP TABLE IF EXISTS public.observia_migrations")
    await conn.close()
    await migrate(s.db_dsn)
    pool = await get_pool(s.db_dsn)
    async with pool.acquire() as c:
        for row in DEMO:
            await add_equipment(c, *row)
        key = await add_source(c, "iot-main", "IOT")
    t = step("schéma, équipements et source", t)

    stats = await indexer.index_runbooks(pool, get_embedder(), s.knowledge_dir, s.embed_doc_prefix)
    t = step(f"runbooks indexés avec de vrais plongements : {stats}", t)
    for query in ("le ventilateur de la baie ne tourne plus", "plus aucune mesure ne remonte du collecteur"):
        hits = await knowledge.search(pool, get_embedder(), query, k=2, query_prefix=s.embed_query_prefix)
        print(f"    « {query} » → " + ", ".join(f"{h['ref']} ({h['score']})" for h in hits))
    t = step("recherche sémantique", t)

    now = datetime.now(timezone.utc)
    events = [{"equipment": "B12", "metric": "temperature", "value": 34.0 + i * 0.3,
               "timestamp": (now - timedelta(seconds=290 - i * 30)).isoformat()} for i in range(10)]
    events += [{"equipment": "B12", "metric": "fan_rpm", "value": 0, "timestamp": (now - timedelta(seconds=s_)).isoformat()}
               for s_ in (40, 20, 0)]
    events.append({"equipment": "B12", "metric": "log", "level": "ERROR", "timestamp": now.isoformat(),
                   "message": "fan3: rotor stalled, rpm=0"})
    ingestion.app.state.http = httpx.AsyncClient()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=ingestion.app), base_url="http://i") as c:
        r = await c.post("/ingest/events", json=events, headers={"X-Source-Key": key})
    t = step(f"ingestion : {r.json()}", t)

    rules, _ = await load_rules(pool)
    rule = {x.name: x for x in rules}["rack_temperature_high"]
    await evaluate(pool, rule, s)
    await pool.execute("UPDATE obs.rule_state SET pending_since = pending_since - interval '5 min'")  # for_s
    await evaluate(pool, rule, s)
    incident_id = await pool.fetchval("SELECT id FROM obs.incident LIMIT 1")
    t = step(f"détection : incident {incident_id}", t)

    gateway = ModelGateway(s.model_gateway_url, s.model_name, None, s.model_timeout_s, temperature=s.model_temperature)
    outcome = await AgentService(pool, s, gateway, mcp_server).handle(incident_id)
    t = step("investigation par le modèle", t)

    print(f"\nRésultat : {outcome.status} — {outcome.steps} appel(s) au modèle, {outcome.tokens} jetons")
    if outcome.reason:
        print(f"  motif : {outcome.reason}")
    for row in await pool.fetch(
        "SELECT st.seq, st.tool, st.args, st.duration_ms FROM obs.agent_step st "
        "JOIN obs.agent_run r ON r.id = st.run_id ORDER BY st.seq"):
        print(f"  outil {row['seq']} : {row['tool']}({row['args']}) en {row['duration_ms']} ms")
    if outcome.output:
        o = outcome.output
        print(f"  diagnostic : {o.diagnostic}\n  cause : {o.cause_probable} (confiance {o.confiance})")
        print(f"  action proposée : {o.action.model_dump() if o.action else 'aucune (escalade humaine)'}")
    if outcome.decision:
        print(f"  décision du garde-fou : {outcome.decision['decision']} (niveau {outcome.decision['effective_level']}) "
              f"{outcome.decision['reasons']}")


if __name__ == "__main__":
    asyncio.run(main())
