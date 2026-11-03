"""Implémentation des outils MCP (SAD §8.2).

Outils de lecture : connexion au rôle lecture seule. propose_action : seule entrée vers
le garde-fou ; il ne s'exécute jamais directement (FR-10).
"""
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import httpx

from audit import log as audit
from guardrail.service import Proposal, evaluate_proposal
from knowledge import store as knowledge
from knowledge.embedder import get_embedder
from mcp_server.sanitize import wrap
from shared.config import get_settings
from shared.db import get_pool

log = logging.getLogger("mcp.tools")

AGGREGATES = {"avg": "avg(value)", "min": "min(value)", "max": "max(value)", "last": "(array_agg(value ORDER BY time DESC))[1]"}
MAX_LIMIT = 200


async def _reader():
    return await get_pool(get_settings().reader_dsn)


async def _report_injection(tool: str, ref: str, patterns: list[str]) -> None:
    pool = await get_pool(get_settings().db_dsn)
    async with pool.acquire() as conn, conn.transaction():
        await audit.append(conn, "mcp", "INJECTION_SUSPECTED", ref, {"tool": tool, "patterns": patterns})


async def _out(tool: str, ref: str, data: Any) -> str:
    s = wrap(json.dumps(data, ensure_ascii=False, default=str), tool)
    if s.suspicious:
        log.warning("motifs d'injection détectés dans %s(%s) : %s", tool, ref, s.suspicious)
        await _report_injection(tool, ref, s.suspicious)
    return s.text


async def get_logs(equipment: str, level: str | None = None, since_minutes: int = 60,
                   limit: int = 100, source: str | None = None) -> str:
    limit = max(1, min(limit, MAX_LIMIT))
    since_minutes = max(1, min(since_minutes, 24 * 60))
    settings = get_settings()
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=since_minutes)
    if settings.loki_url:
        selector = {"equipment": equipment, **({"level": level} if level else {}), **({"source": source} if source else {})}
        logql = "{" + ",".join(f'{k}="{_logql_escape(v)}"' for k, v in selector.items()) + "}"
        async with httpx.AsyncClient(timeout=5.0) as http:
            resp = await http.get(f"{settings.loki_url}/loki/api/v1/query_range", params={
                "query": logql, "start": int(start.timestamp() * 1e9), "end": int(end.timestamp() * 1e9),
                "limit": limit, "direction": "backward",
            })
            resp.raise_for_status()
        lines = [
            {"time": datetime.fromtimestamp(int(ts) / 1e9, timezone.utc).isoformat(), "level": s["stream"].get("level"), "line": line}
            for s in resp.json()["data"]["result"] for ts, line in s["values"]
        ]
    else:
        rows = await (await _reader()).fetch(
            """
            SELECT e.time, e.level, e.payload - '_ingest' AS payload FROM obs.event e
              JOIN obs.equipment q ON q.id = e.equipment_id
             WHERE q.code = $1 AND e.metric = 'log' AND e.time > $2 AND ($3::text IS NULL OR e.level = $3)
             ORDER BY e.time DESC LIMIT $4
            """,
            equipment, start, level, limit,
        )
        lines = [dict(r) for r in rows]
    return await _out("get_logs", equipment, {"equipment": equipment, "count": len(lines), "lines": lines})


def _logql_escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"')


async def get_metrics(equipment: str, metric: str, period_minutes: int = 60,
                      aggregate: str = "avg", bucket_minutes: int = 5) -> str:
    agg = AGGREGATES.get(aggregate)
    if agg is None:
        return f"agrégat inconnu ; valeurs possibles : {', '.join(AGGREGATES)}"
    period_minutes = max(1, min(period_minutes, 7 * 24 * 60))
    bucket_minutes = max(1, min(bucket_minutes, period_minutes))
    rows = await (await _reader()).fetch(
        f"""
        SELECT date_bin(make_interval(mins => $3), e.time, TIMESTAMPTZ '2000-01-01') AS bucket, {agg} AS value, count(*) AS n
          FROM obs.event e JOIN obs.equipment q ON q.id = e.equipment_id
         WHERE q.code = $1 AND e.metric = $2 AND e.time > now() - make_interval(mins => $4)
         GROUP BY bucket ORDER BY bucket
        """,
        equipment, metric, bucket_minutes, period_minutes,
    )
    series = [{"t": r["bucket"].isoformat(), "v": r["value"], "n": r["n"]} for r in rows]
    return await _out("get_metrics", equipment, {"equipment": equipment, "metric": metric,
                                                  "aggregate": aggregate, "series": series})


async def get_topology(equipment: str) -> str:
    pool = await _reader()
    eq = await pool.fetchrow("SELECT id, code, type, zone, rack, criticality, env FROM obs.equipment WHERE code = $1", equipment)
    if eq is None:
        return await _out("get_topology", equipment, {"error": "équipement inconnu"})
    parents = await pool.fetch(
        "SELECT e.code, e.type, e.criticality FROM obs.equipment_dependency d JOIN obs.equipment e ON e.id = d.parent_id WHERE d.child_id = $1",
        eq["id"],
    )
    children = await pool.fetch(
        "SELECT e.code, e.type, e.criticality FROM obs.equipment_dependency d JOIN obs.equipment e ON e.id = d.child_id WHERE d.parent_id = $1",
        eq["id"],
    )
    neighbours = await pool.fetch(
        "SELECT code, type FROM obs.equipment WHERE rack IS NOT DISTINCT FROM $1 AND zone IS NOT DISTINCT FROM $2 AND id <> $3 LIMIT 50",
        eq["rack"], eq["zone"], eq["id"],
    )
    data = {k: eq[k] for k in ("code", "type", "zone", "rack", "criticality", "env")}
    data.update(depends_on=[dict(r) for r in parents], dependents=[dict(r) for r in children],
                same_rack=[dict(r) for r in neighbours])
    return await _out("get_topology", equipment, data)


async def get_incident_history(equipment: str, period_days: int = 30) -> str:
    period_days = max(1, min(period_days, 365))
    rows = await (await _reader()).fetch(
        """
        SELECT i.id, i.opened_at, i.closed_at, i.status, i.severity, i.summary,
               r.action_id, r.target, r.effective_level, r.decision
          FROM obs.incident i JOIN obs.equipment q ON q.id = i.equipment_id
          LEFT JOIN obs.agent_run ar ON ar.incident_id = i.id
          LEFT JOIN obs.action_request r ON r.run_id = ar.id
         WHERE q.code = $1 AND i.opened_at > now() - make_interval(days => $2)
         ORDER BY i.opened_at DESC LIMIT 50
        """,
        equipment, period_days,
    )
    return await _out("get_incident_history", equipment, {"equipment": equipment, "incidents": [dict(r) for r in rows]})


async def search_knowledge(query: str, kind: str | None = None, k: int | None = None) -> str:
    """RAG : runbooks et incidents passés validés par un humain, les plus proches de la requête."""
    settings = get_settings()
    if kind is not None and kind not in ("RUNBOOK", "INCIDENT"):
        return "kind doit valoir RUNBOOK, INCIDENT ou être omis."
    hits = await knowledge.search(
        await _reader(), get_embedder(), query[:1000], k=max(1, min(k or settings.rag_top_k, 10)), kind=kind,
        min_score=settings.rag_min_score, query_prefix=settings.embed_query_prefix,
    )
    return await _out("search_knowledge", query[:64], {"query": query[:200], "results": hits})


async def propose_action(run_id: str, action_id: str, target: str, justification: str,
                         confidence: float, params: dict[str, Any] | None = None) -> dict[str, Any]:
    settings = get_settings()
    pool = await get_pool(settings.db_dsn)
    incident_id = await pool.fetchval("SELECT incident_id FROM obs.agent_run WHERE id = $1", UUID(run_id))
    if incident_id is None:
        return {"decision": "REFUSED", "reasons": ["exécution d'agent inconnue"]}
    decision = await evaluate_proposal(pool, Proposal(
        run_id=UUID(run_id), action_id=action_id, target=target, params=params or {},
        justification=justification[:4000], confidence=confidence, incident_id=incident_id,
    ))
    # L'agent ne reçoit que la décision : pas d'op_id, pas de faits internes
    return {"decision": decision.decision, "effective_level": decision.effective_level,
            "reasons": decision.reasons, "request_id": str(decision.request_id) if decision.request_id else None}
