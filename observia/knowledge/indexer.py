"""Indexation de la base de connaissances : python -m knowledge.indexer

Deux sources :
  - les runbooks Markdown du dépôt (knowledge/), relus par l'exploitation ;
  - les incidents résolus ayant un VERDICT HUMAIN (comparaison du mode ombre ou décision
    de validation). Les conclusions de l'agent non vérifiées ne sont jamais indexées seules :
    l'agent ne doit pas s'auto-renforcer sur ses propres erreurs.
"""
import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import asyncpg

from knowledge.chunking import title_of
from knowledge.embedder import Embedder, get_embedder
from knowledge.store import delete_missing, upsert_document
from shared.config import get_settings
from shared.db import get_pool

log = logging.getLogger("knowledge.indexer")
INCIDENT_BATCH = 200

VALIDATED_INCIDENTS_SQL = """
SELECT i.id, i.summary, i.severity, i.opened_at, i.closed_at, r.name AS rule,
       e.code AS equipment, e.type AS equipment_type, e.criticality, e.env,
       ar.output, q.action_id, q.target, q.effective_level, q.decision,
       c.human_action, c.match, a.status AS approval_status, a.comment AS approval_comment
  FROM obs.incident i
  JOIN obs.detection_rule r ON r.id = i.detection_rule
  LEFT JOIN obs.equipment e ON e.id = i.equipment_id
  JOIN LATERAL (SELECT id, output FROM obs.agent_run
                 WHERE incident_id = i.id AND status <> 'RUNNING' ORDER BY started_at DESC LIMIT 1) ar ON TRUE
  JOIN obs.action_request q ON q.run_id = ar.id
  LEFT JOIN obs.shadow_comparison c ON c.request_id = q.id
  LEFT JOIN obs.approval a ON a.request_id = q.id
 WHERE i.status = 'RESOLVED'
   AND (c.match IS NOT NULL OR a.status IN ('APPROVED', 'REJECTED'))
   AND i.closed_at > now() - interval '365 days'
 ORDER BY i.closed_at DESC
 LIMIT $1
"""


def incident_document(row: dict[str, Any]) -> str:
    conclusion = ((row.get("output") or {}).get("conclusion")) or {}
    if row.get("match") is not None:
        human = row.get("human_action") or {}
        verdict = (f"action humaine réelle : {human.get('action_id')} sur {human.get('target')} — "
                   f"{'concordante' if row['match'] else 'DIFFÉRENTE de la proposition'}")
    else:
        verdict = f"validation {row['approval_status']}" + (f" ({row['approval_comment']})" if row.get("approval_comment") else "")
    return "\n".join([
        f"# Incident {row['rule']} — {row.get('equipment') or 'source'}",
        f"Résumé : {row['summary']}",
        f"Équipement : {row.get('equipment')} (type {row.get('equipment_type')}, criticité {row.get('criticality')}, {row.get('env')})",
        f"Période : {row['opened_at']:%Y-%m-%d %H:%M} → {row['closed_at']:%Y-%m-%d %H:%M} UTC",
        "",
        f"Diagnostic de l'agent : {conclusion.get('diagnostic', '—')}",
        f"Cause probable : {conclusion.get('cause_probable', '—')}",
        f"Action proposée : {row['action_id']} sur {row['target']} (niveau {row['effective_level']}, décision {row['decision']})",
        f"Verdict humain : {verdict}",
    ])


async def index_runbooks(pool: asyncpg.Pool, embedder: Embedder, root: Path, doc_prefix: str = "") -> dict[str, int]:
    stats = {"indexed": 0, "unchanged": 0, "removed": 0}
    refs: set[str] = set()
    for path in sorted(root.rglob("*.md")):
        text = path.read_text()
        ref = f"runbook:{path.relative_to(root).as_posix()}"
        refs.add(ref)
        changed = await upsert_document(pool, embedder, "RUNBOOK", ref, title_of(text, path.stem), text,
                                        {"path": path.relative_to(root).as_posix()}, doc_prefix)
        stats["indexed" if changed else "unchanged"] += 1
    stats["removed"] = await delete_missing(pool, "RUNBOOK", refs)
    return stats


async def index_incidents(pool: asyncpg.Pool, embedder: Embedder, doc_prefix: str = "") -> dict[str, int]:
    stats = {"indexed": 0, "unchanged": 0}
    for row in await pool.fetch(VALIDATED_INCIDENTS_SQL, INCIDENT_BATCH):
        row = dict(row)
        changed = await upsert_document(
            pool, embedder, "INCIDENT", f"incident:{row['id']}", f"Incident {row['rule']} {row.get('equipment') or ''}".strip(),
            incident_document(row), json.loads(json.dumps(
                {"incident_id": row["id"], "rule": row["rule"], "equipment": row.get("equipment")}, default=str)),
            doc_prefix,
        )
        stats["indexed" if changed else "unchanged"] += 1
    return stats


async def main() -> None:
    settings = get_settings()
    pool = await get_pool(settings.db_dsn)
    embedder = get_embedder()
    while True:
        try:
            runbooks = await index_runbooks(pool, embedder, settings.knowledge_dir, settings.embed_doc_prefix)
            incidents = await index_incidents(pool, embedder, settings.embed_doc_prefix)
            if runbooks["indexed"] or runbooks["removed"] or incidents["indexed"]:
                log.info("runbooks %s ; incidents %s", runbooks, incidents)
        except Exception:
            log.exception("échec de l'indexation (Ollama ou base indisponible ?)")
        await asyncio.sleep(settings.rag_index_interval_s)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
