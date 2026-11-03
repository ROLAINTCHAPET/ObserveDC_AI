"""Journal d'audit chaîné par hachage (FR-21, NFR-11, décision D12).

Chaque entrée est écrite dans la transaction de la décision qu'elle trace, puis
répliquée vers immudb par audit.replicator. hash = sha256(prev_hash | ts | actor |
event_type | ref | payload canonique) : toute altération d'une ligne casse la chaîne.
"""
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import asyncpg

GENESIS = "0" * 64
# Sérialise les écritures pour que prev_hash désigne toujours la dernière ligne
_CHAIN_LOCK = 0x0B5E_A0D1


def canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def compute_hash(prev_hash: str, ts: datetime, actor: str, event_type: str, ref: str | None, payload: Any) -> str:
    material = "|".join([prev_hash, ts.isoformat(), actor, event_type, ref or "", canonical(payload)])
    return hashlib.sha256(material.encode()).hexdigest()


async def append(
    conn: asyncpg.Connection, actor: str, event_type: str, ref: str | None, payload: dict[str, Any]
) -> str:
    """Ajoute une entrée ; doit être appelé dans une transaction ouverte."""
    payload = json.loads(canonical(payload))  # ce qui est haché = ce qui est stocké
    await conn.execute("SELECT pg_advisory_xact_lock($1)", _CHAIN_LOCK)
    prev = await conn.fetchval("SELECT hash FROM obs.audit_log ORDER BY id DESC LIMIT 1") or GENESIS
    ts = datetime.now(timezone.utc)
    digest = compute_hash(prev, ts, actor, event_type, ref, payload)
    await conn.execute(
        "INSERT INTO obs.audit_log (ts, actor, event_type, ref, payload, prev_hash, hash) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7)",
        ts, actor, event_type, ref, payload, prev, digest,
    )
    return digest


@dataclass
class ChainReport:
    checked: int
    valid: bool
    first_broken_id: int | None = None


def verify_rows(rows: list[dict[str, Any]], start_prev: str = GENESIS) -> ChainReport:
    prev = start_prev
    for i, r in enumerate(rows):
        expected = compute_hash(prev, r["ts"], r["actor"], r["event_type"], r["ref"], r["payload"])
        if r["prev_hash"] != prev or r["hash"] != expected:
            return ChainReport(checked=i, valid=False, first_broken_id=r["id"])
        prev = r["hash"]
    return ChainReport(checked=len(rows), valid=True)


async def verify_chain(conn: asyncpg.Connection) -> ChainReport:
    rows = await conn.fetch(
        "SELECT id, ts, actor, event_type, ref, payload, prev_hash, hash FROM obs.audit_log ORDER BY id"
    )
    return verify_rows([dict(r) for r in rows])
