"""Pools asyncpg partagés, un par DSN (donc par rôle de base)."""
import json

import asyncpg

_pools: dict[str, asyncpg.Pool] = {}


def _dumps(v) -> bytes:
    return json.dumps(v, default=str).encode()


async def _init_connection(conn: asyncpg.Connection) -> None:
    # Format binaire : requis par COPY (ingestion en lot). jsonb = octet de version 1 + texte JSON.
    await conn.set_type_codec("json", schema="pg_catalog", format="binary",
                              encoder=_dumps, decoder=lambda b: json.loads(b))
    await conn.set_type_codec("jsonb", schema="pg_catalog", format="binary",
                              encoder=lambda v: b"\x01" + _dumps(v), decoder=lambda b: json.loads(b[1:]))


async def get_pool(dsn: str) -> asyncpg.Pool:
    pool = _pools.get(dsn)
    if pool is None:
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=10, init=_init_connection)
        _pools[dsn] = pool
    return pool


async def close_pools() -> None:
    while _pools:
        _, pool = _pools.popitem()
        await pool.close()
