"""Réplique le tampon PostgreSQL vers immudb (D12) : python -m audit.replicator

Chaque entrée est écrite avec verifiedSet, qui vérifie la preuve cryptographique
côté client. Désactivé en profil A− (OBSERVIA_IMMUDB_ENABLED=false) : le journal
PostgreSQL chaîné reste alors la seule référence.
"""
import asyncio
import json
import logging

from shared.config import get_settings
from shared.db import get_pool

log = logging.getLogger("audit.replicator")
BATCH = 200


async def replicate_once(pool, client) -> int:
    async with pool.acquire() as conn, conn.transaction():
        last_id = await conn.fetchval(
            "SELECT last_id FROM obs.audit_replication WHERE target = 'immudb' FOR UPDATE"
        )
        rows = await conn.fetch(
            "SELECT id, ts, actor, event_type, ref, payload, prev_hash, hash "
            "FROM obs.audit_log WHERE id > $1 ORDER BY id LIMIT $2",
            last_id, BATCH,
        )
        for r in rows:
            value = json.dumps({**dict(r), "ts": r["ts"].isoformat()}, sort_keys=True).encode()
            # Appel bloquant du SDK immudb, sorti de la boucle d'événements
            await asyncio.to_thread(client.verifiedSet, f"audit:{r['id']:012d}".encode(), value)
        if rows:
            await conn.execute(
                "UPDATE obs.audit_replication SET last_id = $1 WHERE target = 'immudb'", rows[-1]["id"]
            )
    return len(rows)


async def main() -> None:
    settings = get_settings()
    if not settings.immudb_enabled:
        log.warning("immudb désactivé (profil A−) : réplicateur inactif")
        while True:
            await asyncio.sleep(3600)
    from immudb import ImmudbClient  # dépendance optionnelle (extra « immudb »)

    client = ImmudbClient(settings.immudb_addr)
    client.login(settings.immudb_user, settings.immudb_password)
    pool = await get_pool(settings.db_dsn)
    while True:
        try:
            if await replicate_once(pool, client) == 0:
                await asyncio.sleep(2)
        except Exception:
            log.exception("échec de réplication ; nouvelle tentative")
            await asyncio.sleep(5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
