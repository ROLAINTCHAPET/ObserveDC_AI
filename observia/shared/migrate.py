"""Applique les migrations SQL dans l'ordre : python -m shared.migrate"""
import asyncio
import logging

import asyncpg

from shared.config import ROOT, get_settings
from shared.db import _init_connection

log = logging.getLogger("migrate")


async def migrate(dsn: str) -> list[str]:
    conn = await asyncpg.connect(dsn)
    await _init_connection(conn)
    applied: list[str] = []
    try:
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS public.observia_migrations "
            "(name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        done = {r["name"] for r in await conn.fetch("SELECT name FROM public.observia_migrations")}
        for path in sorted((ROOT / "migrations").glob("*.sql")):
            if path.name in done:
                continue
            async with conn.transaction():
                await conn.execute(path.read_text())
                await conn.execute("INSERT INTO public.observia_migrations (name) VALUES ($1)", path.name)
            log.info("migration appliquée : %s", path.name)
            applied.append(path.name)
        # Le catalogue Git est la référence ; la table sert de clé étrangère (FR-11)
        from guardrail.catalog import load_catalog, sync_catalog

        await sync_catalog(conn, load_catalog(get_settings().catalog_path))
    finally:
        await conn.close()
    return applied


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(migrate(get_settings().db_dsn))
