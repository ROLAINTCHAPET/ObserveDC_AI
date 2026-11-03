"""Administration : python -m shared.admin <commande>

  add-source NOM KIND               enregistre une source (IOT|CARD|SOFTWARE) et affiche sa clé UNE fois
  add-equipment CODE TYPE CRIT ENV  [--zone Z] [--rack R] [--parent CODE]
  demo-seed                         jeu d'équipements de démonstration (baie B12…)
  verify-audit                      vérifie la chaîne de hachage du journal d'audit
"""
import argparse
import asyncio
import hashlib
import secrets

import asyncpg

from audit import log as audit
from shared.config import get_settings
from shared.db import _init_connection


async def add_source(conn: asyncpg.Connection, name: str, kind: str) -> str:
    key = secrets.token_urlsafe(32)
    async with conn.transaction():
        await conn.execute("INSERT INTO obs.source (name, kind, auth_ref) VALUES ($1, $2, $3)",
                           name, kind, hashlib.sha256(key.encode()).hexdigest())
        await audit.append(conn, "admin-cli", "SOURCE_REGISTERED", name, {"kind": kind})
    return key


async def add_equipment(conn: asyncpg.Connection, code: str, type_: str, criticality: str, env: str,
                        zone: str | None = None, rack: str | None = None, parent: str | None = None) -> None:
    async with conn.transaction():
        eq_id = await conn.fetchval(
            """
            INSERT INTO obs.equipment (code, type, zone, rack, criticality, env) VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (code) DO UPDATE SET type = EXCLUDED.type, zone = EXCLUDED.zone, rack = EXCLUDED.rack,
              criticality = EXCLUDED.criticality, env = EXCLUDED.env
            RETURNING id
            """,
            code, type_, zone, rack, criticality, env,
        )
        if parent:
            await conn.execute(
                "INSERT INTO obs.equipment_dependency (parent_id, child_id) "
                "SELECT id, $2 FROM obs.equipment WHERE code = $1 ON CONFLICT DO NOTHING",
                parent, eq_id,
            )


DEMO = [
    ("B12", "rack", "MED", "PROD", "Z1", "B12", None),
    ("srv-b12-01", "server", "MED", "PROD", "Z1", "B12", "B12"),
    ("srv-b12-02", "server", "LOW", "TEST", "Z1", "B12", "B12"),
    ("B13", "rack", "HIGH", "PROD", "Z1", "B13", None),
    ("stor-ctrl-01", "storage_controller", "CRITICAL", "PROD", "Z1", "B13", "B13"),
    ("srv-test-01", "server", "LOW", "TEST", "Z2", "C01", None),
    ("crac-z1", "crac", "HIGH", "PROD", "Z1", None, None),
]


async def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m shared.admin")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("add-source")
    s.add_argument("name")
    s.add_argument("kind", choices=["IOT", "CARD", "SOFTWARE"])
    e = sub.add_parser("add-equipment")
    e.add_argument("code")
    e.add_argument("type")
    e.add_argument("criticality", choices=["LOW", "MED", "HIGH", "CRITICAL"])
    e.add_argument("env", choices=["TEST", "PROD"])
    e.add_argument("--zone")
    e.add_argument("--rack")
    e.add_argument("--parent")
    sub.add_parser("demo-seed")
    sub.add_parser("verify-audit")
    args = parser.parse_args()

    conn = await asyncpg.connect(get_settings().db_dsn)
    await _init_connection(conn)
    try:
        if args.cmd == "add-source":
            key = await add_source(conn, args.name, args.kind)
            print(f"Source « {args.name} » enregistrée. Clé d'API (affichée une seule fois) :\n{key}")
        elif args.cmd == "add-equipment":
            await add_equipment(conn, args.code, args.type, args.criticality, args.env, args.zone, args.rack, args.parent)
            print(f"Équipement {args.code} enregistré.")
        elif args.cmd == "demo-seed":
            for row in DEMO:
                await add_equipment(conn, *row)
            print(f"{len(DEMO)} équipements de démonstration enregistrés.")
        elif args.cmd == "verify-audit":
            report = await audit.verify_chain(conn)
            print(f"Chaîne {'VALIDE' if report.valid else 'ROMPUE'} : {report.checked} entrée(s) vérifiée(s)"
                  + (f", première entrée invalide : {report.first_broken_id}" if not report.valid else ""))
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
