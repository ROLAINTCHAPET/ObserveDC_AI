"""Catalogue d'actions fermé (FR-11), lu depuis policies/catalog.yaml."""
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import asyncpg
import jsonschema
import yaml


@dataclass(frozen=True)
class CatalogAction:
    action_id: str
    base_level: int
    reversible: bool
    params_schema: dict[str, Any]
    allowed_targets: dict[str, Any]
    non_intrusive: bool = False
    rollback_ref: str | None = None

    def params_valid(self, params: dict[str, Any]) -> bool:
        try:
            jsonschema.validate(params, self.params_schema)
        except jsonschema.ValidationError:
            return False
        return True


@lru_cache
def load_catalog(path: Path) -> dict[str, CatalogAction]:
    raw = yaml.safe_load(path.read_text())["catalog"]
    return {
        action_id: CatalogAction(
            action_id=action_id,
            base_level=spec["base_level"],
            reversible=spec["reversible"],
            params_schema=spec.get("params_schema", {"type": "object"}),
            allowed_targets=spec["allowed_targets"],
            non_intrusive=spec.get("non_intrusive", False),
            rollback_ref=spec.get("rollback_ref"),
        )
        for action_id, spec in raw.items()
    }


async def sync_catalog(conn: asyncpg.Connection, catalog: dict[str, CatalogAction]) -> None:
    """Reflète le catalogue Git dans obs.action_catalog (clé étrangère des demandes)."""
    await conn.executemany(
        """
        INSERT INTO obs.action_catalog (action_id, params_schema, base_level, allowed_targets, reversible, rollback_ref)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (action_id) DO UPDATE SET params_schema = EXCLUDED.params_schema,
          base_level = EXCLUDED.base_level, allowed_targets = EXCLUDED.allowed_targets,
          reversible = EXCLUDED.reversible, rollback_ref = EXCLUDED.rollback_ref
        """,
        [(a.action_id, a.params_schema, a.base_level, a.allowed_targets, a.reversible, a.rollback_ref)
         for a in catalog.values()],
    )
