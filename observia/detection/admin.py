"""Gestion des règles de pré-détection par l'administrateur (API de la console).

Garanties :
  - toute règle est validée (gabarit et bornes) puis EXÉCUTÉE à blanc avant d'être enregistrée :
    une règle cassée est refusée tout de suite, au lieu de lever plus tard une alerte M10 ;
  - CUSTOM_SQL : une seule requête SELECT, exécutée en lecture seule, sous le rôle lecture seule ;
  - chaque version est tracée avec le nom de la personne (déclencheur SQL + observia.actor, M13) ;
  - modification optimiste : la version attendue est exigée, pas d'écrasement silencieux ;
  - « suppression » = archivage : incidents et audit gardent leur référence ; une règle ayant
    des incidents ouverts n'est archivée que si l'on demande explicitement de les clore ;
  - calibration (M14) : une règle créée par l'API démarre EN OMBRE, sauf demande contraire.
    Elle enregistre ce qu'elle aurait détecté (rule_shadow_hit) sans créer d'incident ; le
    rapport d'ombre aide à régler les seuils, puis la promotion la passe en service.
"""
import re
from typing import Any, Literal

import asyncpg
from pydantic import BaseModel, ConfigDict, Field

from audit import log as audit
from detection.engine import STORM_RULE, Rule, RuleConfigError, observe
from detection.templates import FIRING, NO_DATA, PARAMS
from detection.worker import audit_rule_changes
from shared.config import Settings
from shared.db import get_pool

RuleType = Literal["THRESHOLD", "STATE", "RATE", "SLOPE", "FROZEN", "SILENT_SOURCE", "SILENT_EQUIPMENT", "CUSTOM_SQL"]
Severity = Literal["LOW", "MED", "HIGH", "CRITICAL"]
EDITABLE = ("rule_type", "params", "query", "window_s", "check_interval_s", "for_s", "min_data_points",
            "severity_hint", "stability_s", "maintenance_mode", "shadow", "enabled", "description")
PREVIEW_LIMIT = 50


class RuleError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class RuleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_type: RuleType
    params: dict[str, Any] = Field(default_factory=dict)
    query: str | None = Field(default=None, max_length=8000)
    window_s: int = Field(ge=10, le=7 * 86400)
    check_interval_s: int = Field(ge=10, le=300)
    for_s: int = Field(default=0, ge=0, le=86400)
    min_data_points: int = Field(default=1, ge=1, le=100_000)
    severity_hint: Severity
    stability_s: int = Field(default=120, ge=0, le=86400)
    maintenance_mode: Literal["SUPPRESS", "DEGRADE", "IGNORE"] = "SUPPRESS"
    shadow: bool = False  # M14 : conseillé pour une règle nouvelle, pendant sa calibration
    enabled: bool = True
    description: str | None = Field(default=None, max_length=500)


class RuleCreate(RuleDefinition):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    # Calibration d'abord ; « false » explicite pour une règle de sûreté à mettre en service tout de suite
    shadow: bool = True


class RulePromote(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(description="Version observée en ombre (contrôle de concurrence)")
    force: bool = False
    reason: str | None = Field(default=None, min_length=3, max_length=500)


class RulePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(description="Version sur laquelle porte la modification (contrôle de concurrence)")
    params: dict[str, Any] | None = None
    query: str | None = Field(default=None, max_length=8000)
    window_s: int | None = Field(default=None, ge=10, le=7 * 86400)
    check_interval_s: int | None = Field(default=None, ge=10, le=300)
    for_s: int | None = Field(default=None, ge=0, le=86400)
    min_data_points: int | None = Field(default=None, ge=1, le=100_000)
    severity_hint: Severity | None = None
    stability_s: int | None = Field(default=None, ge=0, le=86400)
    maintenance_mode: Literal["SUPPRESS", "DEGRADE", "IGNORE"] | None = None
    shadow: bool | None = None
    enabled: bool | None = None
    description: str | None = Field(default=None, max_length=500)


def rule_types() -> dict[str, Any]:
    """Schémas JSON des paramètres par type : de quoi construire les formulaires de la console."""
    return {name: model.model_json_schema() for name, model in PARAMS.items()}


def check_custom_query(query: str | None) -> str:
    if not query or not query.strip():
        raise RuleError(422, "CUSTOM_SQL : requête obligatoire")
    q = query.strip().rstrip(";").strip()
    if ";" in q:
        raise RuleError(422, "CUSTOM_SQL : une seule requête, sans « ; »")
    if not re.match(r"(?is)^(select|with)\b", q):
        raise RuleError(422, "CUSTOM_SQL : la requête doit commencer par SELECT ou WITH")
    if "$1" not in q:
        raise RuleError(422, "CUSTOM_SQL : la requête doit utiliser $1 (fenêtre en secondes)")
    return q


def build_rule(name: str, d: dict[str, Any], rule_id: Any = None, version: int = 0) -> Rule:
    if d["rule_type"] == "CUSTOM_SQL":
        d["query"] = check_custom_query(d.get("query"))
    elif d.get("query"):
        raise RuleError(422, "query n'est accepté que pour CUSTOM_SQL")
    else:
        d["query"] = None
    try:
        return Rule.from_row({**d, "id": rule_id, "name": name, "version": version})
    except RuleConfigError as exc:
        raise RuleError(422, str(exc)) from exc


async def dry_run(rule: Rule, settings: Settings) -> dict[str, Any]:
    """Exécute la requête de la règle une fois, en lecture seule, sans rien écrire."""
    reader = await get_pool(settings.reader_dsn)
    try:
        async with reader.acquire() as conn:
            observations = await observe(conn, rule)
    except (asyncpg.PostgresError, ValueError) as exc:
        raise RuleError(422, f"la règle échoue à l'exécution : {type(exc).__name__}: {exc}") from exc
    counts: dict[str, int] = {}
    for o in observations:
        counts[o.status] = counts.get(o.status, 0) + 1
    return {
        "keys": len(observations), "by_status": counts,
        "sample": [{"equipment_id": o.equipment_id, "source_id": o.source_id, "status": o.status,
                    "value": o.value, "detail": o.detail}
                   for o in sorted(observations, key=lambda o: (o.status != FIRING, o.status != NO_DATA))[:PREVIEW_LIMIT]],
    }


async def _as_actor(conn: asyncpg.Connection, user: str) -> None:
    # Lue par le déclencheur de versionnement : l'historique nomme la personne, pas le compte de base
    await conn.execute("SELECT set_config('observia.actor', $1, true)", user)


async def get_rule(pool: asyncpg.Pool, name: str) -> asyncpg.Record:
    row = await pool.fetchrow("SELECT * FROM obs.detection_rule WHERE name = $1 AND rule_type <> 'SYSTEM'", name)
    if row is None:
        raise RuleError(404, "règle introuvable")
    return row


async def create_rule(pool: asyncpg.Pool, body: RuleCreate, user: str, settings: Settings) -> dict[str, Any]:
    if body.name == STORM_RULE:
        raise RuleError(409, "nom réservé")
    d = body.model_dump(exclude={"name"})
    rule = build_rule(body.name, d)
    preview = await dry_run(rule, settings)
    async with pool.acquire() as conn, conn.transaction():
        existing = await conn.fetchrow("SELECT archived_at FROM obs.detection_rule WHERE name = $1", body.name)
        if existing:
            hint = " (archivée : la restaurer plutôt)" if existing["archived_at"] else ""
            raise RuleError(409, f"une règle porte déjà ce nom{hint}")
        await _as_actor(conn, user)
        await conn.execute(
            f"INSERT INTO obs.detection_rule (name, {', '.join(EDITABLE)}) "
            f"VALUES ($1, {', '.join(f'${i + 2}' for i in range(len(EDITABLE)))})",
            body.name, *(d[c] for c in EDITABLE))
    await audit_rule_changes(pool)
    return {"rule": dict(await get_rule(pool, body.name)), "dry_run": preview}


async def update_rule(pool: asyncpg.Pool, name: str, patch: RulePatch, user: str, settings: Settings) -> dict[str, Any]:
    current = await get_rule(pool, name)
    if current["archived_at"]:
        raise RuleError(409, "règle archivée : la restaurer avant de la modifier")
    changes = patch.model_dump(exclude_unset=True, exclude={"version"})
    if not changes:
        raise RuleError(422, "aucune modification")
    merged = {c: current[c] for c in EDITABLE} | changes
    rule = build_rule(name, merged, current["id"], current["version"])
    preview = await dry_run(rule, settings)
    async with pool.acquire() as conn, conn.transaction():
        await _as_actor(conn, user)
        updated = await conn.fetchval(
            f"UPDATE obs.detection_rule SET {', '.join(f'{c} = ${i + 3}' for i, c in enumerate(EDITABLE))} "
            "WHERE name = $1 AND version = $2 AND archived_at IS NULL RETURNING version",
            name, patch.version, *(merged[c] for c in EDITABLE))
        if updated is None:
            raise RuleError(409, "la règle a été modifiée entre-temps : recharger puis recommencer")
    await audit_rule_changes(pool)
    return {"rule": dict(await get_rule(pool, name)), "dry_run": preview}


async def archive_rule(pool: asyncpg.Pool, name: str, user: str, close_incidents: bool) -> dict[str, Any]:
    async with pool.acquire() as conn, conn.transaction():
        row = await conn.fetchrow("SELECT id, archived_at FROM obs.detection_rule WHERE name = $1 "
                                  "AND rule_type <> 'SYSTEM' FOR UPDATE", name)
        if row is None:
            raise RuleError(404, "règle introuvable")
        if row["archived_at"]:
            raise RuleError(409, "règle déjà archivée")
        open_ids = [r["id"] for r in await conn.fetch(
            "SELECT id FROM obs.incident WHERE detection_rule = $1 AND status <> 'RESOLVED'", row["id"])]
        if open_ids and not close_incidents:
            # Une règle qui n'est plus évaluée ne refermerait jamais ses incidents (M9)
            raise RuleError(409, f"{len(open_ids)} incident(s) ouvert(s) : les traiter, ou archiver avec close_incidents=true")
        await _as_actor(conn, user)
        await conn.execute("UPDATE obs.detection_rule SET enabled = FALSE, archived_at = now(), archived_by = $2 "
                           "WHERE id = $1", row["id"], user)
        await conn.execute("DELETE FROM obs.rule_state WHERE rule_id = $1", row["id"])
        for incident_id in open_ids:
            await conn.execute("UPDATE obs.incident SET status = 'RESOLVED', closed_at = now() WHERE id = $1", incident_id)
            await audit.append(conn, user, "INCIDENT_CLOSED_RULE_ARCHIVED", str(incident_id), {"rule": name})
    await audit_rule_changes(pool)
    return {"archived": name, "closed_incidents": len(open_ids)}


async def restore_rule(pool: asyncpg.Pool, name: str, user: str) -> dict[str, Any]:
    async with pool.acquire() as conn, conn.transaction():
        await _as_actor(conn, user)
        # Restaurée désactivée : l'administrateur la réactive en connaissance de cause
        restored = await conn.fetchval(
            "UPDATE obs.detection_rule SET archived_at = NULL, archived_by = NULL WHERE name = $1 "
            "AND archived_at IS NOT NULL RETURNING version", name)
        if restored is None:
            raise RuleError(404, "aucune règle archivée de ce nom")
    await audit_rule_changes(pool)
    return {"rule": dict(await get_rule(pool, name))}


async def preview(body: RuleDefinition | RuleCreate, settings: Settings) -> dict[str, Any]:
    return await dry_run(build_rule(getattr(body, "name", "apercu"), body.model_dump(exclude={"name"})), settings)


SHADOW_RECENT = 20


async def shadow_report(pool: asyncpg.Pool, name: str, settings: Settings) -> dict[str, Any]:
    """Ce que la règle aurait détecté pendant son observation en ombre."""
    rule = await get_rule(pool, name)
    since = rule["shadow_since"]
    report: dict[str, Any] = {
        "rule": name, "version": rule["version"], "shadow": rule["shadow"], "shadow_since": since,
        "observed_s": None, "min_observation_s": settings.rule_shadow_min_s, "ready": False,
    }
    if not rule["shadow"]:
        return report
    stats = await pool.fetchrow(
        """
        SELECT now() - $2::timestamptz AS observed, count(*) AS hits,
               count(*) FILTER (WHERE rule_version = $3) AS hits_current_version,
               count(DISTINCT dedup_key) AS distinct_keys, min(value) AS min_value, max(value) AS max_value
          FROM obs.rule_shadow_hit WHERE rule_id = $1 AND fired_at >= $2
        """, rule["id"], since, rule["version"])
    observed_s = int(stats["observed"].total_seconds())
    by_day = await pool.fetch(
        "SELECT date_trunc('day', fired_at) AS day, count(*) AS hits FROM obs.rule_shadow_hit "
        "WHERE rule_id = $1 AND fired_at >= $2 GROUP BY 1 ORDER BY 1", rule["id"], since)
    by_key = await pool.fetch(
        """
        SELECT h.dedup_key, coalesce(e.code, s.name) AS subject, count(*) AS hits, max(h.fired_at) AS last_fired_at
          FROM obs.rule_shadow_hit h LEFT JOIN obs.equipment e ON e.id = h.equipment_id
          LEFT JOIN obs.source s ON s.id = h.source_id
         WHERE h.rule_id = $1 AND h.fired_at >= $2 GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 50
        """, rule["id"], since)
    recent = await pool.fetch(
        "SELECT fired_at, rule_version, dedup_key, value, detail FROM obs.rule_shadow_hit "
        "WHERE rule_id = $1 AND fired_at >= $2 ORDER BY fired_at DESC LIMIT $3", rule["id"], since, SHADOW_RECENT)
    report.update(
        observed_s=observed_s, ready=observed_s >= settings.rule_shadow_min_s,
        hits=stats["hits"], hits_current_version=stats["hits_current_version"],
        distinct_keys=stats["distinct_keys"], value_range=[stats["min_value"], stats["max_value"]],
        by_day=[dict(r) for r in by_day], by_key=[dict(r) for r in by_key], recent=[dict(r) for r in recent],
    )
    return report


async def promote_rule(pool: asyncpg.Pool, name: str, body: RulePromote, user: str, settings: Settings) -> dict[str, Any]:
    """M14 → service : la règle crée désormais des incidents. Avant l'observation minimale,
    la promotion exige force=true et un motif, tracés dans l'audit."""
    report = await shadow_report(pool, name, settings)
    if not report["shadow"]:
        raise RuleError(409, "la règle n'est pas en mode ombre")
    if report["version"] != body.version:
        raise RuleError(409, "la règle a été modifiée entre-temps : relire le rapport d'ombre")
    if not report["ready"]:
        if not body.force:
            raise RuleError(409, f"observation en ombre trop courte ({report['observed_s']} s sur "
                                 f"{settings.rule_shadow_min_s} s) : attendre, ou forcer avec un motif")
        if not body.reason:
            raise RuleError(422, "promotion forcée : motif obligatoire")
    async with pool.acquire() as conn, conn.transaction():
        await _as_actor(conn, user)
        version = await conn.fetchval(
            "UPDATE obs.detection_rule SET shadow = FALSE WHERE name = $1 AND version = $2 AND shadow "
            "AND archived_at IS NULL RETURNING version", name, body.version)
        if version is None:
            raise RuleError(409, "la règle a été modifiée entre-temps : relire le rapport d'ombre")
        await audit.append(conn, user, "RULE_PROMOTED", f"rule:{name}", {
            "from_version": body.version, "to_version": version, "forced": not report["ready"],
            "reason": body.reason, "observed_s": report["observed_s"], "hits": report["hits"],
            "hits_current_version": report["hits_current_version"], "distinct_keys": report["distinct_keys"],
        })
    await audit_rule_changes(pool)
    return {"rule": dict(await get_rule(pool, name)), "shadow_report": report}
