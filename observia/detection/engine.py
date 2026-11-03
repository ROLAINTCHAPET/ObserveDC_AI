"""Moteur de pré-détection (FR-05 à FR-07, document « Règles de pré-détection V1.0 », §4).

Pour chaque clé (équipement ou source) d'une règle, à chaque évaluation :

  sans incident ouvert  FIRING pendant for_s  → ouverture (M1), sauf règle en ombre (M14),
                                                maintenance (M6) ou tempête (M7)
                        autre statut          → la persistance repart de zéro
  incident ouvert       FIRING                → occurrence_count + 1, last_true_at (M2)
                        BETWEEN               → reste ouvert (bande d'hystérésis, M3)
                        OK pendant stability_s → fermeture (M4)
                        NO_DATA ou clé absente → reste ouvert, marqué data_missing_since (M9)

Une clé absente du résultat n'est jamais lue comme « normale ». Toute erreur remonte au
service (detection.worker), qui la traite en échec sûr (M10).
"""
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import asyncpg
from pydantic import ValidationError

from audit import log as audit
from detection.templates import BETWEEN, FIRING, NO_DATA, OK, PARAMS, Observation, build_query, classify
from shared import notify
from shared.config import Settings
from shared.db import get_pool
from shared.outbox import TOPIC_INCIDENTS, publish

log = logging.getLogger("detection.engine")

STATEMENT_TIMEOUT_MS = 5000
SEVERITIES = ["LOW", "MED", "HIGH", "CRITICAL"]
STORM_RULE = "incident_storm"
STORM_KEY = "storm"


class RuleConfigError(Exception):
    """Règle mal paramétrée : traitée comme un échec d'évaluation (M10), jamais ignorée."""


@dataclass
class Rule:
    id: Any
    name: str
    rule_type: str
    version: int
    params: Any
    raw_params: dict[str, Any]
    query: str | None
    window_s: int
    check_interval_s: int
    for_s: int
    min_data_points: int
    severity_hint: str
    stability_s: int
    maintenance_mode: str
    shadow: bool

    @classmethod
    def from_row(cls, r: asyncpg.Record) -> "Rule":
        model = PARAMS.get(r["rule_type"])
        if model is None:
            raise RuleConfigError(f"type non évaluable : {r['rule_type']}")
        try:
            params = model.model_validate(r["params"] or {})
        except ValidationError as exc:
            raise RuleConfigError(f"paramètres invalides : {exc.errors(include_url=False)[0]['msg']}") from exc
        return cls(
            id=r["id"], name=r["name"], rule_type=r["rule_type"], version=r["version"], params=params,
            raw_params=r["params"] or {}, query=r["query"], window_s=r["window_s"],
            check_interval_s=r["check_interval_s"], for_s=r["for_s"], min_data_points=r["min_data_points"],
            severity_hint=r["severity_hint"], stability_s=r["stability_s"],
            maintenance_mode=r["maintenance_mode"], shadow=r["shadow"],
        )


@dataclass
class EvalResult:
    stats: dict[str, int] = field(default_factory=lambda: dict.fromkeys(
        ("opened", "updated", "resolved", "firing", "no_data", "pending", "suppressed", "shadow", "storm"), 0))

    @property
    def status(self) -> str:
        if self.stats["firing"]:
            return "FIRING"
        return "NO_DATA" if self.stats["no_data"] else "OK"


async def load_rules(pool: asyncpg.Pool) -> tuple[list[Rule], list[tuple[Any, str, str]]]:
    """Renvoie les règles valides et, à part, les règles invalides (id, nom, erreur)."""
    rows = await pool.fetch(
        "SELECT * FROM obs.detection_rule WHERE enabled AND archived_at IS NULL AND rule_type <> 'SYSTEM' ORDER BY name"
    )
    rules, invalid = [], []
    for r in rows:
        try:
            rules.append(Rule.from_row(r))
        except RuleConfigError as exc:
            invalid.append((r["id"], r["name"], str(exc)))
    return rules, invalid


def severity(hint: str, criticality: str | None) -> str:
    """M8 : max(severity_hint, criticité de l'équipement), même logique que le garde-fou."""
    levels = [hint] + ([criticality] if criticality in SEVERITIES else [])
    return max(levels, key=SEVERITIES.index)


def dedup_key(rule: Rule, subject: Any) -> str:
    return f"{rule.name}:{subject}"


async def observe(conn: asyncpg.Connection, rule: Rule) -> list[Observation]:
    sql, args = build_query(rule.rule_type, rule.params, rule.window_s, rule.query)
    async with conn.transaction(readonly=True):
        await conn.execute(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}")
        rows = await conn.fetch(sql, *args)
    out = []
    for row in rows:
        o = classify(rule.rule_type, rule.params, dict(row), rule.window_s, rule.min_data_points)
        if o.subject is not None:
            out.append(o)
    return out


async def evaluate(pool: asyncpg.Pool, rule: Rule, settings: Settings) -> EvalResult:
    result = EvalResult()
    # Requête de la règle sous le rôle lecture seule : un CUSTOM_SQL ne peut rien modifier
    reader = await get_pool(settings.reader_dsn)
    async with reader.acquire() as rconn:
        observations = {dedup_key(rule, o.subject): o for o in await observe(rconn, rule)}
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Deux services de détection ne traitent jamais la même règle en même temps
            await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended('rule:' || $1, 0))", str(rule.id))
            ctx = await _Context.load(conn, rule, observations, settings)
            for key in sorted(set(observations) | set(ctx.open) | set(ctx.states)):
                obs = observations.get(key) or _missing(key, ctx)
                if obs.status == FIRING:
                    result.stats["firing"] += 1
                elif obs.status == NO_DATA:
                    result.stats["no_data"] += 1
                if key in ctx.open:
                    await _update_open(conn, rule, key, obs, ctx, result)
                else:
                    await _update_pending(conn, rule, key, obs, ctx, result, settings)
            if result.stats["shadow"]:
                await conn.execute("UPDATE obs.rule_status SET shadow_hits = shadow_hits + $2 WHERE rule_id = $1",
                                   rule.id, result.stats["shadow"])
    return result


@dataclass
class _Context:
    now: datetime
    open: dict[str, asyncpg.Record]
    states: dict[str, asyncpg.Record]
    equipment: dict[Any, asyncpg.Record]
    in_maintenance: set[Any]
    recent_opened: int

    @classmethod
    async def load(cls, conn, rule: Rule, observations: dict[str, Observation], settings: Settings) -> "_Context":
        now = await conn.fetchval("SELECT now()")
        open_ = {r["dedup_key"]: r for r in await conn.fetch(
            "SELECT id, dedup_key, equipment_id, source_id, cleared_at, data_missing_since FROM obs.incident "
            "WHERE detection_rule = $1 AND status <> 'RESOLVED'", rule.id)}
        states = {r["dedup_key"]: r for r in await conn.fetch(
            "SELECT dedup_key, pending_since, marked_at FROM obs.rule_state WHERE rule_id = $1", rule.id)}
        eq_ids = list({o.equipment_id for o in observations.values() if o.equipment_id})
        equipment = {r["id"]: r for r in await conn.fetch(
            "SELECT id, code, criticality FROM obs.equipment WHERE id = ANY($1::uuid[])", eq_ids)}
        maint = set()
        if rule.maintenance_mode != "IGNORE" and eq_ids:
            maint = {r["equipment_id"] for r in await conn.fetch(
                "SELECT DISTINCT equipment_id FROM obs.maintenance_window "
                "WHERE equipment_id = ANY($1::uuid[]) AND now() BETWEEN starts_at AND ends_at", eq_ids)}
        recent = await conn.fetchval(
            "SELECT count(*) FROM obs.incident WHERE opened_at > now() - interval '1 minute' AND dedup_key <> $1",
            STORM_KEY)
        return cls(now, open_, states, equipment, maint, recent)


def _missing(key: str, ctx: _Context) -> Observation:
    """Clé connue (incident ouvert ou persistance en cours) mais absente du résultat (M9)."""
    inc = ctx.open.get(key)
    return Observation(inc["equipment_id"] if inc else None, inc["source_id"] if inc else None, NO_DATA, None,
                       "aucune donnée sur la fenêtre de la règle")


async def _update_open(conn, rule: Rule, key: str, obs: Observation, ctx: _Context, result: EvalResult) -> None:
    inc = ctx.open[key]
    if obs.status == FIRING:
        await conn.execute(
            "UPDATE obs.incident SET last_true_at = now(), occurrence_count = occurrence_count + 1, cleared_at = NULL, "
            "data_missing_since = NULL, summary = $2, context = context || jsonb_build_object('last', $3::jsonb) "
            "WHERE id = $1",
            inc["id"], f"[{rule.name}] {obs.detail}", _observed(obs, ctx.now))
        result.stats["updated"] += 1
    elif obs.status == BETWEEN:
        await conn.execute("UPDATE obs.incident SET cleared_at = NULL, data_missing_since = NULL WHERE id = $1", inc["id"])
    elif obs.status == NO_DATA:
        if inc["data_missing_since"] is None:
            await conn.execute("UPDATE obs.incident SET data_missing_since = now(), cleared_at = NULL WHERE id = $1", inc["id"])
            await audit.append(conn, "detection", "INCIDENT_DATA_MISSING", str(inc["id"]), {"rule": rule.name, "key": key})
    elif inc["cleared_at"] is None:  # OK : début de la stabilisation
        await conn.execute("UPDATE obs.incident SET cleared_at = now(), data_missing_since = NULL WHERE id = $1", inc["id"])
    elif ctx.now - inc["cleared_at"] >= timedelta(seconds=rule.stability_s):
        await conn.execute("UPDATE obs.incident SET status = 'RESOLVED', closed_at = now() WHERE id = $1", inc["id"])
        await audit.append(conn, "detection", "INCIDENT_RESOLVED", str(inc["id"]),
                           {"rule": rule.name, "rule_version": rule.version, "stable_since": inc["cleared_at"]})
        result.stats["resolved"] += 1


async def _update_pending(conn, rule: Rule, key: str, obs: Observation, ctx: _Context,
                          result: EvalResult, settings: Settings) -> None:
    state = ctx.states.get(key)
    if obs.status != FIRING:
        # M1 : la condition doit rester vraie sans interruption ; NO_DATA interrompt aussi
        if state:
            await conn.execute("DELETE FROM obs.rule_state WHERE rule_id = $1 AND dedup_key = $2", rule.id, key)
        return
    pending_since = state["pending_since"] if state else ctx.now
    if ctx.now - pending_since < timedelta(seconds=rule.for_s):
        await _save_state(conn, rule, key, pending_since, obs, state["marked_at"] if state else None)
        result.stats["pending"] += 1
        return
    outcome = await _try_open(conn, rule, key, obs, ctx, state, pending_since, settings)
    result.stats[outcome] += 1
    if outcome == "opened":
        if state:
            await conn.execute("DELETE FROM obs.rule_state WHERE rule_id = $1 AND dedup_key = $2", rule.id, key)
    else:  # ombre, maintenance, tempête : la persistance est conservée, on retentera
        marked = ctx.now if outcome in ("shadow", "suppressed") else (state["marked_at"] if state else None)
        await _save_state(conn, rule, key, pending_since, obs, marked)


async def _save_state(conn, rule: Rule, key: str, pending_since, obs: Observation, marked_at) -> None:
    await conn.execute(
        """
        INSERT INTO obs.rule_state (rule_id, dedup_key, pending_since, last_status, last_value, marked_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, now())
        ON CONFLICT (rule_id, dedup_key) DO UPDATE SET pending_since = EXCLUDED.pending_since,
          last_status = EXCLUDED.last_status, last_value = EXCLUDED.last_value,
          marked_at = EXCLUDED.marked_at, updated_at = now()
        """,
        rule.id, key, pending_since, obs.status, obs.value, marked_at)


async def _try_open(conn, rule: Rule, key: str, obs: Observation, ctx: _Context, state,
                    pending_since, settings: Settings) -> str:
    equipment = ctx.equipment.get(obs.equipment_id)
    already_marked = bool(state and state["marked_at"])
    context = {
        "rule": rule.name, "rule_type": rule.rule_type, "rule_version": rule.version, "params": rule.raw_params,
        "window_s": rule.window_s, "for_s": rule.for_s, "min_data_points": rule.min_data_points,
        "severity_hint": rule.severity_hint, "equipment_criticality": equipment["criticality"] if equipment else None,
        "pending_since": pending_since, "first": _observed(obs, ctx.now),
    }

    if rule.shadow:  # M14 : enregistrée pour la calibration, sans incident ni réveil de l'agent
        if not already_marked:
            await conn.execute(
                "INSERT INTO obs.rule_shadow_hit (rule_id, rule_version, dedup_key, equipment_id, source_id, value, "
                "detail, context) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                rule.id, rule.version, key, obs.equipment_id, obs.source_id, obs.value, obs.detail,
                json.loads(json.dumps(context, default=str)))
            return "shadow"
        return "pending"
    in_maintenance = obs.equipment_id in ctx.in_maintenance
    if in_maintenance and rule.maintenance_mode == "SUPPRESS":
        if not already_marked:
            await audit.append(conn, "detection", "INCIDENT_SUPPRESSED_MAINTENANCE", key, context)
            return "suppressed"
        return "pending"

    sev = "LOW" if in_maintenance else severity(rule.severity_hint, context["equipment_criticality"])
    if ctx.recent_opened >= settings.storm_max_per_min:
        await _attach_to_storm(conn, key, obs, ctx, settings)
        return "storm"

    context.update(severity=sev, maintenance=in_maintenance)
    incident_id = await conn.fetchval(
        """
        INSERT INTO obs.incident (equipment_id, source_id, severity, detection_rule, rule_version, summary,
                                  context, dedup_key, maintenance)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (dedup_key) WHERE status <> 'RESOLVED' DO NOTHING
        RETURNING id
        """,
        obs.equipment_id, obs.source_id, sev, rule.id, rule.version, f"[{rule.name}] {obs.detail}",
        json.loads(json.dumps(context, default=str)), key, in_maintenance)
    if incident_id is None:
        return "updated"
    ctx.recent_opened += 1
    # M6 DEGRADE : incident tracé en sévérité basse, mais l'agent n'investigue pas une opération planifiée
    if not in_maintenance:
        await publish(conn, TOPIC_INCIDENTS, {"incident_id": str(incident_id)})
    await audit.append(conn, "detection", "INCIDENT_OPENED", str(incident_id), {"dedup_key": key, **context})
    return "opened"


async def _attach_to_storm(conn, key: str, obs: Observation, ctx: _Context, settings: Settings) -> None:
    """M7 : au-delà du plafond, les alertes sont regroupées dans un seul incident « tempête »,
    signalé directement à l'administrateur ; l'agent n'est pas réveillé pour chacune."""
    storm = await conn.fetchrow(
        "SELECT id, context FROM obs.incident WHERE dedup_key = $1 AND status <> 'RESOLVED' FOR UPDATE", STORM_KEY)
    if storm is None:
        rule_id = await conn.fetchval("SELECT id FROM obs.detection_rule WHERE name = $1", STORM_RULE)
        storm_id = await conn.fetchval(
            "INSERT INTO obs.incident (severity, detection_rule, summary, context, dedup_key) "
            "VALUES ('CRITICAL', $1, $2, $3, $4) RETURNING id",
            rule_id, "Tempête d'alertes : 1 alerte regroupée", {"keys": [key], "cap_per_min": settings.storm_max_per_min},
            STORM_KEY)
        await audit.append(conn, "detection", "STORM_OPENED", str(storm_id), {"first_key": key})
        await notify.enqueue(conn, "ESCALATION", "Tempête d'alertes : création d'incidents plafonnée",
                             f"Plus de {settings.storm_max_per_min} incidents par minute. Les alertes suivantes sont "
                             "regroupées dans un incident unique ; l'agent n'est pas sollicité pour chacune.",
                             level=3, incident_id=str(storm_id))
        return
    keys = list(storm["context"].get("keys", []))
    if key not in keys:
        keys.append(key)
    await conn.execute(
        "UPDATE obs.incident SET last_true_at = now(), occurrence_count = $2, summary = $3, "
        "context = context || jsonb_build_object('keys', $4::jsonb) WHERE id = $1",
        storm["id"], len(keys), f"Tempête d'alertes : {len(keys)} alertes regroupées", keys)


async def close_quiet_storm(pool: asyncpg.Pool, quiet_s: int) -> bool:
    async with pool.acquire() as conn, conn.transaction():
        storm_id = await conn.fetchval(
            "UPDATE obs.incident SET status = 'RESOLVED', closed_at = now() WHERE dedup_key = $1 "
            "AND status <> 'RESOLVED' AND last_true_at < now() - make_interval(secs => $2) RETURNING id",
            STORM_KEY, float(quiet_s))
        if storm_id:
            await audit.append(conn, "detection", "STORM_RESOLVED", str(storm_id), {})
    return storm_id is not None


def _observed(obs: Observation, at: datetime) -> dict[str, Any]:
    return json.loads(json.dumps({"at": at, "status": obs.status, "value": obs.value, "detail": obs.detail,
                                  **obs.observed}, default=str))
