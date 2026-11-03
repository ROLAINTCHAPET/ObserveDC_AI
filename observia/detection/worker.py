"""Service de pré-détection permanent, sans IA : python -m detection.worker

Chaque règle est évaluée à son propre intervalle (check_interval_s, 10 s à 5 min).
L'agent n'est réveillé que par les incidents créés ici (SAD §2.1).

Échec sûr (M10) : une règle qui plante, dépasse son délai ou est mal paramétrée lève
une alerte interne ; ses incidents ouverts restent ouverts, rien n'est conclu « normal ».
"""
import asyncio
import logging
import time
from typing import Any

import asyncpg

from audit import log as audit
from detection.engine import EvalResult, Rule, close_quiet_storm, evaluate, load_rules
from shared import notify
from shared.config import Settings, get_settings
from shared.db import get_pool

log = logging.getLogger("detection")
RELOAD_RULES_S = 30.0  # filet de sécurité si la notification est perdue
TICK_S = 1.0
RULES_CHANNEL = "observia_rules"


class RuleChangeListener:
    """LISTEN observia_rules : le déclencheur de versionnement notifie chaque changement de règle,
    qui est pris en compte au tick suivant (1 s) au lieu d'attendre le rechargement périodique."""

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self.changed = asyncio.Event()
        self.conn: asyncpg.Connection | None = None

    async def ensure(self) -> None:
        if self.conn is not None and not self.conn.is_closed():
            return
        try:
            self.conn = await asyncpg.connect(self.dsn)
            await self.conn.add_listener(RULES_CHANNEL, lambda *_: self.changed.set())
        except (OSError, asyncpg.PostgresError) as exc:
            self.conn = None
            log.warning("écoute des changements de règles indisponible (%s) : rechargement périodique seul", exc)

    def consume(self) -> bool:
        if self.changed.is_set():
            self.changed.clear()
            return True
        return False


async def audit_rule_changes(pool: asyncpg.Pool) -> int:
    """M13 : chaque version d'une règle (déclencheur SQL) est reportée dans le journal d'audit."""
    async with pool.acquire() as conn, conn.transaction():
        rows = await conn.fetch(
            "SELECT h.id, h.rule_id, h.version, h.changed_at, h.changed_by, h.definition "
            "FROM obs.detection_rule_history h WHERE NOT h.audited ORDER BY h.id FOR UPDATE SKIP LOCKED")
        for r in rows:
            await audit.append(conn, r["changed_by"], "RULE_VERSION", f"rule:{r['definition'].get('name')}", {
                "rule_id": str(r["rule_id"]), "version": r["version"], "changed_at": r["changed_at"],
                "definition": r["definition"]})
            await conn.execute("UPDATE obs.detection_rule_history SET audited = TRUE WHERE id = $1", r["id"])
    return len(rows)


async def ensure_status_rows(pool: asyncpg.Pool, rule_ids: list[Any]) -> None:
    await pool.execute(
        "INSERT INTO obs.rule_status (rule_id) SELECT unnest($1::uuid[]) ON CONFLICT DO NOTHING", rule_ids)


async def _set_status(conn, rule_id, status: str, duration_ms: int | None, detail: str | None,
                      firing: int = 0, no_data: int = 0, failed: bool = False) -> asyncpg.Record:
    """Met à jour la santé de la règle (M15) ; journalise seulement les changements de statut."""
    before = await conn.fetchrow("SELECT status, consecutive_failures, alerted_at FROM obs.rule_status "
                                 "WHERE rule_id = $1 FOR UPDATE", rule_id)
    await conn.execute(
        """
        INSERT INTO obs.rule_status (rule_id, last_eval_at, duration_ms, status, last_error, consecutive_failures,
                                     firing_keys, no_data_keys)
        VALUES ($1, now(), $2, $3, $4, $5, $6, $7)
        ON CONFLICT (rule_id) DO UPDATE SET last_eval_at = now(), duration_ms = $2, status = $3, last_error = $4,
          consecutive_failures = $5, firing_keys = $6, no_data_keys = $7
        """,
        rule_id, duration_ms, status, detail if failed else None,
        ((before["consecutive_failures"] if before else 0) + 1) if failed else 0, firing, no_data)
    if before is None or before["status"] != status:
        await conn.execute("INSERT INTO obs.rule_eval_log (rule_id, duration_ms, status, detail) VALUES ($1, $2, $3, $4)",
                           rule_id, duration_ms, status, detail)
    return before


async def record_success(pool: asyncpg.Pool, rule: Rule, result: EvalResult, duration_ms: int) -> None:
    async with pool.acquire() as conn, conn.transaction():
        before = await _set_status(conn, rule.id, result.status, duration_ms, None,
                                   result.stats["firing"], result.stats["no_data"])
        if before and before["consecutive_failures"]:
            await audit.append(conn, "detection", "RULE_EVAL_RECOVERED", f"rule:{rule.name}",
                               {"after_failures": before["consecutive_failures"]})
            await conn.execute("UPDATE obs.rule_status SET alerted_at = NULL WHERE rule_id = $1", rule.id)
            await notify.enqueue(conn, "INTERNAL", f"Règle {rule.name} de nouveau évaluée",
                                 f"Évaluation rétablie après {before['consecutive_failures']} échec(s).")


async def record_failure(pool: asyncpg.Pool, rule_id: Any, name: str, status: str, error: str,
                         duration_ms: int | None, settings: Settings) -> None:
    """M10 : jamais « normal » ; alerte interne, au plus une fois par internal_alert_interval_s."""
    async with pool.acquire() as conn, conn.transaction():
        before = await _set_status(conn, rule_id, status, duration_ms, error[:1000], failed=True)
        alerted_at = before["alerted_at"] if before else None
        now = await conn.fetchval("SELECT now()")
        if alerted_at is None or (now - alerted_at).total_seconds() > settings.internal_alert_interval_s:
            await conn.execute("UPDATE obs.rule_status SET alerted_at = now() WHERE rule_id = $1", rule_id)
            await audit.append(conn, "detection", "RULE_EVAL_FAILED", f"rule:{name}", {"status": status, "error": error[:1000]})
            await notify.enqueue(
                conn, "INTERNAL", f"Pré-détection aveugle : règle {name} en {status}",
                f"{error[:500]}\nLes incidents ouverts par cette règle restent ouverts ; aucune condition "
                "n'est considérée comme normale tant que la règle n'est pas évaluée.", level=3)


async def run_rule(pool: asyncpg.Pool, rule: Rule, settings: Settings) -> EvalResult | None:
    started = time.monotonic()
    try:
        result = await asyncio.wait_for(evaluate(pool, rule, settings), settings.rule_eval_timeout_s)
    except asyncio.TimeoutError:
        await record_failure(pool, rule.id, rule.name, "TIMEOUT", f"évaluation > {settings.rule_eval_timeout_s} s",
                             int((time.monotonic() - started) * 1000), settings)
        return None
    except Exception as exc:
        log.exception("échec de la règle %s", rule.name)
        status = "TIMEOUT" if isinstance(exc, asyncpg.QueryCanceledError) else "ERROR"
        await record_failure(pool, rule.id, rule.name, status, f"{type(exc).__name__}: {exc}",
                             int((time.monotonic() - started) * 1000), settings)
        return None
    duration_ms = int((time.monotonic() - started) * 1000)
    await record_success(pool, rule, result, duration_ms)
    if result.stats["opened"] or result.stats["resolved"] or result.stats["storm"]:
        log.info("règle %s : %s (%d ms)", rule.name, result.stats, duration_ms)
    return result


async def main() -> None:
    settings = get_settings()
    pool = await get_pool(settings.db_dsn)
    rules: list[Rule] = []
    invalid: list[tuple[Any, str, str]] = []
    next_due: dict[Any, float] = {}
    loaded_at = 0.0
    listener = RuleChangeListener(settings.db_dsn)
    while True:
        now = time.monotonic()
        notified = listener.consume()
        if notified or now - loaded_at > RELOAD_RULES_S:
            await listener.ensure()
            await audit_rule_changes(pool)
            rules, invalid = await load_rules(pool)
            await ensure_status_rows(pool, [r.id for r in rules] + [i[0] for i in invalid])
            for rule_id, name, error in invalid:
                await record_failure(pool, rule_id, name, "ERROR", error, None, settings)
            loaded_at = now
            log.info("%d règle(s) active(s), %d invalide(s)%s", len(rules), len(invalid),
                     " (changement notifié)" if notified else "")
        for rule in rules:
            # Clé = id + version : une règle modifiée est réévaluée aussitôt
            key = (rule.id, rule.version)
            if next_due.get(key, 0.0) > now:
                continue
            next_due[key] = now + rule.check_interval_s
            await run_rule(pool, rule, settings)
        await close_quiet_storm(pool, settings.storm_quiet_s)
        await asyncio.sleep(TICK_S)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
