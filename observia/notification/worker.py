"""Service de notification : python -m notification.worker

Consomme notifications.out, surveille l'expiration des validations (BR-10 : relance,
puis escalade, jamais d'exécution par défaut) et la santé de la pré-détection (M15) :
ce contrôle tourne hors du service de détection, pour rester vrai si celui-ci est arrêté.
"""
import asyncio
import logging
from typing import Any

import asyncpg
import httpx

from audit import log as audit
from notification.channels import Channel, EmailChannel, SmsChannel, WebhookChannel, route
from shared import notify, outbox
from shared.config import get_settings
from shared.db import get_pool

log = logging.getLogger("notification")
SWEEP_INTERVAL_S = 15.0


async def deliver(pool: asyncpg.Pool, channels: dict[str, Channel], msg: outbox.Message) -> bool:
    """Envoie sur chaque canal routé ; renvoie False s'il faut réessayer."""
    payload = msg.payload
    already = {
        (r["channel"], r["recipient"]) for r in await pool.fetch(
            "SELECT channel, recipient FROM obs.notification_log WHERE outbox_id = $1 AND status = 'SENT'", msg.id
        )
    }
    complete = True
    configured = 0
    for name in route(payload):
        channel = channels[name]
        for recipient in channel.recipients():
            configured += 1
            if (name, recipient) in already:
                continue
            error = None
            try:
                await channel.send(recipient, payload)
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"[:500]
                complete = False
                log.warning("échec %s → %s : %s", name, recipient, error)
            await pool.execute(
                "INSERT INTO obs.notification_log (outbox_id, request_id, incident_id, channel, recipient, status, error) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7)",
                msg.id, payload.get("request_id"), payload.get("incident_id"), name, recipient,
                "FAILED" if error else "SENT", error,
            )
    if configured == 0:
        log.error("aucun canal configuré pour %s : %s", payload["kind"], payload["subject"])
    return complete


async def sweep_approvals(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn, conn.transaction():
        reminders = await conn.fetch(
            """
            UPDATE obs.approval a SET reminded_at = now()
              FROM obs.action_request r
             WHERE r.id = a.request_id AND a.status = 'PENDING' AND a.reminded_at IS NULL
               AND now() > a.requested_at + (a.expires_at - a.requested_at) / 2 AND now() < a.expires_at
            RETURNING a.id, a.request_id, a.expires_at, r.action_id, r.target
            """
        )
        base = get_settings().console_base_url
        for r in reminders:
            await notify.enqueue(conn, "APPROVAL_REMINDER", f"Relance : validation requise — {r['action_id']} sur {r['target']}",
                                 f"Expire à {r['expires_at']:%H:%M:%S} UTC.", level=3,
                                 request_id=str(r["request_id"]), link=f"{base}/approvals/{r['id']}")
        expired = await conn.fetch(
            """
            UPDATE obs.approval a SET status = 'EXPIRED'
              FROM obs.action_request r
             WHERE r.id = a.request_id AND a.status = 'PENDING' AND a.expires_at < now()
            RETURNING a.id, a.request_id, r.action_id, r.target
            """
        )
        for r in expired:
            await audit.append(conn, "notification", "APPROVAL_EXPIRED", str(r["request_id"]), {"approval_id": str(r["id"])})
            await notify.enqueue(conn, "ESCALATION", f"Validation expirée sans réponse : {r['action_id']} sur {r['target']}",
                                 "Aucune action n'a été exécutée (échec sûr, BR-10). Prise en charge par l'astreinte requise.",
                                 level=3, request_id=str(r["request_id"]))


STALE_RULES_SQL = """
SELECT r.id, r.name, r.check_interval_s, greatest(s.last_eval_at, h.changed_at) AS last_seen
  FROM obs.detection_rule r
  LEFT JOIN obs.rule_status s ON s.rule_id = r.id
  LEFT JOIN LATERAL (SELECT max(changed_at) AS changed_at FROM obs.detection_rule_history
                      WHERE rule_id = r.id) h ON TRUE
 WHERE r.enabled AND r.rule_type <> 'SYSTEM'
   AND greatest(s.last_eval_at, h.changed_at) < now() - make_interval(secs => 3 * r.check_interval_s)
   AND (s.stale_alerted_at IS NULL OR s.stale_alerted_at < now() - make_interval(secs => $1))
 ORDER BY r.name
"""


async def sweep_detector_health(pool: asyncpg.Pool, alert_interval_s: int) -> list[str]:
    """M15 : règle non évaluée depuis 3 intervalles → une alerte interne groupée."""
    async with pool.acquire() as conn, conn.transaction():
        stale = await conn.fetch(STALE_RULES_SQL, float(alert_interval_s))
        if not stale:
            return []
        await conn.execute(
            "INSERT INTO obs.rule_status (rule_id, stale_alerted_at) SELECT unnest($1::uuid[]), now() "
            "ON CONFLICT (rule_id) DO UPDATE SET stale_alerted_at = now()", [r["id"] for r in stale])
        names = [r["name"] for r in stale]
        await audit.append(conn, "notification", "DETECTOR_STALE", None, {"rules": names})
        lines = [f"- {r['name']} : dernier passage {r['last_seen']:%H:%M:%S} UTC (intervalle {r['check_interval_s']} s)"
                 for r in stale]
        await notify.enqueue(conn, "INTERNAL", f"Pré-détection : {len(stale)} règle(s) non évaluée(s)",
                             "Le service de détection est peut-être arrêté ou bloqué :\n" + "\n".join(lines), level=3)
    return names


async def main() -> None:
    settings = get_settings()
    pool = await get_pool(settings.db_dsn)
    http = httpx.AsyncClient(timeout=10.0)
    channels: dict[str, Any] = {
        "email": EmailChannel(settings), "sms": SmsChannel(settings, http), "webhook": WebhookChannel(settings, http),
    }

    async def sweeper() -> None:
        while True:
            try:
                await sweep_approvals(pool)
                await sweep_detector_health(pool, settings.internal_alert_interval_s)
            except Exception:
                log.exception("échec de la surveillance des validations ou de la détection")
            await asyncio.sleep(SWEEP_INTERVAL_S)

    async def consumer() -> None:
        while True:
            msgs = await outbox.claim(pool, outbox.TOPIC_NOTIFICATIONS, limit=10, lease_s=60)
            if not msgs:
                await asyncio.sleep(0.5)
                continue
            for msg in msgs:
                if await deliver(pool, channels, msg):
                    await outbox.ack(pool, msg)
                else:
                    await outbox.nack(pool, msg, "au moins un canal en échec")

    await asyncio.gather(sweeper(), consumer())


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
