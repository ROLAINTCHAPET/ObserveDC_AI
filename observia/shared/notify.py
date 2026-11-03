"""Dépôt d'une notification dans la file notifications.out (consommée par notification.worker).

Un message par incident et par fait marquant (regroupement, SAD §11) : court, avec
incident, cause probable, action, niveau et lien.
"""
from typing import Any, Literal

import asyncpg

from shared.outbox import TOPIC_NOTIFICATIONS, publish

Kind = Literal["DECISION", "APPROVAL_REQUEST", "APPROVAL_REMINDER", "ESCALATION", "DEGRADED", "KILL_SWITCH", "INGESTION", "INTERNAL"]


async def enqueue(
    conn: asyncpg.Connection,
    kind: Kind,
    subject: str,
    body: str,
    *,
    level: int | None = None,
    incident_id: str | None = None,
    request_id: str | None = None,
    link: str | None = None,
) -> None:
    payload: dict[str, Any] = {
        "kind": kind, "subject": subject, "body": body, "level": level,
        "incident_id": incident_id, "request_id": request_id, "link": link,
    }
    await publish(conn, TOPIC_NOTIFICATIONS, payload)
