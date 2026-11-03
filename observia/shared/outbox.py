"""File de messages dans PostgreSQL (décision D6).

La publication se fait dans la transaction de l'appelant : l'incident et son message
sont écrits ensemble ou pas du tout. La consommation utilise un bail (lease) plutôt
qu'une transaction longue : un message dont le bail expire (redémarrage forcé) est
repris par un autre consommateur, d'où une remise « au moins une fois » ; les
consommateurs sont donc idempotents.
"""
from dataclasses import dataclass
from typing import Any

import asyncpg

TOPIC_INCIDENTS = "incidents.new"
TOPIC_APPROVALS = "approvals.pending"
TOPIC_NOTIFICATIONS = "notifications.out"

MAX_ATTEMPTS = 5


@dataclass
class Message:
    id: int
    topic: str
    payload: dict[str, Any]
    attempts: int


async def publish(conn: asyncpg.Connection, topic: str, payload: dict[str, Any]) -> int:
    return await conn.fetchval(
        "INSERT INTO obs.outbox (topic, payload) VALUES ($1, $2) RETURNING id", topic, payload
    )


async def claim(pool: asyncpg.Pool, topic: str, limit: int = 1, lease_s: int = 120) -> list[Message]:
    rows = await pool.fetch(
        """
        UPDATE obs.outbox o
           SET locked_until = now() + make_interval(secs => $3), attempts = o.attempts + 1
         WHERE o.id IN (
           SELECT id FROM obs.outbox
            WHERE topic = $1 AND processed_at IS NULL AND NOT dead
              AND available_at <= now()
              AND (locked_until IS NULL OR locked_until < now())
            ORDER BY id
            LIMIT $2
            FOR UPDATE SKIP LOCKED)
        RETURNING o.id, o.topic, o.payload, o.attempts
        """,
        topic, limit, float(lease_s),
    )
    return [Message(r["id"], r["topic"], r["payload"], r["attempts"]) for r in rows]


async def ack(pool: asyncpg.Pool, msg: Message) -> None:
    await pool.execute("UPDATE obs.outbox SET processed_at = now() WHERE id = $1", msg.id)


async def nack(pool: asyncpg.Pool, msg: Message, error: str) -> bool:
    """Replanifie avec recul exponentiel ; renvoie True si le message part en file des échecs."""
    dead = msg.attempts >= MAX_ATTEMPTS
    await pool.execute(
        """
        UPDATE obs.outbox
           SET last_error = $2, dead = $3, locked_until = NULL,
               available_at = now() + make_interval(secs => $4)
         WHERE id = $1
        """,
        msg.id, error[:2000], dead, float(2 ** msg.attempts),
    )
    return dead
