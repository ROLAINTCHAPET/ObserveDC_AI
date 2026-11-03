"""Mise en file d'une exécution autorisée (FR-14). Appelé par le garde-fou uniquement (SAD §6)."""
from uuid import UUID, uuid4

import asyncpg


async def enqueue_execution(conn: asyncpg.Connection, request_id: UUID) -> UUID:
    """Crée l'exécution avec un op_id unique ; dans la transaction de la décision, elle sert
    aussi de verrou sur la cible tant qu'elle n'est pas terminée (BR-05)."""
    op_id = uuid4()
    await conn.execute(
        "INSERT INTO obs.execution (request_id, op_id, status) VALUES ($1, $2, 'QUEUED')", request_id, op_id
    )
    return op_id
