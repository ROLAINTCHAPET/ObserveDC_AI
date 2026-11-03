"""Base de connaissances vectorielle (pgvector) : indexation et recherche par similarité."""
import hashlib
from typing import Any

import asyncpg

from knowledge.chunking import chunk_markdown
from knowledge.embedder import Embedder


def to_pgvector(v: list[float]) -> str:
    return "[" + ",".join(f"{x:.7g}" for x in v) + "]"


def content_hash(content: str, model: str) -> str:
    return hashlib.sha256(f"{model}\n{content}".encode()).hexdigest()


async def upsert_document(
    pool: asyncpg.Pool, embedder: Embedder, kind: str, ref: str, title: str, content: str,
    metadata: dict[str, Any] | None = None, doc_prefix: str = "",
) -> bool:
    """Indexe un document ; renvoie False s'il était déjà à jour."""
    digest = content_hash(content, embedder.model)
    if await pool.fetchval("SELECT content_hash FROM obs.knowledge_doc WHERE ref = $1", ref) == digest:
        return False
    chunks = chunk_markdown(content)
    # Le calcul des plongements (lent) se fait hors transaction
    vectors = await embedder.embed([f"{doc_prefix}{title}\n{c}" for c in chunks])
    async with pool.acquire() as conn, conn.transaction():
        doc_id = await conn.fetchval(
            """
            INSERT INTO obs.knowledge_doc (kind, ref, title, content_hash, metadata) VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (ref) DO UPDATE SET title = EXCLUDED.title, content_hash = EXCLUDED.content_hash,
              metadata = EXCLUDED.metadata, indexed_at = now()
            RETURNING id
            """,
            kind, ref, title, digest, metadata or {},
        )
        await conn.execute("DELETE FROM obs.knowledge_chunk WHERE doc_id = $1", doc_id)
        await conn.executemany(
            "INSERT INTO obs.knowledge_chunk (doc_id, seq, content, model, embedding) VALUES ($1, $2, $3, $4, $5::vector)",
            [(doc_id, i, c, embedder.model, to_pgvector(v)) for i, (c, v) in enumerate(zip(chunks, vectors))],
        )
    return True


async def delete_missing(pool: asyncpg.Pool, kind: str, keep_refs: set[str]) -> int:
    rows = await pool.fetch(
        "DELETE FROM obs.knowledge_doc WHERE kind = $1 AND NOT (ref = ANY($2::text[])) RETURNING id",
        kind, list(keep_refs),
    )
    return len(rows)


async def search(
    pool: asyncpg.Pool, embedder: Embedder, query: str, k: int = 4, kind: str | None = None,
    min_score: float = 0.0, query_prefix: str = "",
) -> list[dict[str, Any]]:
    [vector] = await embedder.embed([f"{query_prefix}{query}"])
    rows = await pool.fetch(
        """
        SELECT d.kind, d.ref, d.title, c.content, 1 - (c.embedding <=> $1::vector) AS score
          FROM obs.knowledge_chunk c JOIN obs.knowledge_doc d ON d.id = c.doc_id
         WHERE c.model = $2 AND ($3::text IS NULL OR d.kind = $3)
         ORDER BY c.embedding <=> $1::vector
         LIMIT $4
        """,
        to_pgvector(vector), embedder.model, kind, k,
    )
    return [dict(r) | {"score": round(r["score"], 3)} for r in rows if r["score"] >= min_score]
