-- RAG (modèle local, H1 invalidée) : base de connaissances vectorielle dans PostgreSQL (pgvector).
-- Corpus : runbooks versionnés dans Git et incidents résolus ayant un verdict humain.
-- Dimension liée au modèle de plongement (nomic-embed-text = 768) ; en changer = nouvelle migration.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE obs.knowledge_doc (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind         TEXT NOT NULL CHECK (kind IN ('RUNBOOK', 'INCIDENT')),
  ref          TEXT NOT NULL UNIQUE,      -- runbook:<chemin> ou incident:<id>
  title        TEXT NOT NULL,
  content_hash TEXT NOT NULL,             -- réindexation seulement si le contenu ou le modèle change
  metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
  indexed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE obs.knowledge_chunk (
  id        BIGSERIAL PRIMARY KEY,
  doc_id    UUID NOT NULL REFERENCES obs.knowledge_doc(id) ON DELETE CASCADE,
  seq       INTEGER NOT NULL,
  content   TEXT NOT NULL,
  model     TEXT NOT NULL,
  embedding vector(768) NOT NULL,
  UNIQUE (doc_id, seq)
);
CREATE INDEX knowledge_chunk_embedding ON obs.knowledge_chunk USING hnsw (embedding vector_cosine_ops);

GRANT SELECT ON obs.knowledge_doc, obs.knowledge_chunk TO observia_reader_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON obs.knowledge_doc, obs.knowledge_chunk TO observia_app_role;
GRANT USAGE, SELECT ON SEQUENCE obs.knowledge_chunk_id_seq TO observia_app_role;
