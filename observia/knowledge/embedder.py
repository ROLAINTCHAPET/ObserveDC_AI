"""Plongements vectoriels calculés localement par Ollama (POST /api/embed)."""
from typing import Protocol

import httpx


class Embedder(Protocol):
    model: str

    async def embed(self, texts: list[str]) -> list[list[float]]: ...


class OllamaEmbedder:
    def __init__(self, base_url: str, model: str, dim: int, timeout_s: float = 60.0,
                 client: httpx.AsyncClient | None = None) -> None:
        self.url = f"{base_url.rstrip('/')}/api/embed"
        self.model = model
        self.dim = dim
        self.client = client or httpx.AsyncClient(timeout=timeout_s)

    async def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        resp = await self.client.post(self.url, json={"model": self.model, "input": texts})
        resp.raise_for_status()
        vectors = resp.json()["embeddings"]
        if len(vectors) != len(texts) or any(len(v) != self.dim for v in vectors):
            raise ValueError(f"plongements inattendus du modèle {self.model} (dimension attendue {self.dim})")
        return vectors


_embedder: Embedder | None = None


def get_embedder() -> Embedder:
    global _embedder
    if _embedder is None:
        from shared.config import get_settings

        s = get_settings()
        _embedder = OllamaEmbedder(s.ollama_url, s.embed_model, s.embed_dim)
    return _embedder


def set_embedder(embedder: Embedder | None) -> None:
    global _embedder
    _embedder = embedder
