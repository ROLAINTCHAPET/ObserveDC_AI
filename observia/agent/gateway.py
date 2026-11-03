"""Passerelle modèle (NFR-14) : API compatible OpenAI. Cible actuelle : Ollama sur site
(http://ollama:11434/v1), modèle local (H1 invalidée, D2 rejouée).

Changer de modèle ou de moteur (Ollama, vLLM, API cloud) = changer
OBSERVIA_MODEL_GATEWAY_URL et OBSERVIA_MODEL_NAME, sans toucher au code.
"""
import json
from dataclasses import dataclass, field
from typing import Any

import httpx


class ModelUnavailable(Exception):
    """Panne, délai ou réponse inexploitable de la passerelle : déclenche le mode dégradé (BR-08)."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str


@dataclass
class ChatResult:
    content: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    tokens: int = 0
    raw_message: dict[str, Any] = field(default_factory=dict)


class ModelGateway:
    def __init__(self, base_url: str, model: str, api_key: str | None, timeout_s: float,
                 client: httpx.AsyncClient | None = None, temperature: float | None = 0.0) -> None:
        self.url = f"{base_url.rstrip('/')}/chat/completions"
        self.model = model
        self.temperature = temperature
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.client = client or httpx.AsyncClient(timeout=timeout_s)

    async def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ChatResult:
        body = {"model": self.model, "messages": messages, "tools": tools, "tool_choice": "auto", "max_tokens": 1500}
        if self.temperature is not None:
            body["temperature"] = self.temperature
        try:
            resp = await self.client.post(self.url, json=body, headers=self.headers)
            resp.raise_for_status()
            data = resp.json()
            message = data["choices"][0]["message"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise ModelUnavailable(f"{type(exc).__name__}: {exc}") from exc
        calls = [
            ToolCall(c.get("id") or f"call_{i}", c["function"]["name"], _arguments(c["function"].get("arguments")))
            for i, c in enumerate(message.get("tool_calls") or [])
        ]
        tokens = int((data.get("usage") or {}).get("total_tokens", 0))
        return ChatResult(message.get("content"), calls, tokens, message)


def _arguments(raw: Any) -> str:
    # Certains moteurs locaux renvoient un objet plutôt qu'une chaîne JSON
    if raw is None or raw == "":
        return "{}"
    return raw if isinstance(raw, str) else json.dumps(raw)
