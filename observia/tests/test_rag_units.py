"""RAG et modèle local : découpage, passerelle Ollama, pseudonymisation désactivée, préchargement."""
import json
from uuid import uuid4

import httpx

from agent.gateway import ModelGateway
from agent.loop import Budget, investigate
from agent.pseudonymize import Pseudonymizer
from knowledge.chunking import chunk_markdown, title_of
from tests.test_agent_loop import READ_TOOL, FakeGateway, FakeStore, FakeTools, conclusion, tool_call


def test_chunks_follow_headings_and_keep_context():
    text = "# Baie\nintro\n\n## Vérifications\nA\n\nB\n\n## Actions\nC"
    chunks = chunk_markdown(text)
    assert chunks == ["Baie\nintro", "Baie > Vérifications\nA\n\nB", "Baie > Actions\nC"]
    assert title_of(text, "x") == "Baie"


def test_long_sections_are_split():
    chunks = chunk_markdown("# T\n" + "\n\n".join(["mot " * 100] * 10), max_chars=1200)
    assert len(chunks) > 1 and all(len(c) <= 1200 + len("T\n") for c in chunks)


async def test_gateway_handles_ollama_tool_calls():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["temperature"] == 0.0 and body["model"] == "qwen2.5:7b-instruct"
        return httpx.Response(200, json={"choices": [{"message": {"content": "", "tool_calls": [
            {"function": {"name": "get_metrics", "arguments": {"equipment": "B12"}}}]}}],
            "usage": {"total_tokens": 42}})

    gw = ModelGateway("http://ollama:11434/v1", "qwen2.5:7b-instruct", None, 5,
                      client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    res = await gw.chat([], [])
    assert res.tool_calls[0].id == "call_0" and json.loads(res.tool_calls[0].arguments) == {"equipment": "B12"}
    assert res.tokens == 42


def test_pseudonymizer_disabled_is_identity():
    p = Pseudonymizer(["B12"], enabled=False)
    assert p.encode("B12 10.0.0.1") == "B12 10.0.0.1" and p.decode("EQ-001") == "EQ-001"


class KnowledgeTools(FakeTools):
    async def read_tools(self):
        return [READ_TOOL, {"type": "function", "function": {"name": "search_knowledge", "parameters": {"type": "object"}}}]

    async def call(self, name, args):
        self.calls.append((name, args))
        return '<donnee_non_fiable origine="search_knowledge">{"results": [{"title": "Ventilateur à l\'arrêt"}]}</donnee_non_fiable>'


async def test_knowledge_is_prefetched_into_first_message():
    gw, tools, store = FakeGateway([tool_call("submit_conclusion", conclusion(None))]), KnowledgeTools(), FakeStore()
    out = await investigate(uuid4(), {"summary": "fan_stopped"}, "sys", gw, tools, store, Pseudonymizer([], False),
                            Budget(), knowledge_query="vitesse du ventilateur = 0 rack")
    assert tools.calls == [("search_knowledge", {"query": "vitesse du ventilateur = 0 rack"})]
    assert "Ventilateur à l'arrêt" in gw.seen[0][1]["content"]
    assert out.tool_calls == ["search_knowledge"] and len(store.steps) == 1


async def test_no_prefetch_without_knowledge_tool():
    gw, tools = FakeGateway([tool_call("submit_conclusion", conclusion(None))]), FakeTools()
    await investigate(uuid4(), {}, "sys", gw, tools, FakeStore(), Pseudonymizer([]), Budget(), knowledge_query="x")
    assert tools.calls == []
