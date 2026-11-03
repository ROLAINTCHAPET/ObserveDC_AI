"""Boucle d'investigation observer → diagnostiquer → proposer (FR-08, SAD §8.1, D9).

Plafonds : max_steps appels au modèle et max_seconds au total (NFR-06). Le modèle ne
voit que les outils de lecture et submit_conclusion ; propose_action est appelé par la
boucle elle-même, avec le run_id injecté ici, à partir d'une sortie validée par schéma.
Ce module n'importe jamais executor (règle d'isolation, SAD §6).
"""
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol
from uuid import UUID

from pydantic import ValidationError

from agent.gateway import ModelGateway, ModelUnavailable
from agent.output import CONCLUSION_TOOL, AgentOutput
from agent.prompts import incident_message
from agent.pseudonymize import Pseudonymizer

log = logging.getLogger("agent.loop")
MAX_INVALID_OUTPUTS = 2
KNOWLEDGE_TOOL = "search_knowledge"


class ToolClient(Protocol):
    async def read_tools(self) -> list[dict[str, Any]]: ...
    async def call(self, name: str, args: dict[str, Any]) -> str: ...
    async def propose(self, run_id: UUID, action_id: str, target: str, justification: str,
                      confidence: float, params: dict[str, Any]) -> dict[str, Any]: ...


class RunStore(Protocol):
    async def record_step(self, run_id: UUID, seq: int, tool: str, args: dict[str, Any],
                          result_ref: str | None, duration_ms: int) -> None: ...


@dataclass
class Budget:
    max_steps: int = 8
    max_seconds: float = 30.0
    model_timeout_s: float = 20.0


@dataclass
class Outcome:
    status: str  # PROPOSED | CONCLUDED | ESCALATED | DEGRADED
    output: AgentOutput | None = None
    decision: dict[str, Any] | None = None
    reason: str = ""
    steps: int = 0
    tokens: int = 0
    tool_calls: list[str] = field(default_factory=list)


async def investigate(
    run_id: UUID, incident: dict[str, Any], system: str, gateway: ModelGateway,
    tools: ToolClient, store: RunStore, pseudo: Pseudonymizer, budget: Budget,
    knowledge_query: str | None = None,
) -> Outcome:
    deadline = time.monotonic() + budget.max_seconds
    out = Outcome(status="ESCALATED")
    try:
        read_tools = await tools.read_tools()
    except Exception as exc:
        return Outcome(status="DEGRADED", reason=f"serveur MCP indisponible : {exc}")
    read_names = {t["function"]["name"] for t in read_tools}
    tool_specs = read_tools + [CONCLUSION_TOOL]
    invalid = 0
    seq = 0
    first = pseudo.encode(incident_message(incident))
    # RAG : récupération d'office des runbooks et cas validés proches, avant le premier appel
    # au modèle (un petit modèle local sous-utilise souvent les outils de recherche)
    if knowledge_query and KNOWLEDGE_TOOL in read_names:
        seq += 1
        context = await _call_read_tool(run_id, seq, KNOWLEDGE_TOOL, json.dumps({"query": knowledge_query}),
                                        tools, store, pseudo, deadline)
        out.tool_calls.append(KNOWLEDGE_TOOL)
        first += f"\n\nConnaissances proches (runbooks, incidents validés) :\n{context}"
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": first},
    ]

    while out.steps < budget.max_steps:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        out.steps += 1
        try:
            resp = await asyncio.wait_for(gateway.chat(messages, tool_specs), min(remaining, budget.model_timeout_s))
        except (asyncio.TimeoutError, ModelUnavailable) as exc:
            out.status, out.reason = "DEGRADED", f"modèle indisponible ou trop lent : {exc or 'délai dépassé'}"
            return out
        out.tokens += resp.tokens

        if not resp.tool_calls:
            # Sortie hors outil : on tente le JSON direct, sinon rappel à l'ordre
            conclusion = _parse(resp.content or "", pseudo)
            if conclusion is not None:
                return await _finish(run_id, conclusion, tools, out)
            invalid += 1
            if invalid >= MAX_INVALID_OUTPUTS:
                out.status, out.reason = "DEGRADED", "sorties incohérentes du modèle"
                return out
            messages.append({"role": "assistant", "content": resp.content or ""})
            messages.append({"role": "user", "content": "Termine obligatoirement par un appel à submit_conclusion."})
            continue

        messages.append({"role": "assistant", "content": resp.content, "tool_calls": [
            {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": c.arguments}}
            for c in resp.tool_calls
        ]})
        for call in resp.tool_calls:
            if call.name == "submit_conclusion":
                conclusion = _parse(call.arguments, pseudo)
                if conclusion is not None:
                    return await _finish(run_id, conclusion, tools, out)
                invalid += 1
                if invalid >= MAX_INVALID_OUTPUTS:
                    out.status, out.reason = "DEGRADED", "sorties non conformes au schéma"
                    return out
                result = "Sortie non conforme au schéma attendu ; corrige et rappelle submit_conclusion."
            elif call.name in read_names:
                seq += 1
                result = await _call_read_tool(run_id, seq, call.name, call.arguments, tools, store, pseudo, deadline)
                out.tool_calls.append(call.name)
            else:
                result = f"Outil « {call.name[:64]} » inexistant ou non autorisé."
            messages.append({"role": "tool", "tool_call_id": call.id, "content": result})

    out.status = "ESCALATED"
    out.reason = f"budget épuisé ({out.steps} étapes, plafond {budget.max_steps} / {budget.max_seconds:.0f} s)"
    return out


def _parse(raw: str, pseudo: Pseudonymizer) -> AgentOutput | None:
    try:
        data = json.loads(raw)
        return AgentOutput.model_validate(pseudo.decode_obj(data))
    except (ValueError, ValidationError, TypeError):
        return None


async def _call_read_tool(run_id: UUID, seq: int, name: str, raw_args: str, tools: ToolClient,
                          store: RunStore, pseudo: Pseudonymizer, deadline: float) -> str:
    started = time.monotonic()
    try:
        args = pseudo.decode_obj(json.loads(raw_args or "{}"))
        if not isinstance(args, dict):
            raise ValueError("arguments non objet")
    except ValueError:
        return "Arguments JSON invalides."
    try:
        result = await asyncio.wait_for(tools.call(name, args), max(0.1, deadline - time.monotonic()))
        ref = f"ok:{len(result)}c"
    except Exception as exc:
        result, ref = f"Échec de l'outil : {type(exc).__name__}", f"error:{type(exc).__name__}"
    await store.record_step(run_id, seq, name, args, ref, int((time.monotonic() - started) * 1000))
    return pseudo.encode(result)


async def _finish(run_id: UUID, conclusion: AgentOutput, tools: ToolClient, out: Outcome) -> Outcome:
    out.output = conclusion
    if conclusion.action is None:
        out.status = "CONCLUDED"
        return out
    justification = f"{conclusion.diagnostic} — cause probable : {conclusion.cause_probable}"
    try:
        out.decision = await tools.propose(
            run_id, conclusion.action.action_id, conclusion.action.cible, justification,
            conclusion.confiance, conclusion.action.parametres,
        )
    except Exception as exc:
        # Garde-fou injoignable : aucune action, escalade (NFR-10)
        out.status, out.reason = "ESCALATED", f"garde-fou injoignable : {exc}"
        return out
    out.status = "PROPOSED"
    return out
