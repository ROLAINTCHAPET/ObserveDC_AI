"""Service agent : python -m agent.worker

Consomme la file incidents.new et lance une seule boucle d'investigation par incident.
"""
import asyncio
import json
import logging
import time
from dataclasses import asdict
from decimal import Decimal
from typing import Any
from uuid import UUID

import asyncpg
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from agent.degraded import degraded_message
from agent.gateway import ModelGateway
from agent.loop import Budget, Outcome, investigate
from agent.prompts import system_prompt
from agent.pseudonymize import Pseudonymizer
from audit import log as audit
from guardrail.catalog import load_catalog
from shared import notify, outbox
from shared.config import Settings, get_settings
from shared.db import get_pool

log = logging.getLogger("agent")
ACTION_TOOLS = {"propose_action"}
MODEL_COOLDOWN_S = 60.0  # après une panne du modèle, mode dégradé direct pendant ce délai


class MCPToolClient:
    """Client MCP : outils de lecture exposés au modèle, propose_action réservé à la boucle."""

    def __init__(self, target: Any, token: str | None = None) -> None:
        if isinstance(target, str):
            http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=30.0)
            target = streamable_http_client(target, http_client=http)
        self._client = Client(target)

    async def __aenter__(self) -> "MCPToolClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self._client.__aexit__(*exc)

    async def read_tools(self) -> list[dict[str, Any]]:
        listed = await self._client.list_tools()
        # NFR-13 : tout nouvel outil de lecture publié par le serveur est utilisable sans modifier l'agent
        return [
            {"type": "function", "function": {"name": t.name, "description": t.description or "",
                                              "parameters": t.input_schema}}
            for t in listed.tools if t.name not in ACTION_TOOLS
        ]

    async def call(self, name: str, args: dict[str, Any]) -> str:
        if name in ACTION_TOOLS:
            raise PermissionError("outil d'action non accessible au modèle")
        result = await self._client.call_tool(name, args)
        text = "\n".join(getattr(c, "text", "") for c in result.content)
        return f"Erreur : {text}" if getattr(result, "is_error", False) else text

    async def propose(self, run_id: UUID, action_id: str, target: str, justification: str,
                      confidence: float, params: dict[str, Any]) -> dict[str, Any]:
        result = await self._client.call_tool("propose_action", {
            "run_id": str(run_id), "action_id": action_id, "target": target,
            "justification": justification, "confidence": confidence, "params": params,
        })
        if getattr(result, "is_error", False):
            raise RuntimeError("; ".join(getattr(c, "text", "") for c in result.content))
        if isinstance(result.structured_content, dict):
            return result.structured_content
        return json.loads("".join(getattr(c, "text", "") for c in result.content))


class DbRunStore:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def record_step(self, run_id: UUID, seq: int, tool: str, args: dict[str, Any],
                          result_ref: str | None, duration_ms: int) -> None:
        await self.pool.execute(
            "INSERT INTO obs.agent_step (run_id, seq, tool, args, result_ref, duration_ms) VALUES ($1, $2, $3, $4, $5, $6)",
            run_id, seq, tool, args, result_ref, duration_ms,
        )


async def load_incident(conn: asyncpg.Connection, incident_id: UUID) -> dict[str, Any] | None:
    row = await conn.fetchrow(
        """
        SELECT i.id, i.status, i.summary, i.severity, i.opened_at, i.context, r.name AS rule,
               e.code AS equipment, e.type AS equipment_type, e.criticality, e.env, e.zone, e.rack,
               s.name AS source
          FROM obs.incident i JOIN obs.detection_rule r ON r.id = i.detection_rule
          LEFT JOIN obs.equipment e ON e.id = i.equipment_id
          LEFT JOIN obs.source s ON s.id = i.source_id
         WHERE i.id = $1
        """,
        incident_id,
    )
    if row is None:
        return None
    data = dict(row)
    data["incident_id"] = str(data.pop("id"))
    return data


class AgentService:
    def __init__(self, pool: asyncpg.Pool, settings: Settings, gateway: ModelGateway, tools_target: Any) -> None:
        self.pool = pool
        self.settings = settings
        self.gateway = gateway
        self.tools_target = tools_target
        self.catalog = load_catalog(settings.catalog_path)
        self.model_down_until = 0.0

    async def handle(self, incident_id: UUID) -> Outcome | None:
        async with self.pool.acquire() as conn:
            # Remise « au moins une fois » : un incident déjà traité n'est pas réinvestigué
            if await conn.fetchval(
                "SELECT 1 FROM obs.agent_run WHERE incident_id = $1 AND status <> 'RUNNING'", incident_id
            ):
                return None
            await conn.execute(
                "UPDATE obs.agent_run SET status = 'DEGRADED', ended_at = now(), output = $2 "
                "WHERE incident_id = $1 AND status = 'RUNNING'",
                incident_id, {"note": "exécution interrompue, reprise"},
            )
            incident = await load_incident(conn, incident_id)
            if incident is None or incident["status"] == "RESOLVED":
                return None
            run_id = await conn.fetchval(
                "INSERT INTO obs.agent_run (incident_id, model) VALUES ($1, $2) RETURNING id",
                incident_id, self.settings.model_name,
            )
            await conn.execute("UPDATE obs.incident SET status = 'INVESTIGATING' WHERE id = $1 AND status = 'OPEN'", incident_id)
            codes = [r["code"] for r in await conn.fetch("SELECT code FROM obs.equipment")]

        started = time.monotonic()
        if time.monotonic() < self.model_down_until:
            outcome = Outcome(status="DEGRADED", reason="modèle récemment indisponible (attente avant nouvel essai)")
        else:
            budget = Budget(self.settings.agent_max_steps, self.settings.agent_max_seconds, self.settings.model_timeout_s)
            try:
                async with MCPToolClient(self.tools_target, self.settings.mcp_token) as tools:
                    outcome = await investigate(
                        run_id, incident, system_prompt(self.catalog), self.gateway, tools,
                        DbRunStore(self.pool), Pseudonymizer(codes, self.settings.pseudonymize), budget,
                        knowledge_query=" ".join(filter(None, [incident["summary"], incident.get("equipment_type")])),
                    )
            except Exception as exc:
                log.exception("investigation interrompue")
                outcome = Outcome(status="DEGRADED", reason=f"erreur interne de l'agent : {type(exc).__name__}")
            if outcome.status == "DEGRADED" and "modèle" in outcome.reason:
                self.model_down_until = time.monotonic() + MODEL_COOLDOWN_S
        await self._finish(run_id, incident, outcome, time.monotonic() - started)
        return outcome

    async def _finish(self, run_id: UUID, incident: dict[str, Any], outcome: Outcome, elapsed: float) -> None:
        output = outcome.output.model_dump() if outcome.output else None
        cost = Decimal(str(outcome.tokens * self.settings.model_cost_per_mtok / 1_000_000))
        incident_id = incident["incident_id"]
        async with self.pool.acquire() as conn, conn.transaction():
            await conn.execute(
                "UPDATE obs.agent_run SET status = $2, ended_at = now(), steps = $3, tokens = $4, cost = $5, output = $6 WHERE id = $1",
                run_id, outcome.status, outcome.steps, outcome.tokens, cost,
                {"conclusion": output, "decision": outcome.decision, "reason": outcome.reason},
            )
            # BR-11 : outils appelés, données consultées (agent_step) et raisonnement résumé
            await audit.append(conn, "agent", "AGENT_RUN_FINISHED", str(run_id), {
                "incident_id": incident_id, "status": outcome.status, "reason": outcome.reason,
                "tool_calls": outcome.tool_calls, "conclusion": output, "decision": outcome.decision,
                "steps": outcome.steps, "tokens": outcome.tokens, "elapsed_s": round(elapsed, 2),
                "model": self.settings.model_name,
            })
            if outcome.status == "CONCLUDED" and outcome.output:
                await notify.enqueue(conn, "DECISION", f"Diagnostic sans action : {incident['summary']}",
                                     f"{outcome.output.diagnostic}\nConfiance : {outcome.output.confiance:.2f}",
                                     incident_id=incident_id)
            elif outcome.status == "ESCALATED":
                body = outcome.output.diagnostic if outcome.output else "Aucun diagnostic dans le budget imparti."
                await notify.enqueue(conn, "ESCALATION", f"Escalade : {incident['summary']}",
                                     f"{outcome.reason}\n{body}", level=3, incident_id=incident_id)
            elif outcome.status == "DEGRADED":
                subject, body = degraded_message(incident, outcome.reason)
                await notify.enqueue(conn, "DEGRADED", subject, body, level=3, incident_id=incident_id)


async def main() -> None:
    settings = get_settings()
    pool = await get_pool(settings.db_dsn)
    gateway = ModelGateway(settings.model_gateway_url, settings.model_name, settings.model_api_key,
                           settings.model_timeout_s, temperature=settings.model_temperature)
    service = AgentService(pool, settings, gateway, settings.mcp_url)

    async def consume() -> None:
        while True:
            msgs = await outbox.claim(pool, outbox.TOPIC_INCIDENTS, limit=1,
                                      lease_s=int(settings.agent_max_seconds * 3))
            if not msgs:
                await asyncio.sleep(0.5)
                continue
            msg = msgs[0]
            try:
                await service.handle(UUID(msg.payload["incident_id"]))
                await outbox.ack(pool, msg)
            except Exception as exc:
                log.exception("échec du traitement de l'incident %s", msg.payload)
                if await outbox.nack(pool, msg, str(exc)):
                    async with pool.acquire() as conn, conn.transaction():
                        await notify.enqueue(conn, "ESCALATION", "Incident non traité par l'agent",
                                             f"{msg.payload} : {exc}", level=3,
                                             incident_id=msg.payload.get("incident_id"))

    await asyncio.gather(*(consume() for _ in range(settings.agent_concurrency)))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
