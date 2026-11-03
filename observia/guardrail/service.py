"""Garde-fou : point d'entrée unique entre une proposition et l'exécution (FR-10 à FR-13).

La décision, le verrou par cible et le compteur de quota sont posés dans une même
transaction PostgreSQL (D17). Les faits (criticité, périmètre, kill switch, niveaux
ouverts, quotas) viennent de la base, jamais de l'agent. Toute erreur du moteur de
politiques donne PENDING_APPROVAL (NFR-10).
"""
import logging
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Any
from uuid import UUID

import asyncpg

from audit import log as audit
from executor.queue import enqueue_execution
from guardrail.catalog import CatalogAction, load_catalog
from guardrail.policy import FAIL_SAFE, LocalPolicy, OpaPolicy, PolicyEngine, PolicyResult
from shared import notify
from shared.config import Settings, get_settings

log = logging.getLogger("guardrail")

QUOTA_SCOPE = "auto_actions"


@dataclass
class Proposal:
    run_id: UUID
    action_id: str
    target: str
    params: dict[str, Any]
    justification: str
    confidence: float | None
    incident_id: UUID | None = None


@dataclass
class Decision:
    decision: str
    effective_level: int
    reasons: list[str]
    request_id: UUID | None = None
    approval_id: UUID | None = None
    op_id: UUID | None = None
    facts: dict[str, Any] = field(default_factory=dict)


_engine: PolicyEngine | None = None


def get_engine(settings: Settings | None = None) -> PolicyEngine:
    global _engine
    if _engine is None:
        settings = settings or get_settings()
        if settings.policy_engine == "local":
            _engine = LocalPolicy(load_catalog(settings.catalog_path))
        else:
            _engine = OpaPolicy(settings.opa_url, settings.opa_timeout_s)
    return _engine


def set_engine(engine: PolicyEngine | None) -> None:
    global _engine
    _engine = engine


def shadow_mode(settings: Settings) -> bool:
    # Sans exécuteur actif, rien ne peut être exécuté : le mode ombre est imposé
    return settings.shadow_mode or not settings.execution_enabled


async def resolve_target(conn: asyncpg.Connection, target: str) -> dict[str, Any]:
    """Cible → faits pour la politique, dont le périmètre d'impact (BR-06)."""
    if target.startswith("zone:"):
        row = await conn.fetchrow(
            """
            SELECT count(*) AS n, bool_or(env = 'PROD') AS prod,
                   max(CASE criticality WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MED' THEN 2 ELSE 1 END) AS crit
              FROM obs.equipment WHERE zone = $1
            """,
            target[5:],
        )
        crit = {4: "CRITICAL", 3: "HIGH", 2: "MED", 1: "LOW"}.get(row["crit"], "LOW")
        return {"known": row["n"] > 0, "kind": "zone", "type": "zone", "criticality": crit,
                "env": "PROD" if row["prod"] else "TEST", "impacted_count": row["n"]}
    if target.startswith("site:"):
        n = await conn.fetchval("SELECT count(*) FROM obs.equipment")
        return {"known": True, "kind": "site", "type": "site", "criticality": "CRITICAL",
                "env": "PROD", "impacted_count": n}
    row = await conn.fetchrow(
        """
        WITH RECURSIVE impacted AS (
          SELECT id FROM obs.equipment WHERE code = $1
          UNION
          SELECT d.child_id FROM obs.equipment_dependency d JOIN impacted i ON d.parent_id = i.id
        )
        SELECT e.type, e.criticality, e.env, (SELECT count(*) FROM impacted) AS impacted
          FROM obs.equipment e WHERE e.code = $1
        """,
        target,
    )
    if row is None:
        return {"known": False, "kind": "equipment", "type": None, "criticality": None, "env": None,
                "impacted_count": 0}
    return {"known": True, "kind": "equipment", "type": row["type"], "criticality": row["criticality"],
            "env": row["env"], "impacted_count": row["impacted"]}


async def kill_switch_active(conn: asyncpg.Connection) -> bool:
    return bool(await conn.fetchval("SELECT active FROM obs.kill_switch ORDER BY id DESC LIMIT 1"))


async def gather_state(conn: asyncpg.Connection, target: str, settings: Settings) -> dict[str, Any]:
    # Sérialise les évaluations sur une même cible jusqu'à la fin de la transaction
    await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended('target:' || $1, 0))", target)
    lock_held = await conn.fetchval(
        """
        SELECT EXISTS (SELECT 1 FROM obs.execution x JOIN obs.action_request r ON r.id = x.request_id
                        WHERE r.target = $1 AND x.status IN ('QUEUED', 'RUNNING'))
        """,
        target,
    )
    used = await conn.fetchval(
        "SELECT count FROM obs.rate_counter WHERE scope = $1 AND window_start = date_trunc('hour', now())",
        QUOTA_SCOPE,
    ) or 0
    open_levels = [r["level"] for r in await conn.fetch("SELECT level FROM obs.autonomy_state WHERE enabled")]
    return {
        "kill_switch": await kill_switch_active(conn),
        "shadow_mode": shadow_mode(settings),
        "open_levels": open_levels,
        "quota_exceeded": used >= settings.max_auto_actions_per_hour,
        "lock_held": bool(lock_held),
    }


async def _decide(
    conn: asyncpg.Connection, action: CatalogAction | None, action_id: str, target: str,
    params: dict[str, Any], confidence: float | None, human_approval: bool, settings: Settings,
) -> tuple[PolicyResult, dict[str, Any], str]:
    policy_input = {
        "action_id": action_id,
        "params_valid": action.params_valid(params) if action else False,
        "confidence": confidence,
        "human_approval": human_approval,
        "target": await resolve_target(conn, target),
        "state": await gather_state(conn, target, settings),
        "limits": {"max_impacted_equipment": settings.max_impacted_equipment,
                   "min_confidence": settings.min_confidence},
    }
    engine = get_engine(settings)
    try:
        result = await engine.evaluate(policy_input)
    except Exception as exc:
        log.error("moteur de politiques en erreur (%s) : échec sûr", exc)
        return FAIL_SAFE, policy_input, f"{engine.name}:error"
    if result.decision not in {"EXECUTE", "PENDING_APPROVAL", "REFUSED", "SHADOW"} or result.effective_level not in (1, 2, 3):
        return FAIL_SAFE, policy_input, f"{engine.name}:invalid"
    return result, policy_input, engine.name


async def evaluate_proposal(pool: asyncpg.Pool, p: Proposal, settings: Settings | None = None) -> Decision:
    settings = settings or get_settings()
    action = load_catalog(settings.catalog_path).get(p.action_id)
    async with pool.acquire() as conn, conn.transaction():
        result, facts, engine = await _decide(
            conn, action, p.action_id, p.target, p.params, p.confidence, False, settings
        )
        out = Decision(result.decision, result.effective_level, result.reasons, facts=facts)
        trace = {"proposal": {**asdict(p), "run_id": str(p.run_id)}, "input": facts,
                 "result": asdict(result), "engine": engine}
        incident = str(p.incident_id) if p.incident_id else None

        if action is None:
            # Action hors catalogue : pas de ligne action_request (clé étrangère), mais trace complète
            await audit.append(conn, "guardrail", "PROPOSAL_REFUSED", str(p.run_id), trace)
            await notify.enqueue(conn, "DECISION", f"Proposition refusée : action inconnue « {p.action_id[:64]} »",
                                 "L'agent a proposé une action hors catalogue ; elle a été refusée.",
                                 level=3, incident_id=incident)
            return out

        out.request_id = await conn.fetchval(
            """
            INSERT INTO obs.action_request (run_id, action_id, target, params, justification, confidence,
                                            effective_level, decision, reasons)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id
            """,
            p.run_id, p.action_id, p.target, p.params, p.justification, p.confidence,
            result.effective_level, result.decision, result.reasons,
        )
        rid = str(out.request_id)
        summary = f"{p.action_id} sur {p.target} — niveau {result.effective_level}"
        if result.decision == "EXECUTE":
            await conn.execute(
                """
                INSERT INTO obs.rate_counter (scope, window_start, count) VALUES ($1, date_trunc('hour', now()), 1)
                ON CONFLICT (scope, window_start) DO UPDATE SET count = obs.rate_counter.count + 1
                """,
                QUOTA_SCOPE,
            )
            out.op_id = await enqueue_execution(conn, out.request_id)
            body = f"Exécution automatique autorisée (op {out.op_id}). {p.justification}"
            link = f"{settings.console_base_url}/executions?request={rid}"
            await notify.enqueue(conn, "DECISION", f"Action exécutée : {summary}", body,
                                 level=result.effective_level, incident_id=incident, request_id=rid, link=link)
        elif result.decision == "PENDING_APPROVAL":
            out.approval_id = await conn.fetchval(
                "INSERT INTO obs.approval (request_id, expires_at) VALUES ($1, now() + $2) RETURNING id",
                out.request_id, timedelta(seconds=settings.approval_ttl_s),
            )
            link = f"{settings.console_base_url}/approvals/{out.approval_id}"
            body = f"{p.justification}\nMotifs : {'; '.join(result.reasons)}"
            await notify.enqueue(conn, "APPROVAL_REQUEST", f"Validation requise : {summary}", body,
                                 level=3, incident_id=incident, request_id=rid, link=link)
        elif result.decision == "SHADOW":
            await conn.execute(
                "INSERT INTO obs.shadow_comparison (request_id, agent_action) VALUES ($1, $2)",
                out.request_id, {"action_id": p.action_id, "target": p.target, "params": p.params},
            )
            await notify.enqueue(conn, "DECISION", f"[Mode ombre] Proposition : {summary}", p.justification,
                                 level=result.effective_level, incident_id=incident, request_id=rid,
                                 link=f"{settings.console_base_url}/decisions?request={rid}")
        else:
            await notify.enqueue(conn, "DECISION", f"Proposition refusée : {summary}",
                                 f"Motifs : {'; '.join(result.reasons)}",
                                 level=result.effective_level, incident_id=incident, request_id=rid)
        await audit.append(conn, "guardrail", "GUARDRAIL_DECISION", rid, trace)
    return out


class ApprovalError(Exception):
    pass


async def decide_approval(
    pool: asyncpg.Pool, approval_id: UUID, user: str, approve: bool, comment: str | None,
    settings: Settings | None = None,
) -> Decision:
    """UC-04 : approbation authentifiée, avec nouvelle évaluation du garde-fou au moment
    de l'approbation (le contexte a pu changer, SAD §9.4)."""
    settings = settings or get_settings()
    async with pool.acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """
            SELECT a.id, a.status, a.expires_at < now() AS expired, r.id AS request_id, r.action_id,
                   r.target, r.params, r.confidence, ar.incident_id
              FROM obs.approval a JOIN obs.action_request r ON r.id = a.request_id
              JOIN obs.agent_run ar ON ar.id = r.run_id
             WHERE a.id = $1 FOR UPDATE OF a
            """,
            approval_id,
        )
        if row is None:
            raise ApprovalError("validation introuvable")
        if row["status"] != "PENDING":
            raise ApprovalError(f"validation déjà traitée ({row['status']})")
        if row["expired"]:
            raise ApprovalError("validation expirée : aucune exécution par défaut (BR-10)")
        rid, incident = str(row["request_id"]), str(row["incident_id"])

        if not approve:
            await conn.execute(
                "UPDATE obs.approval SET status = 'REJECTED', decision = 'REJECT', decided_by = $2, "
                "decided_at = now(), comment = $3 WHERE id = $1",
                approval_id, user, comment,
            )
            await audit.append(conn, user, "APPROVAL_REJECTED", rid, {"approval_id": str(approval_id), "comment": comment})
            await notify.enqueue(conn, "DECISION", f"Action refusée par {user} : {row['action_id']} sur {row['target']}",
                                 comment or "", level=3, incident_id=incident, request_id=rid)
            return Decision("REFUSED", 3, ["refusée par l'administrateur"], request_id=row["request_id"],
                            approval_id=approval_id)

        action = load_catalog(settings.catalog_path).get(row["action_id"])
        result, facts, engine = await _decide(
            conn, action, row["action_id"], row["target"], row["params"], row["confidence"], True, settings
        )
        out = Decision(result.decision, result.effective_level, result.reasons, request_id=row["request_id"],
                       approval_id=approval_id, facts=facts)
        if result.decision == "PENDING_APPROVAL":
            # Ex. : action en cours sur la cible ; la validation reste ouverte
            await audit.append(conn, user, "APPROVAL_DEFERRED", rid, {"result": asdict(result), "engine": engine})
            return out
        status = "APPROVED" if result.decision == "EXECUTE" else "REJECTED"
        await conn.execute(
            "UPDATE obs.approval SET status = $2, decision = 'APPROVE', decided_by = $3, decided_at = now(), "
            "comment = $4 WHERE id = $1",
            approval_id, status, user, comment,
        )
        if result.decision == "EXECUTE" and settings.execution_enabled:
            out.op_id = await enqueue_execution(conn, row["request_id"])
        await audit.append(conn, user, "APPROVAL_APPROVED", rid, {
            "approval_id": str(approval_id), "input": facts, "result": asdict(result), "engine": engine,
            "execution_enabled": settings.execution_enabled, "op_id": str(out.op_id) if out.op_id else None,
        })
        note = f"op {out.op_id}" if out.op_id else "exécuteur désactivé (V1.0) : action à réaliser manuellement"
        await notify.enqueue(conn, "DECISION", f"Action approuvée par {user} : {row['action_id']} sur {row['target']}",
                             note if result.decision == "EXECUTE" else f"Refusée à la réévaluation : {result.reasons}",
                             level=3, incident_id=incident, request_id=rid)
    return out


async def set_kill_switch(pool: asyncpg.Pool, active: bool, user: str, reason: str) -> None:
    """FR-17, UC-05 : effet immédiat (chaque évaluation relit l'état dans sa transaction)."""
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(
            "INSERT INTO obs.kill_switch (active, changed_by, reason) VALUES ($1, $2, $3)", active, user, reason
        )
        cancelled = 0
        if active:
            # Les exécutions non démarrées sont annulées ; celles en cours se terminent
            cancelled = len(await conn.fetch(
                "UPDATE obs.execution SET status = 'CANCELLED' WHERE status = 'QUEUED' RETURNING id"
            ))
        await audit.append(conn, user, "KILL_SWITCH_ON" if active else "KILL_SWITCH_OFF", None,
                           {"reason": reason, "cancelled_executions": cancelled})
        await notify.enqueue(conn, "KILL_SWITCH",
                             f"Kill switch {'ACTIVÉ' if active else 'désactivé'} par {user}", reason, level=3)
