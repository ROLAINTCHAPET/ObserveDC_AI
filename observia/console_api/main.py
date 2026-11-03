"""API de la console d'administration (SAD §13.1) : uvicorn console_api.main:app"""
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from audit import log as audit
from console_api.auth import ANY_READER, User, require
from detection import admin as rules_admin
from guardrail.service import ApprovalError, decide_approval, kill_switch_active, set_kill_switch
from shared.config import get_settings
from shared.db import close_pools, get_pool


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await close_pools()


app = FastAPI(title="ObservIA-DC — console", lifespan=lifespan)


async def pool():
    return await get_pool(get_settings().db_dsn)


def rows(records) -> list[dict[str, Any]]:
    return [dict(r) for r in records]


# --- Incidents et décisions (FR-22) ------------------------------------------

@app.get("/incidents")
async def list_incidents(status: str | None = None, limit: int = Query(50, le=500),
                         _: User = Depends(require(*ANY_READER))):
    return rows(await (await pool()).fetch(
        """
        SELECT i.id, i.opened_at, i.closed_at, i.status, i.severity, i.summary,
               e.code AS equipment, s.name AS source, r.name AS rule
          FROM obs.incident i JOIN obs.detection_rule r ON r.id = i.detection_rule
          LEFT JOIN obs.equipment e ON e.id = i.equipment_id LEFT JOIN obs.source s ON s.id = i.source_id
         WHERE ($1::text IS NULL OR i.status = $1) ORDER BY i.opened_at DESC LIMIT $2
        """, status, limit))


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: UUID, _: User = Depends(require(*ANY_READER))):
    p = await pool()
    incident = await p.fetchrow(
        """
        SELECT i.*, e.code AS equipment, r.name AS rule FROM obs.incident i
          JOIN obs.detection_rule r ON r.id = i.detection_rule LEFT JOIN obs.equipment e ON e.id = i.equipment_id
         WHERE i.id = $1
        """, incident_id)
    if incident is None:
        raise HTTPException(404, "incident introuvable")
    runs = rows(await p.fetch("SELECT * FROM obs.agent_run WHERE incident_id = $1 ORDER BY started_at", incident_id))
    for run in runs:
        run["steps_detail"] = rows(await p.fetch("SELECT seq, tool, args, result_ref, duration_ms FROM obs.agent_step WHERE run_id = $1 ORDER BY seq", run["id"]))
        run["requests"] = rows(await p.fetch(
            "SELECT r.*, a.id AS approval_id, a.status AS approval_status FROM obs.action_request r "
            "LEFT JOIN obs.approval a ON a.request_id = r.id WHERE r.run_id = $1", run["id"]))
    return {"incident": dict(incident), "runs": runs, "audit": f"/audit?ref={incident_id}"}


@app.get("/decisions")
async def decisions(limit: int = Query(50, le=500), _: User = Depends(require(*ANY_READER))):
    return rows(await (await pool()).fetch(
        """
        SELECT r.id, r.decided_at, r.action_id, r.target, r.effective_level, r.decision, r.reasons,
               r.confidence, r.justification, ar.incident_id, i.summary AS incident_summary,
               a.id AS approval_id, a.status AS approval_status
          FROM obs.action_request r JOIN obs.agent_run ar ON ar.id = r.run_id
          JOIN obs.incident i ON i.id = ar.incident_id LEFT JOIN obs.approval a ON a.request_id = r.id
         ORDER BY r.decided_at DESC LIMIT $1
        """, limit))


# --- Validation niveau 3 (FR-15, UC-04) --------------------------------------

@app.get("/approvals")
async def approvals(status: Literal["pending", "all"] = "pending", _: User = Depends(require(*ANY_READER))):
    return rows(await (await pool()).fetch(
        """
        SELECT a.id, a.status, a.requested_at, a.expires_at,
               greatest(0, extract(epoch FROM a.expires_at - now()))::int AS expires_in_s,
               r.id AS request_id, r.action_id, r.target, r.params, r.effective_level, r.reasons,
               r.justification, r.confidence, ar.incident_id, i.summary AS incident_summary
          FROM obs.approval a JOIN obs.action_request r ON r.id = a.request_id
          JOIN obs.agent_run ar ON ar.id = r.run_id JOIN obs.incident i ON i.id = ar.incident_id
         WHERE $1 = 'all' OR a.status = 'PENDING' ORDER BY a.expires_at
        """, status))


class ApprovalDecision(BaseModel):
    decision: Literal["APPROVE", "REJECT"]
    confirm_id: UUID = Field(description="Confirmation explicite : identifiant de la validation")
    comment: str | None = Field(default=None, max_length=1000)


@app.post("/approvals/{approval_id}/decision")
async def approval_decision(approval_id: UUID, body: ApprovalDecision, user: User = Depends(require("admin"))):
    if body.confirm_id != approval_id:
        raise HTTPException(400, "confirmation invalide")
    try:
        d = await decide_approval(await pool(), approval_id, user.name, body.decision == "APPROVE", body.comment)
    except ApprovalError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"decision": d.decision, "effective_level": d.effective_level, "reasons": d.reasons,
            "op_id": str(d.op_id) if d.op_id else None, "execution_enabled": get_settings().execution_enabled}


@app.post("/executions/{execution_id}/rollback")
async def rollback(execution_id: UUID, _: User = Depends(require("admin", "oncall"))):
    raise HTTPException(501, "annulation (FR-19) prévue en V1.1 avec l'exécuteur")


# --- Kill switch (FR-17, UC-05) ----------------------------------------------

class KillSwitchBody(BaseModel):
    active: bool
    reason: str = Field(min_length=3, max_length=500)


@app.get("/killswitch")
async def get_killswitch(_: User = Depends(require(*ANY_READER))):
    p = await pool()
    async with p.acquire() as conn:
        last = await conn.fetchrow("SELECT active, changed_by, changed_at, reason FROM obs.kill_switch ORDER BY id DESC LIMIT 1")
        return {"active": await kill_switch_active(conn), "last_change": dict(last) if last else None}


@app.post("/killswitch")
async def post_killswitch(body: KillSwitchBody, user: User = Depends(require("admin", "oncall"))):
    await set_kill_switch(await pool(), body.active, user.name, body.reason)
    return {"active": body.active}


# --- Niveaux d'autonomie (BR-09) et mode ombre (FR-18, UC-07) -----------------

SHADOW_REPORT_SQL = """
SELECT r.action_id, r.effective_level, count(*) AS proposals, count(c.match) AS compared,
       count(*) FILTER (WHERE c.match) AS matches,
       CASE WHEN count(c.match) > 0 THEN (count(*) FILTER (WHERE c.match))::float8 / count(c.match) END AS concordance
  FROM obs.shadow_comparison c JOIN obs.action_request r ON r.id = c.request_id
 WHERE r.decided_at > now() - make_interval(days => $1)
 GROUP BY r.action_id, r.effective_level ORDER BY r.effective_level, r.action_id
"""


async def level_concordance(p, level: int, days: int) -> tuple[float | None, int]:
    row = await p.fetchrow(
        """
        SELECT count(c.match) AS n, (count(*) FILTER (WHERE c.match))::float8 / nullif(count(c.match), 0) AS score
          FROM obs.shadow_comparison c JOIN obs.action_request r ON r.id = c.request_id
         WHERE r.effective_level = $1 AND r.decided_at > now() - make_interval(days => $2)
        """, level, days)
    return row["score"], row["n"]


@app.get("/shadow/report")
async def shadow_report(_: User = Depends(require(*ANY_READER, "auditor"))):
    s = get_settings()
    p = await pool()
    levels = {}
    for level in (1, 2):
        score, n = await level_concordance(p, level, s.shadow_window_days)
        levels[level] = {"concordance": score, "compared": n,
                         "eligible": score is not None and n >= s.shadow_min_samples and score >= s.shadow_open_threshold}
    return {"window_days": s.shadow_window_days, "threshold": s.shadow_open_threshold,
            "by_action": rows(await p.fetch(SHADOW_REPORT_SQL, s.shadow_window_days)), "by_level": levels}


class HumanAction(BaseModel):
    action_id: str = Field(max_length=64, description="« none » si l'humain n'a rien fait")
    target: str | None = Field(default=None, max_length=128)
    params: dict[str, Any] = Field(default_factory=dict)


@app.post("/shadow/{request_id}/human-action")
async def record_human_action(request_id: UUID, body: HumanAction, user: User = Depends(require("admin", "oncall"))):
    p = await pool()
    async with p.acquire() as conn, conn.transaction():
        agent = await conn.fetchval("SELECT agent_action FROM obs.shadow_comparison WHERE request_id = $1 FOR UPDATE", request_id)
        if agent is None:
            raise HTTPException(404, "proposition du mode ombre introuvable")
        match = agent["action_id"] == body.action_id and agent["target"] == body.target
        await conn.execute(
            "UPDATE obs.shadow_comparison SET human_action = $2, match = $3, noted_at = now(), noted_by = $4 WHERE request_id = $1",
            request_id, body.model_dump(), match, user.name)
        await audit.append(conn, user.name, "SHADOW_HUMAN_ACTION", str(request_id), {"human": body.model_dump(), "match": match})
    return {"match": match}


@app.get("/autonomy/levels")
async def autonomy_levels(_: User = Depends(require(*ANY_READER))):
    return rows(await (await pool()).fetch("SELECT * FROM obs.autonomy_state ORDER BY level"))


@app.get("/autonomy/levels/{level}")
async def autonomy_level(level: int, _: User = Depends(require(*ANY_READER))):
    row = await (await pool()).fetchrow("SELECT * FROM obs.autonomy_state WHERE level = $1", level)
    if row is None:
        raise HTTPException(404, "niveau inconnu")
    return dict(row)


class LevelBody(BaseModel):
    enabled: bool


@app.put("/autonomy/levels/{level}")
async def set_autonomy_level(level: int, body: LevelBody, user: User = Depends(require("ops_manager"))):
    s = get_settings()
    p = await pool()
    score, n = await level_concordance(p, level, s.shadow_window_days) if level in (1, 2) else (None, 0)
    if body.enabled:
        if level == 3:
            raise HTTPException(409, "le niveau 3 n'est jamais autonome (BR-02)")
        if not s.execution_enabled:
            raise HTTPException(409, "exécuteur désactivé : ouverture possible à partir de la V1.1")
        if score is None or n < s.shadow_min_samples or score < s.shadow_open_threshold:
            raise HTTPException(409, f"mode ombre non concluant : concordance {score} sur {n} cas "
                                     f"(requis ≥ {s.shadow_open_threshold} sur ≥ {s.shadow_min_samples}, BR-09)")
        if level == 2 and not await p.fetchval("SELECT enabled FROM obs.autonomy_state WHERE level = 1"):
            raise HTTPException(409, "ouverture progressive : le niveau 1 doit être ouvert avant le niveau 2")
    async with p.acquire() as conn, conn.transaction():
        await conn.execute(
            "UPDATE obs.autonomy_state SET enabled = $2, opened_by = $3, opened_at = now(), shadow_score = $4 WHERE level = $1",
            level, body.enabled, user.name, score)
        await audit.append(conn, user.name, "AUTONOMY_LEVEL_CHANGED", f"level:{level}",
                           {"enabled": body.enabled, "shadow_score": score, "samples": n})
    return {"level": level, "enabled": body.enabled, "shadow_score": score}


# --- Pré-détection : règles (M13, M15) et maintenance (M6) --------------------

RULE_MANAGERS = ("admin", "ops_manager")  # RACI : évolution des règles (responsable d'exploitation)


def _rule_error(exc: rules_admin.RuleError) -> HTTPException:
    return HTTPException(exc.status, str(exc))


@app.get("/rules")
async def list_rules(include_archived: bool = False, _: User = Depends(require(*ANY_READER))):
    return rows(await (await pool()).fetch(
        """
        SELECT r.id, r.name, r.rule_type, r.version, r.params, r.query, r.window_s, r.check_interval_s, r.for_s,
               r.min_data_points, r.severity_hint, r.stability_s, r.maintenance_mode, r.shadow, r.shadow_since,
               r.enabled, r.description, r.archived_at, r.archived_by, s.status, s.last_eval_at, s.duration_ms, s.last_error,
               s.consecutive_failures, s.firing_keys, s.no_data_keys, s.shadow_hits,
               (SELECT count(*) FROM obs.incident i WHERE i.detection_rule = r.id AND i.status <> 'RESOLVED') AS open_incidents
          FROM obs.detection_rule r LEFT JOIN obs.rule_status s ON s.rule_id = r.id
         WHERE r.rule_type <> 'SYSTEM' AND ($1 OR r.archived_at IS NULL) ORDER BY r.name
        """, include_archived))


@app.get("/rules/types")
async def list_rule_types(_: User = Depends(require(*ANY_READER))):
    """Types de règles et schéma de leurs paramètres (formulaires de la console)."""
    return rules_admin.rule_types()


@app.post("/rules/preview")
async def preview_rule(body: rules_admin.RuleDefinition, _: User = Depends(require(*RULE_MANAGERS))):
    """Ce que la règle détecterait maintenant, sans rien enregistrer ni créer."""
    try:
        return await rules_admin.preview(body, get_settings())
    except rules_admin.RuleError as exc:
        raise _rule_error(exc) from exc


@app.post("/rules", status_code=201)
async def create_rule(body: rules_admin.RuleCreate, user: User = Depends(require(*RULE_MANAGERS))):
    try:
        return await rules_admin.create_rule(await pool(), body, user.name, get_settings())
    except rules_admin.RuleError as exc:
        raise _rule_error(exc) from exc


@app.get("/rules/{name}")
async def get_rule(name: str, _: User = Depends(require(*ANY_READER))):
    try:
        rule = dict(await rules_admin.get_rule(await pool(), name))
    except rules_admin.RuleError as exc:
        raise _rule_error(exc) from exc
    status = await (await pool()).fetchrow("SELECT * FROM obs.rule_status WHERE rule_id = $1", rule["id"])
    return {"rule": rule, "status": dict(status) if status else None, "history": f"/rules/{name}/history"}


@app.patch("/rules/{name}")
async def update_rule(name: str, body: rules_admin.RulePatch, user: User = Depends(require(*RULE_MANAGERS))):
    try:
        return await rules_admin.update_rule(await pool(), name, body, user.name, get_settings())
    except rules_admin.RuleError as exc:
        raise _rule_error(exc) from exc


@app.delete("/rules/{name}")
async def delete_rule(name: str, close_incidents: bool = False, user: User = Depends(require(*RULE_MANAGERS))):
    """Archive la règle (jamais d'effacement : incidents et audit la référencent)."""
    try:
        return await rules_admin.archive_rule(await pool(), name, user.name, close_incidents)
    except rules_admin.RuleError as exc:
        raise _rule_error(exc) from exc


@app.post("/rules/{name}/restore")
async def restore_rule(name: str, user: User = Depends(require(*RULE_MANAGERS))):
    try:
        return await rules_admin.restore_rule(await pool(), name, user.name)
    except rules_admin.RuleError as exc:
        raise _rule_error(exc) from exc


@app.get("/rules/{name}/shadow")
async def rule_shadow_report(name: str, _: User = Depends(require(*ANY_READER))):
    """Rapport de calibration (M14) : ce que la règle aurait détecté en ombre."""
    try:
        return await rules_admin.shadow_report(await pool(), name, get_settings())
    except rules_admin.RuleError as exc:
        raise _rule_error(exc) from exc


@app.post("/rules/{name}/promote")
async def promote_rule(name: str, body: rules_admin.RulePromote, user: User = Depends(require(*RULE_MANAGERS))):
    """Passe une règle d'ombre en service : elle crée désormais des incidents."""
    try:
        return await rules_admin.promote_rule(await pool(), name, body, user.name, get_settings())
    except rules_admin.RuleError as exc:
        raise _rule_error(exc) from exc


@app.get("/rules/{name}/history")
async def rule_history(name: str, _: User = Depends(require(*ANY_READER, "auditor"))):
    return rows(await (await pool()).fetch(
        "SELECT h.version, h.changed_at, h.changed_by, h.definition FROM obs.detection_rule_history h "
        "JOIN obs.detection_rule r ON r.id = h.rule_id WHERE r.name = $1 ORDER BY h.version DESC", name))


class MaintenanceBody(BaseModel):
    equipment: str = Field(max_length=128, description="Code de l'équipement")
    starts_at: datetime
    ends_at: datetime
    reason: str = Field(min_length=3, max_length=500)


@app.get("/maintenance")
async def list_maintenance(include_past: bool = False, _: User = Depends(require(*ANY_READER))):
    return rows(await (await pool()).fetch(
        "SELECT m.id, e.code AS equipment, m.starts_at, m.ends_at, m.reason, m.created_by, m.created_at "
        "FROM obs.maintenance_window m JOIN obs.equipment e ON e.id = m.equipment_id "
        "WHERE $1 OR m.ends_at > now() ORDER BY m.starts_at", include_past))


@app.post("/maintenance", status_code=201)
async def create_maintenance(body: MaintenanceBody, user: User = Depends(require("admin", "oncall"))):
    if body.ends_at <= body.starts_at:
        raise HTTPException(400, "la fin doit suivre le début")
    if body.ends_at - body.starts_at > timedelta(days=7):
        raise HTTPException(400, "fenêtre limitée à 7 jours : une maintenance oubliée masquerait des alertes")
    p = await pool()
    async with p.acquire() as conn, conn.transaction():
        eq = await conn.fetchval("SELECT id FROM obs.equipment WHERE code = $1", body.equipment)
        if eq is None:
            raise HTTPException(404, "équipement inconnu")
        mid = await conn.fetchval(
            "INSERT INTO obs.maintenance_window (equipment_id, starts_at, ends_at, reason, created_by) "
            "VALUES ($1, $2, $3, $4, $5) RETURNING id", eq, body.starts_at, body.ends_at, body.reason, user.name)
        await audit.append(conn, user.name, "MAINTENANCE_DECLARED", body.equipment, {
            "id": str(mid), "starts_at": body.starts_at, "ends_at": body.ends_at, "reason": body.reason})
    return {"id": mid}


@app.post("/maintenance/{maintenance_id}/end")
async def end_maintenance(maintenance_id: UUID, user: User = Depends(require("admin", "oncall"))):
    p = await pool()
    async with p.acquire() as conn, conn.transaction():
        ended = await conn.fetchval(
            "UPDATE obs.maintenance_window SET ends_at = greatest(starts_at + interval '1 second', now()) "
            "WHERE id = $1 AND ends_at > now() RETURNING id", maintenance_id)
        if ended is None:
            raise HTTPException(404, "maintenance introuvable ou déjà terminée")
        await audit.append(conn, user.name, "MAINTENANCE_ENDED", str(maintenance_id), {})
    return {"ended": True}


# --- Audit (FR-21) -----------------------------------------------------------

@app.get("/audit")
async def get_audit(ref: str | None = None, limit: int = Query(200, le=2000),
                    _: User = Depends(require("auditor", "admin"))):
    p = await pool()
    async with p.acquire() as conn:
        entries = rows(await conn.fetch(
            "SELECT id, ts, actor, event_type, ref, payload, hash FROM obs.audit_log "
            "WHERE $1::text IS NULL OR ref = $1 OR payload->>'incident_id' = $1 ORDER BY id DESC LIMIT $2",
            ref, limit))
        report = await audit.verify_chain(conn)
    return {"chain": {"valid": report.valid, "checked": report.checked, "first_broken_id": report.first_broken_id},
            "entries": entries}


@app.get("/healthz")
async def healthz():
    await (await pool()).fetchval("SELECT 1")
    return {"status": "ok"}
