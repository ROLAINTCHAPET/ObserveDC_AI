"""API d'ingestion (FR-01 à FR-04, UC-01) : uvicorn ingestion.main:app"""
import hashlib
import logging
import time
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

import httpx
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from pydantic import ValidationError

from audit import log as audit
from ingestion.adapters import telegraf
from ingestion.normalize import normalize
from shared import notify
from shared.config import get_settings
from shared.db import close_pools, get_pool
from shared.schemas import EventIn, NormalizedEvent

log = logging.getLogger("ingestion")
MAX_BATCH = 5000
CACHE_TTL_S = 30.0
REJECT_AUDIT_INTERVAL_S = 60.0
QUARANTINE_ALERT_INTERVAL_S = 600.0


class _Cache:
    """Sources et équipements en mémoire : l'ingestion ne fait pas une requête par événement."""

    def __init__(self) -> None:
        self.loaded_at = 0.0
        self.sources: dict[str, dict[str, Any]] = {}  # sha256(clé) → source
        self.equipment: dict[str, UUID] = {}  # code → id

    async def refresh(self, pool, force: bool = False) -> None:
        if not force and time.monotonic() - self.loaded_at < CACHE_TTL_S:
            return
        rows = await pool.fetch("SELECT id, name, kind, auth_ref FROM obs.source WHERE status = 'ACTIVE'")
        self.sources = {r["auth_ref"]: dict(r) for r in rows}
        rows = await pool.fetch("SELECT id, code FROM obs.equipment")
        self.equipment = {r["code"]: r["id"] for r in rows}
        self.loaded_at = time.monotonic()


cache = _Cache()
_last_reject_audit: dict[str, float] = {}
_last_quarantine_alert: dict[UUID, float] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http = httpx.AsyncClient(timeout=5.0)
    yield
    await app.state.http.aclose()
    await close_pools()


app = FastAPI(title="ObservIA-DC — ingestion", lifespan=lifespan)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


async def authenticated_source(request: Request, x_source_key: str | None = Header(default=None)) -> dict[str, Any]:
    """FR-03 : source identifiée par clé d'API ; source inconnue rejetée et journalisée.
    (mTLS : terminé par le proxy TLS en frontal, qui transmet alors la clé de la source.)"""
    pool = await get_pool(get_settings().ingest_dsn)
    await cache.refresh(pool)
    source = cache.sources.get(hash_key(x_source_key)) if x_source_key else None
    if source is None:
        await cache.refresh(pool, force=True)
        source = cache.sources.get(hash_key(x_source_key)) if x_source_key else None
    if source is None:
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        # Journalisé, mais limité par adresse pour qu'un flot de rejets ne sature pas l'audit
        if now - _last_reject_audit.get(client, 0.0) > REJECT_AUDIT_INTERVAL_S:
            _last_reject_audit[client] = now
            async with pool.acquire() as conn, conn.transaction():
                await audit.append(conn, "ingestion", "SOURCE_REJECTED", None,
                                   {"client": client, "key_present": bool(x_source_key)})
        raise HTTPException(status_code=401, detail="source inconnue")
    return source


async def _push_logs(http: httpx.AsyncClient, source: dict[str, Any], events: list[NormalizedEvent]) -> None:
    url = get_settings().loki_url
    lines = [e for e in events if e.message]
    if not url or not lines:
        return
    streams: dict[tuple[str, str], list[list[str]]] = {}
    for e in lines:
        key = (e.equipment_code, e.level.value)
        streams.setdefault(key, []).append([str(int(e.time.timestamp() * 1e9)), e.message or ""])
    body = {"streams": [
        {"stream": {"equipment": eq, "level": lvl, "source": source["name"]}, "values": vals}
        for (eq, lvl), vals in streams.items()
    ]}
    try:
        resp = await http.post(f"{url}/loki/api/v1/push", json=body)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        # Les métadonnées de l'événement restent stockées dans TimescaleDB
        log.warning("envoi vers Loki impossible : %s", exc)


def _stored_payload(e: NormalizedEvent, keep_message: bool) -> dict[str, Any]:
    # Sans Loki (pilote, profil réduit), la ligne de log reste dans l'événement pour get_logs
    return {**e.payload, "message": e.message} if keep_message and e.message else e.payload


async def ingest(request: Request, source: dict[str, Any], items: list[Any]) -> dict[str, int]:
    if len(items) > MAX_BATCH:
        raise HTTPException(status_code=413, detail=f"lot limité à {MAX_BATCH} événements")
    pool = await get_pool(get_settings().ingest_dsn)
    accepted: list[NormalizedEvent] = []
    quarantined: list[tuple[str, Any]] = []
    for raw in items:
        try:
            event = EventIn.model_validate(raw)
        except ValidationError as exc:
            quarantined.append((f"SCHEMA: {exc.errors(include_url=False)[0]['msg']}", raw))
            continue
        equipment_id = cache.equipment.get(event.equipment)
        if equipment_id is None:
            quarantined.append(("UNKNOWN_EQUIPMENT", raw))
            continue
        accepted.append(normalize(event, source["id"], equipment_id))

    keep_message = not get_settings().loki_url
    async with pool.acquire() as conn, conn.transaction():
        if accepted:
            await conn.copy_records_to_table(
                "event", schema_name="obs",
                columns=["time", "source_id", "equipment_id", "metric", "value", "level", "payload", "correlation_id"],
                records=[(e.time, e.source_id, e.equipment_id, e.metric, e.value, e.level.value,
                          _stored_payload(e, keep_message), e.correlation_id) for e in accepted],
            )
        if quarantined:
            await conn.executemany(
                "INSERT INTO obs.quarantine (source_id, reason, raw) VALUES ($1, $2, $3)",
                [(source["id"], reason, raw if isinstance(raw, dict) else {"value": raw})
                 for reason, raw in quarantined],
            )
            now = time.monotonic()
            if now - _last_quarantine_alert.get(source["id"], 0.0) > QUARANTINE_ALERT_INTERVAL_S:
                _last_quarantine_alert[source["id"]] = now
                await notify.enqueue(
                    conn, "INGESTION", f"Événements en quarantaine — source {source['name']}",
                    f"{len(quarantined)} événement(s) rejeté(s), premier motif : {quarantined[0][0]}",
                )
    await _push_logs(request.app.state.http, source, accepted)
    return {"accepted": len(accepted), "quarantined": len(quarantined)}


@app.post("/ingest/events")
async def ingest_events(
    request: Request,
    body: dict[str, Any] | list[Any] = Body(...),
    source: dict[str, Any] = Depends(authenticated_source),
) -> dict[str, int]:
    items = body if isinstance(body, list) else body.get("events", [body])
    return await ingest(request, source, items)


@app.post("/ingest/telegraf")
async def ingest_telegraf(
    request: Request,
    body: dict[str, Any] = Body(...),
    source: dict[str, Any] = Depends(authenticated_source),
) -> dict[str, int]:
    return await ingest(request, source, telegraf.to_events(body))


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    await (await get_pool(get_settings().ingest_dsn)).fetchval("SELECT 1")
    return {"status": "ok"}
