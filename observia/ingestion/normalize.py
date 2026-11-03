"""Normalisation en schéma d'événement unique (FR-02, UC-01)."""
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from shared.schemas import EVENT_SCHEMA_VERSION, EventIn, NormalizedEvent

MAX_FUTURE_SKEW = timedelta(minutes=5)
MAX_AGE = timedelta(days=7)


def normalize(
    event: EventIn, source_id: UUID, equipment_id: UUID, now: datetime | None = None
) -> NormalizedEvent:
    now = now or datetime.now(timezone.utc)
    ts = event.timestamp if event.timestamp.tzinfo else event.timestamp.replace(tzinfo=timezone.utc)
    ts = ts.astimezone(timezone.utc)
    meta: dict[str, Any] = {"schema_version": EVENT_SCHEMA_VERSION}
    # UC-01 : horodatage incohérent → l'événement est gardé mais marqué
    if ts - now > MAX_FUTURE_SKEW or now - ts > MAX_AGE:
        meta["ts_suspect"] = True
        meta["received_at"] = now.isoformat()
    return NormalizedEvent(
        time=ts,
        source_id=source_id,
        equipment_id=equipment_id,
        equipment_code=event.equipment,
        metric=event.metric,
        value=event.value,
        level=event.level,
        correlation_id=event.correlation_id,
        payload={**event.payload, "_ingest": meta},
        message=event.message,
    )
