"""Schémas partagés (schéma d'événement versionné, FR-02)."""
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

EVENT_SCHEMA_VERSION = 1


class Level(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class EventIn(BaseModel):
    """Événement tel qu'envoyé par une source. La source n'est jamais lue dans le corps :
    elle découle de la clé d'API (STRIDE, usurpation)."""

    model_config = ConfigDict(extra="forbid")

    equipment: str = Field(min_length=1, max_length=128)
    metric: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    value: float | None = None
    level: Level = Level.INFO
    timestamp: datetime
    correlation_id: UUID | None = None
    message: str | None = Field(default=None, max_length=16_384)  # ligne de log → Loki
    payload: dict[str, Any] = Field(default_factory=dict)


class NormalizedEvent(BaseModel):
    """{source, équipement, métrique/type, valeur, niveau, horodatage, id_corrélation}"""

    time: datetime
    source_id: UUID
    equipment_id: UUID
    equipment_code: str
    metric: str
    value: float | None
    level: Level
    correlation_id: UUID | None
    payload: dict[str, Any]
    message: str | None = None
