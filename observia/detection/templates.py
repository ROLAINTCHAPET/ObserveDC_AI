"""Gabarits de règles de pré-détection (document « Règles de pré-détection V1.0 », §3).

Chaque type fournit :
  - un modèle de paramètres validé (une règle mal paramétrée échoue bruyamment, M10) ;
  - une requête SQL figée, dont toutes les valeurs sont des paramètres liés ;
  - une fonction de classement pure : FIRING, BETWEEN (bande d'hystérésis), OK ou NO_DATA.

L'hystérésis (M3) et « donnée absente ≠ normal » (M9) sont donc traités une seule fois ici,
pour toutes les règles, au lieu d'être réécrits dans chaque requête.
"""
import math
import operator
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

FIRING, BETWEEN, OK, NO_DATA = "FIRING", "BETWEEN", "OK", "NO_DATA"
STATUSES = {FIRING, BETWEEN, OK, NO_DATA}
NEVER_SEEN_S = 1e9  # source ou équipement sans aucune donnée : silence « infini »

_OPS = {">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le}


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid")
    equipment_types: list[str] | None = None  # périmètre (scope), tous si absent


class ThresholdParams(_Params):
    metric: str
    op: Literal[">", ">=", "<", "<=", "outside"]
    threshold: float | None = None
    clear_threshold: float | None = None  # M3 : défaut = seuil d'alerte (pas d'hystérésis)
    low: float | None = None  # op = outside : alerte hors de [low, high]
    high: float | None = None
    clear_low: float | None = None  # retour à la normale dans [clear_low, clear_high]
    clear_high: float | None = None
    aggregate: Literal["last", "avg", "min", "max"] = "last"

    @model_validator(mode="after")
    def _check(self) -> "ThresholdParams":
        if self.op == "outside":
            if self.low is None or self.high is None or self.low >= self.high:
                raise ValueError("op outside : low < high requis")
        elif self.threshold is None:
            raise ValueError("threshold requis")
        return self


class StateParams(_Params):
    metric: str
    equals: float  # ex. ventilateur = 0, fuite = 1


class RateParams(_Params):
    metric: str = "log"
    levels: list[str] = Field(default_factory=lambda: ["ERROR", "CRITICAL"])
    measure: Literal["ratio", "count"] = "ratio"
    threshold: float
    clear_threshold: float | None = None


class SlopeParams(_Params):
    metric: str
    rise: float  # hausse sur la fenêtre (ex. 5 °C en 10 min) ; négatif = baisse
    clear_rise: float | None = None


class FrozenParams(_Params):
    metric: str  # métrique normalement variable ; min_data_points = nombre de relevés identiques


class SilentSourceParams(_Params):
    pass


class SilentEquipmentParams(_Params):
    default_interval_s: int = 60  # si equipment.expected_interval_s est vide
    multiplier: float = 3.0  # muet depuis 3 intervalles attendus (S2)
    lookback_s: int = 86_400  # « qui émettait » : vu au moins une fois sur cette période


class CustomParams(_Params):
    pass


PARAMS: dict[str, type[_Params]] = {
    "THRESHOLD": ThresholdParams, "STATE": StateParams, "RATE": RateParams, "SLOPE": SlopeParams,
    "FROZEN": FrozenParams, "SILENT_SOURCE": SilentSourceParams, "SILENT_EQUIPMENT": SilentEquipmentParams,
    "CUSTOM_SQL": CustomParams,
}


@dataclass
class Observation:
    """État d'une clé (équipement ou source) lors d'une évaluation."""

    equipment_id: Any
    source_id: Any
    status: str
    value: float | None
    detail: str
    observed: dict[str, Any] = field(default_factory=dict)

    @property
    def subject(self) -> Any:
        return self.equipment_id or self.source_id


# --- Requêtes --------------------------------------------------------------------

_METRIC_SQL = """
SELECT e.equipment_id, NULL::uuid AS source_id, count(*) AS n,
       (array_agg(e.value ORDER BY e.time DESC))[1] AS last,
       avg(e.value) AS avg, min(e.value) AS min, max(e.value) AS max,
       count(DISTINCT e.value) AS distinct_values,
       regr_slope(e.value, extract(epoch FROM e.time)) AS slope
  FROM obs.event e JOIN obs.equipment q ON q.id = e.equipment_id
 WHERE e.metric = $1 AND e.value IS NOT NULL
   AND e.time > now() - make_interval(secs => $2)
   AND ($3::text[] IS NULL OR q.type = ANY($3))
 GROUP BY e.equipment_id
"""

_RATE_SQL = """
SELECT e.equipment_id, NULL::uuid AS source_id, count(*) AS n,
       count(*) FILTER (WHERE e.level = ANY($4::text[])) AS matching
  FROM obs.event e JOIN obs.equipment q ON q.id = e.equipment_id
 WHERE e.metric = $1 AND e.time > now() - make_interval(secs => $2)
   AND ($3::text[] IS NULL OR q.type = ANY($3))
 GROUP BY e.equipment_id
"""

_SILENT_SOURCE_SQL = """
SELECT NULL::uuid AS equipment_id, s.id AS source_id, s.name, 1 AS n,
       extract(epoch FROM now() - last.t)::float8 AS silent_s
  FROM obs.source s
  LEFT JOIN LATERAL (SELECT max(e.time) AS t FROM obs.event e
                      WHERE e.source_id = s.id AND e.time > now() - interval '7 days') last ON TRUE
 WHERE s.status = 'ACTIVE'
"""

_SILENT_EQUIPMENT_SQL = """
SELECT q.id AS equipment_id, NULL::uuid AS source_id, q.code, 1 AS n,
       extract(epoch FROM now() - last.t)::float8 AS silent_s,
       coalesce(q.expected_interval_s, $1)::float8 AS expected_s
  FROM obs.equipment q
  LEFT JOIN LATERAL (SELECT max(e.time) AS t FROM obs.event e
                      WHERE e.equipment_id = q.id AND e.time > now() - make_interval(secs => $2)) last ON TRUE
 WHERE (last.t IS NOT NULL OR q.expected_interval_s IS NOT NULL)
   AND ($3::text[] IS NULL OR q.type = ANY($3))
"""


def build_query(rule_type: str, params: _Params, window_s: int, custom_query: str | None) -> tuple[str, list[Any]]:
    types = params.equipment_types
    if rule_type in ("THRESHOLD", "STATE", "SLOPE", "FROZEN"):
        return _METRIC_SQL, [params.metric, float(window_s), types]
    if rule_type == "RATE":
        return _RATE_SQL, [params.metric, float(window_s), types, params.levels]
    if rule_type == "SILENT_SOURCE":
        return _SILENT_SOURCE_SQL, []
    if rule_type == "SILENT_EQUIPMENT":
        return _SILENT_EQUIPMENT_SQL, [params.default_interval_s, float(params.lookback_s), types]
    if rule_type == "CUSTOM_SQL":
        return custom_query or "", [float(window_s)]
    raise ValueError(f"type de règle non évaluable : {rule_type}")


# --- Classement ------------------------------------------------------------------

def classify(rule_type: str, p: _Params, row: dict[str, Any], window_s: int, min_points: int) -> Observation:
    eq, src = row.get("equipment_id"), row.get("source_id")
    n = int(row.get("n") or 0)

    if rule_type == "CUSTOM_SQL":
        status = row.get("status")
        if status not in STATUSES:
            raise ValueError("une règle CUSTOM_SQL doit renvoyer une colonne status (FIRING, BETWEEN, OK, NO_DATA)")
        return Observation(eq, src, status, row.get("value"), row.get("detail") or "", {"n": n})

    if rule_type == "SILENT_SOURCE":
        silent = row["silent_s"] if row["silent_s"] is not None else NEVER_SEEN_S
        status = FIRING if silent > window_s else OK
        return Observation(eq, src, status, silent, f"aucune donnée de la source {row['name']} depuis {_human(silent)}",
                           {"silent_s": silent, "limit_s": window_s})

    if rule_type == "SILENT_EQUIPMENT":
        silent = row["silent_s"] if row["silent_s"] is not None else NEVER_SEEN_S
        limit = row["expected_s"] * p.multiplier
        status = FIRING if silent > limit else OK
        return Observation(eq, src, status, silent, f"{row['code']} muet depuis {_human(silent)} (attendu toutes les {row['expected_s']:.0f} s)",
                           {"silent_s": silent, "limit_s": limit})

    # M9 : pas assez de relevés sur la fenêtre → NO_DATA, jamais « OK »
    if n < min_points:
        return Observation(eq, src, NO_DATA, None, f"{n} relevé(s) sur {window_s} s, {min_points} requis", {"n": n})

    if rule_type == "THRESHOLD":
        v = row[p.aggregate]
        observed = {"n": n, "value": v, "aggregate": p.aggregate}
        if p.op == "outside":
            firing = v < p.low or v > p.high
            cl = p.clear_low if p.clear_low is not None else p.low
            ch = p.clear_high if p.clear_high is not None else p.high
            clear = cl <= v <= ch
            detail = f"{p.metric} = {v:g} (plage normale {p.low:g} à {p.high:g})"
        else:
            cmp = _OPS[p.op]
            clear_at = p.clear_threshold if p.clear_threshold is not None else p.threshold
            firing, clear = cmp(v, p.threshold), not cmp(v, clear_at)
            detail = f"{p.metric} = {v:g} ({p.aggregate}), seuil {p.op} {p.threshold:g}"
        return Observation(eq, src, _status(firing, clear), v, detail, observed)

    if rule_type == "STATE":
        v = row["last"]
        firing = math.isclose(v, p.equals)
        return Observation(eq, src, FIRING if firing else OK, v, f"{p.metric} = {v:g}", {"n": n, "value": v})

    if rule_type == "RATE":
        matching = int(row["matching"])
        v = matching / n if p.measure == "ratio" else float(matching)
        clear_at = p.clear_threshold if p.clear_threshold is not None else p.threshold
        label = f"{100 * v:.1f} %" if p.measure == "ratio" else f"{matching}"
        return Observation(eq, src, _status(v > p.threshold, v <= clear_at), v,
                           f"{label} de {'/'.join(p.levels)} sur {n} lignes en {window_s} s",
                           {"n": n, "matching": matching, "value": v})

    if rule_type == "SLOPE":
        rise = (row["slope"] or 0.0) * window_s
        clear_at = p.clear_rise if p.clear_rise is not None else p.rise
        firing = rise > p.rise if p.rise >= 0 else rise < p.rise
        clear = rise <= clear_at if p.rise >= 0 else rise >= clear_at
        return Observation(eq, src, _status(firing, clear), rise,
                           f"{p.metric} : variation {rise:+.1f} sur {window_s} s (seuil {p.rise:+g})",
                           {"n": n, "rise": rise, "slope_per_s": row["slope"]})

    if rule_type == "FROZEN":
        frozen = int(row["distinct_values"]) == 1
        return Observation(eq, src, FIRING if frozen else OK, row["last"],
                           f"{p.metric} figé à {row['last']:g} sur {n} relevés", {"n": n, "distinct": row["distinct_values"]})

    raise ValueError(f"type inconnu : {rule_type}")


def _status(firing: bool, clear: bool) -> str:
    if firing:
        return FIRING
    return OK if clear else BETWEEN


def _human(seconds: float) -> str:
    if seconds >= NEVER_SEEN_S:
        return "toujours (jamais reçue)"
    if seconds >= 3600:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 60:.1f} min" if seconds >= 120 else f"{seconds:.0f} s"
