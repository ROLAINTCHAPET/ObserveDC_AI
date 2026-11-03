"""Gabarits de règles : classement FIRING / BETWEEN / OK / NO_DATA (M3, M8, M9)."""
import pytest

from detection.engine import RuleConfigError, Rule, severity
from detection.templates import BETWEEN, FIRING, NO_DATA, OK, PARAMS, classify


def params(rule_type, **kw):
    return PARAMS[rule_type].model_validate(kw)


def metric_row(last=None, n=5, **kw):
    return {"equipment_id": "eq", "source_id": None, "n": n, "last": last, "avg": kw.get("avg", last),
            "min": kw.get("min", last), "max": kw.get("max", last), "distinct_values": kw.get("distinct", 2),
            "slope": kw.get("slope")}


@pytest.mark.parametrize("value,expected", [(31, FIRING), (29, BETWEEN), (28, OK), (25, OK)])
def test_threshold_hysteresis_m3(value, expected):
    p = params("THRESHOLD", metric="temperature", op=">", threshold=30, clear_threshold=28)
    assert classify("THRESHOLD", p, metric_row(value), 120, 1).status == expected


def test_threshold_without_clear_has_no_band():
    p = params("THRESHOLD", metric="t", op=">", threshold=30)
    assert classify("THRESHOLD", p, metric_row(30), 60, 1).status == OK


@pytest.mark.parametrize("value,expected", [(15, FIRING), (85, FIRING), (22, BETWEEN), (50, OK)])
def test_threshold_outside_range(value, expected):
    p = params("THRESHOLD", metric="humidity", op="outside", low=20, high=80, clear_low=25, clear_high=75)
    assert classify("THRESHOLD", p, metric_row(value), 300, 1).status == expected


def test_not_enough_points_is_no_data_never_ok_m9():
    p = params("THRESHOLD", metric="t", op=">", threshold=30)
    o = classify("THRESHOLD", p, metric_row(10, n=2), 300, 3)
    assert o.status == NO_DATA


def test_threshold_aggregate_min_means_sustained():
    p = params("THRESHOLD", metric="cpu", op=">", threshold=90, aggregate="min")
    assert classify("THRESHOLD", p, metric_row(99, min=70), 600, 1).status != FIRING


def test_state():
    p = params("STATE", metric="fan_rpm", equals=0)
    assert classify("STATE", p, metric_row(0.0), 60, 1).status == FIRING
    assert classify("STATE", p, metric_row(1200.0), 60, 1).status == OK


def test_rate_ratio_and_count():
    p = params("RATE", threshold=0.05, clear_threshold=0.02)
    row = {"equipment_id": "eq", "source_id": None, "n": 100, "matching": 6}
    assert classify("RATE", p, row, 600, 20).status == FIRING
    assert classify("RATE", p, {**row, "matching": 3}, 600, 20).status == BETWEEN
    assert classify("RATE", p, {**row, "n": 10}, 600, 20).status == NO_DATA
    c = params("RATE", levels=["CRITICAL"], measure="count", threshold=0)
    assert classify("RATE", c, {**row, "matching": 1}, 300, 1).status == FIRING


def test_slope():
    p = params("SLOPE", metric="temperature", rise=5, clear_rise=2)
    assert classify("SLOPE", p, metric_row(30, slope=6 / 600), 600, 5).status == FIRING   # +6 °C / 10 min
    assert classify("SLOPE", p, metric_row(30, slope=3 / 600), 600, 5).status == BETWEEN
    assert classify("SLOPE", p, metric_row(30, slope=0.0), 600, 5).status == OK


def test_frozen():
    p = params("FROZEN", metric="temperature")
    assert classify("FROZEN", p, metric_row(24.0, n=20, distinct=1), 900, 20).status == FIRING
    assert classify("FROZEN", p, metric_row(24.0, n=20, distinct=4), 900, 20).status == OK
    assert classify("FROZEN", p, metric_row(24.0, n=5, distinct=1), 900, 20).status == NO_DATA


def test_silent_source_and_equipment():
    src = classify("SILENT_SOURCE", params("SILENT_SOURCE"),
                   {"equipment_id": None, "source_id": "s", "name": "iot", "silent_s": None}, 120, 1)
    assert src.status == FIRING and "jamais" in src.detail
    eq = params("SILENT_EQUIPMENT", multiplier=3)
    row = {"equipment_id": "e", "source_id": None, "code": "B12", "silent_s": 200.0, "expected_s": 60.0}
    assert classify("SILENT_EQUIPMENT", eq, row, 180, 1).status == FIRING
    assert classify("SILENT_EQUIPMENT", eq, {**row, "silent_s": 100.0}, 180, 1).status == OK


def test_custom_sql_must_return_status():
    p = params("CUSTOM_SQL")
    with pytest.raises(ValueError, match="status"):
        classify("CUSTOM_SQL", p, {"equipment_id": "e", "value": 1}, 60, 1)
    assert classify("CUSTOM_SQL", p, {"source_id": "s", "status": "BETWEEN"}, 60, 1).status == BETWEEN


def test_invalid_params_are_rejected():
    for rule_type, bad in [("THRESHOLD", {"metric": "t", "op": ">"}),                 # pas de seuil
                           ("THRESHOLD", {"metric": "t", "op": "outside", "low": 9, "high": 1}),
                           ("STATE", {"metric": "t", "equals": 0, "typo": 1}),       # champ inconnu
                           ("RATE", {"threshold": 1, "measure": "median"})]:
        row = {"id": 1, "name": "r", "rule_type": rule_type, "version": 1, "params": bad, "query": None,
               "window_s": 60, "check_interval_s": 10, "for_s": 0, "min_data_points": 1, "severity_hint": "LOW",
               "stability_s": 60, "maintenance_mode": "SUPPRESS", "shadow": False}
        with pytest.raises(RuleConfigError):
            Rule.from_row(row)


def test_severity_is_max_of_hint_and_criticality_m8():
    assert severity("MED", "CRITICAL") == "CRITICAL"
    assert severity("HIGH", "LOW") == "HIGH"
    assert severity("MED", None) == "MED"
