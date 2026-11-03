"""Politique du garde-fou : mêmes cas pour le moteur local et pour OPA (parité).

OPA est testé si OBSERVIA_TEST_OPA_URL pointe vers un serveur chargé avec policies/.
"""
import copy
import os

import pytest

from guardrail.catalog import load_catalog
from guardrail.policy import LocalPolicy, OpaPolicy
from shared.config import get_settings

BASE = {
    "action_id": "restart_service",
    "params_valid": True,
    "confidence": 0.9,
    "human_approval": False,
    "target": {"known": True, "kind": "equipment", "type": "server", "criticality": "LOW", "env": "TEST", "impacted_count": 1},
    "state": {"kill_switch": False, "shadow_mode": False, "open_levels": [1, 2], "quota_exceeded": False, "lock_held": False},
    "limits": {"max_impacted_equipment": 3, "min_confidence": 0.5},
}


def case(**changes):
    inp = copy.deepcopy(BASE)
    for path, value in changes.items():
        node = inp
        *parents, leaf = path.split("__")
        for p in parents:
            node = node[p]
        if value is _DELETE:
            node.pop(leaf, None)
        else:
            node[leaf] = value
    return inp


_DELETE = object()

# (nom, entrée, décision attendue, niveau attendu)
CASES = [
    ("nominal N2 exécuté", case(), "EXECUTE", 2),
    ("action hors catalogue", case(action_id="rm_rf"), "REFUSED", 3),
    ("paramètres invalides", case(params_valid=False), "REFUSED", 2),
    ("type de cible interdit", case(target__type="rack"), "REFUSED", 2),
    ("cible inconnue", case(target__known=False), "REFUSED", 2),
    ("BR-12 critique en prod", case(target__criticality="CRITICAL", target__env="PROD"), "PENDING_APPROVAL", 3),
    ("BR-12 critique en test", case(target__criticality="CRITICAL"), "EXECUTE", 2),
    ("BR-12 N1 non intrusif", case(action_id="open_ticket", target__criticality="CRITICAL", target__env="PROD"), "EXECUTE", 1),
    ("BR-06 périmètre", case(target__impacted_count=4), "PENDING_APPROVAL", 3),
    ("BR-06 zone entière", case(action_id="adjust_cooling", target__kind="zone", target__type="zone"), "PENDING_APPROVAL", 3),
    ("confiance basse", case(confidence=0.2), "PENDING_APPROVAL", 3),
    ("confiance absente", case(confidence=_DELETE), "PENDING_APPROVAL", 3),
    ("confiance nulle", case(confidence=None), "PENDING_APPROVAL", 3),
    ("BR-07 kill switch", case(state__kill_switch=True), "PENDING_APPROVAL", 2),
    ("BR-09 niveau fermé", case(state__open_levels=[1]), "PENDING_APPROVAL", 2),
    ("BR-05 quota", case(state__quota_exceeded=True), "PENDING_APPROVAL", 2),
    ("BR-05 verrou", case(state__lock_held=True), "PENDING_APPROVAL", 2),
    ("état incomplet", case(state={}), "PENDING_APPROVAL", 2),
    ("mode ombre", case(state__shadow_mode=True, state__open_levels=[]), "SHADOW", 2),
    ("mode ombre N3", case(action_id="power_cut_rack", target__type="rack", state__shadow_mode=True), "PENDING_APPROVAL", 3),
    ("BR-02 N3 validé", case(action_id="power_cut_rack", target__type="rack", human_approval=True), "EXECUTE", 3),
    ("validation + kill switch", case(action_id="power_cut_rack", target__type="rack", human_approval=True,
                                       state__kill_switch=True), "EXECUTE", 3),
    ("validation + verrou", case(action_id="power_cut_rack", target__type="rack", human_approval=True,
                                  state__lock_held=True), "PENDING_APPROVAL", 3),
    ("validation hors catalogue", case(action_id="rm_rf", human_approval=True), "REFUSED", 3),
]

IDS = [c[0] for c in CASES]


@pytest.fixture(scope="module")
def local():
    return LocalPolicy(load_catalog(get_settings().catalog_path))


@pytest.mark.parametrize("name,inp,decision,level", CASES, ids=IDS)
async def test_local_policy(local, name, inp, decision, level):
    result = await local.evaluate(inp)
    assert (result.decision, result.effective_level) == (decision, level), result.reasons


OPA_URL = os.environ.get("OBSERVIA_TEST_OPA_URL")


@pytest.mark.skipif(not OPA_URL, reason="OBSERVIA_TEST_OPA_URL non défini")
@pytest.mark.parametrize("name,inp,decision,level", CASES, ids=IDS)
async def test_opa_parity(local, name, inp, decision, level):
    opa = await OpaPolicy(OPA_URL, 2.0).evaluate(inp)
    loc = await local.evaluate(inp)
    assert (opa.decision, opa.effective_level, opa.reasons) == (loc.decision, loc.effective_level, loc.reasons)
    assert (opa.decision, opa.effective_level) == (decision, level)


def test_catalog_levels_match_spec():
    catalog = load_catalog(get_settings().catalog_path)
    assert catalog["open_ticket"].base_level == 1
    assert catalog["restart_service"].base_level == 2
    assert catalog["migrate_workload"].rollback_ref == "migrate_workload_back"
    assert {"power_cut_rack", "site_failover"} <= {a for a, s in catalog.items() if s.base_level == 3}
    for action in catalog.values():
        if action.rollback_ref:
            assert action.rollback_ref in catalog, f"rollback inconnu pour {action.action_id}"
