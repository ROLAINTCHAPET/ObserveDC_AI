"""Moteurs de politiques (D3) : OPA en nominal, moteur local en repli ou en test.

Le moteur local reproduit policies/guardrail.rego règle pour règle ; tests/test_policy.py
rejoue les mêmes cas contre les deux moteurs pour garantir leur parité.
"""
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from guardrail.catalog import CatalogAction

LEVEL_3 = 3


@dataclass
class PolicyResult:
    decision: str
    effective_level: int
    reasons: list[str] = field(default_factory=list)


FAIL_SAFE = PolicyResult("PENDING_APPROVAL", LEVEL_3, ["moteur de politiques indisponible : échec sûr"])


class PolicyEngine(Protocol):
    name: str

    async def evaluate(self, policy_input: dict[str, Any]) -> PolicyResult: ...


class OpaPolicy:
    name = "opa"

    def __init__(self, url: str, timeout_s: float, client: httpx.AsyncClient | None = None) -> None:
        self.url = f"{url.rstrip('/')}/v1/data/observia/guardrail/result"
        self.client = client or httpx.AsyncClient(timeout=timeout_s)

    async def evaluate(self, policy_input: dict[str, Any]) -> PolicyResult:
        resp = await self.client.post(self.url, json={"input": policy_input})
        resp.raise_for_status()
        result = resp.json().get("result")
        if not result:  # politique absente ou indéfinie
            raise RuntimeError("résultat OPA indéfini")
        return PolicyResult(result["decision"], int(result["effective_level"]), list(result.get("reasons", [])))


class LocalPolicy:
    name = "local"

    def __init__(self, catalog: dict[str, CatalogAction]) -> None:
        self.catalog = catalog

    async def evaluate(self, policy_input: dict[str, Any]) -> PolicyResult:
        return self.decide(policy_input)

    def decide(self, inp: dict[str, Any]) -> PolicyResult:
        action = self.catalog.get(inp.get("action_id", ""))
        target = inp.get("target") or {}
        state = inp.get("state") or {}
        limits = inp.get("limits") or {}

        refusals: set[str] = set()
        if action is None:
            refusals.add("action hors catalogue")
        if inp.get("params_valid") is not True:
            refusals.add("paramètres invalides")
        if action is not None:
            types = action.allowed_targets.get("types", [])
            type_ok = "*" in types or target.get("type") in types
            if not (target.get("known") is True and type_ok and target.get("env") in action.allowed_targets.get("env", [])):
                refusals.add("cible inconnue ou non autorisée pour cette action")

        levels = {action.base_level} if action else {LEVEL_3}
        if (target.get("criticality") in {"HIGH", "CRITICAL"} and target.get("env") == "PROD"
                and not (action and action.non_intrusive)):
            levels.add(LEVEL_3)
        if _num(target.get("impacted_count")) and _num(limits.get("max_impacted_equipment")) \
                and target["impacted_count"] > limits["max_impacted_equipment"]:
            levels.add(LEVEL_3)
        if target.get("kind") != "equipment":
            levels.add(LEVEL_3)
        conf, min_conf = inp.get("confidence"), limits.get("min_confidence")
        if not (_num(conf) and _num(min_conf) and conf >= min_conf):
            levels.add(LEVEL_3)
        level = max(levels)

        approvals: set[str] = set()
        if state.get("kill_switch") is True:
            approvals.add("kill switch actif : autonomie suspendue")
        if level == LEVEL_3:
            approvals.add("niveau 3 : validation humaine obligatoire")
        if state.get("shadow_mode") is not True and level not in (state.get("open_levels") or []):
            approvals.add("niveau non ouvert à l'autonomie")
        if state.get("quota_exceeded") is not False:
            approvals.add("quota d'actions automatiques atteint")
        if state.get("lock_held") is not False:
            approvals.add("action déjà en cours sur la cible")

        refused = bool(refusals)
        human = inp.get("human_approval") is True
        auto_allowed = not refused and not human and not approvals
        if refused:
            decision = "REFUSED"
        elif human and state.get("lock_held") is False:
            decision = "EXECUTE"
        elif auto_allowed and state.get("shadow_mode") is True:
            decision = "SHADOW"
        elif auto_allowed and state.get("shadow_mode") is False:
            decision = "EXECUTE"
        else:
            decision = "PENDING_APPROVAL"
        return PolicyResult(decision, level, sorted(refusals | approvals))


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)
