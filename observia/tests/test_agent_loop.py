"""Boucle de l'agent avec un modèle simulé : plafonds, mode dégradé, contrat de sortie."""
import asyncio
import json
from uuid import uuid4

from agent.gateway import ChatResult, ModelUnavailable, ToolCall
from agent.loop import Budget, investigate
from agent.pseudonymize import Pseudonymizer

INCIDENT = {"incident_id": "i-1", "summary": "[rack_temperature_high] température > 32 °C", "equipment": "B12"}
READ_TOOL = {"type": "function", "function": {"name": "get_metrics", "description": "", "parameters": {"type": "object"}}}


class FakeGateway:
    def __init__(self, script):
        self.script = list(script)
        self.seen: list[list[dict]] = []

    async def chat(self, messages, tools):
        self.seen.append(json.loads(json.dumps(messages)))
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        if item == "hang":
            await asyncio.sleep(10)
        return item


class FakeTools:
    def __init__(self):
        self.calls, self.proposals = [], []

    async def read_tools(self):
        return [READ_TOOL]

    async def call(self, name, args):
        self.calls.append((name, args))
        return '<donnee_non_fiable origine="get_metrics">{"equipment": "B12", "series": [35.1]}</donnee_non_fiable>'

    async def propose(self, run_id, action_id, target, justification, confidence, params):
        self.proposals.append((action_id, target, confidence, params))
        return {"decision": "SHADOW", "effective_level": 2}


class FakeStore:
    def __init__(self):
        self.steps = []

    async def record_step(self, *args):
        self.steps.append(args)


def tool_call(name, args, cid="c1"):
    return ChatResult(None, [ToolCall(cid, name, json.dumps(args))], tokens=100)


def conclusion(action=None, confiance=0.82):
    return {"diagnostic": "Ventilateur arrêté, température EQ-001 en hausse", "cause_probable": "panne ventilateur",
            "confiance": confiance, "preuves": ["metric:EQ-001.temperature"], "action": action}


async def run(script, budget=Budget(max_steps=8, max_seconds=5, model_timeout_s=2)):
    gw, tools, store = FakeGateway(script), FakeTools(), FakeStore()
    pseudo = Pseudonymizer(["B12"])
    out = await investigate(uuid4(), INCIDENT, "system", gw, tools, store, pseudo, budget)
    return out, gw, tools, store


async def test_nominal_investigation_then_proposal_uc02():
    out, gw, tools, store = await run([
        tool_call("get_metrics", {"equipment": "EQ-001", "metric": "temperature"}),
        tool_call("submit_conclusion", conclusion({"action_id": "migrate_workload", "cible": "EQ-001", "parametres": {}})),
    ])
    assert out.status == "PROPOSED" and out.steps == 2 and out.tokens == 200
    # Pseudonymes restitués avant l'appel des outils et du garde-fou
    assert tools.calls == [("get_metrics", {"equipment": "B12", "metric": "temperature"})]
    assert tools.proposals == [("migrate_workload", "B12", 0.82, {})]
    assert len(store.steps) == 1
    # Le modèle n'a jamais vu le nom réel de l'équipement
    assert "B12" not in json.dumps(gw.seen)


async def test_conclusion_without_action_escalates_to_human():
    out, *_ = await run([tool_call("submit_conclusion", conclusion(None))])
    assert out.status == "CONCLUDED" and out.output.action is None


async def test_step_budget_exhausted_escalates():
    script = [tool_call("get_metrics", {"equipment": "EQ-001", "metric": "t"}, f"c{i}") for i in range(3)]
    out, *_ = await run(script, Budget(max_steps=3, max_seconds=5))
    assert out.status == "ESCALATED" and out.steps == 3 and "budget" in out.reason


async def test_time_budget_degrades_on_hanging_model():
    out, *_ = await run(["hang"], Budget(max_steps=8, max_seconds=0.2, model_timeout_s=0.2))
    assert out.status == "DEGRADED"


async def test_model_unavailable_degrades_br08():
    out, *_ = await run([ModelUnavailable("503")])
    assert out.status == "DEGRADED" and "modèle" in out.reason


async def test_invalid_outputs_degrade():
    bad = tool_call("submit_conclusion", {"diagnostic": "x", "confiance": 7})
    out, *_ = await run([bad, bad])
    assert out.status == "DEGRADED"


async def test_model_cannot_call_propose_action_or_unknown_tools():
    out, gw, tools, _ = await run([
        tool_call("propose_action", {"action_id": "power_cut_rack", "target": "EQ-001"}),
        tool_call("submit_conclusion", conclusion(None)),
    ])
    assert tools.proposals == [] and tools.calls == []
    assert "non autorisé" in gw.seen[1][-1]["content"]
    assert out.status == "CONCLUDED"


async def test_plain_json_answer_is_accepted():
    out, *_ = await run([ChatResult(json.dumps(conclusion(None)), [], 10)])
    assert out.status == "CONCLUDED"
