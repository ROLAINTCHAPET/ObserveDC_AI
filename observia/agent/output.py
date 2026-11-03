"""Contrat de sortie de l'agent, validé par schéma (SAD §13.2)."""
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ProposedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(max_length=64)
    cible: str = Field(max_length=128)
    parametres: dict[str, Any] = Field(default_factory=dict)


class AgentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    diagnostic: str = Field(min_length=1, max_length=2000)
    cause_probable: str = Field(min_length=1, max_length=500)
    confiance: float = Field(ge=0.0, le=1.0)
    preuves: list[str] = Field(default_factory=list, max_length=30)
    action: ProposedAction | None = None


CONCLUSION_TOOL = {
    "type": "function",
    "function": {
        "name": "submit_conclusion",
        "description": (
            "Termine l'investigation. Renseigne le diagnostic, la cause probable, ta confiance (0 à 1), "
            "les preuves consultées et, si une action du catalogue est justifiée, l'action proposée. "
            "Laisse « action » à null pour escalader vers un humain sans proposer d'action."
        ),
        "parameters": AgentOutput.model_json_schema(),
    },
}
