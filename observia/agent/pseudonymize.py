"""Pseudonymisation des extraits envoyés au modèle (hypothèse H1, D2).

Noms d'équipements, adresses IP et MAC, e-mails et noms d'hôtes sont remplacés par des
jetons stables pour la durée d'une investigation, puis restitués dans les arguments
d'outils et dans la sortie de l'agent. La table de correspondance ne quitte jamais le site.

Avec un modèle local (Ollama), les données ne quittent pas le site : la pseudonymisation
est désactivée par défaut (OBSERVIA_PSEUDONYMIZE=false) et ce module devient l'identité.
"""
import json
import re
from typing import Any

_PATTERNS = [
    ("MAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("MAC", re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")),
    ("HOST", re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:local|lan|internal|corp|intra)\b", re.IGNORECASE)),
]


class Pseudonymizer:
    def __init__(self, equipment_codes: list[str], enabled: bool = True) -> None:
        self.enabled = enabled
        self._to_token: dict[str, str] = {}
        self._to_real: dict[str, str] = {}
        codes = sorted({c for c in equipment_codes if c}, key=len, reverse=True)
        self._codes = re.compile(r"(?<![\w-])(" + "|".join(map(re.escape, codes)) + r")(?![\w-])") if codes else None
        self._counters: dict[str, int] = {}

    def _token(self, kind: str, real: str) -> str:
        if real not in self._to_token:
            n = self._counters.get(kind, 0) + 1
            self._counters[kind] = n
            token = f"{kind}-{n:03d}"
            self._to_token[real] = token
            self._to_real[token] = real
        return self._to_token[real]

    def encode(self, text: str) -> str:
        if not self.enabled:
            return text
        for kind, pattern in _PATTERNS:
            text = pattern.sub(lambda m, k=kind: self._token(k, m.group(0)), text)
        if self._codes:
            text = self._codes.sub(lambda m: self._token("EQ", m.group(0)), text)
        return text

    def decode(self, text: str) -> str:
        if not self._to_real:
            return text
        pattern = re.compile("|".join(map(re.escape, sorted(self._to_real, key=len, reverse=True))))
        return pattern.sub(lambda m: self._to_real[m.group(0)], text)

    def decode_obj(self, obj: Any) -> Any:
        return json.loads(self.decode(json.dumps(obj, ensure_ascii=False)))
