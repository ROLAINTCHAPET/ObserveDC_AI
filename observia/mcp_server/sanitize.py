"""Assainissement des données sources avant qu'elles n'atteignent le modèle (BR-04, NFR-03).

Limite de taille, suppression des caractères de contrôle, balisage <donnee_non_fiable>
et détection de motifs d'injection connus (journalisée, non bloquante pour la lecture).
"""
import re
from dataclasses import dataclass, field

TAG = "donnee_non_fiable"
MAX_CHARS = 8000
MAX_LINE_CHARS = 1000

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁦-⁩]")
_TAG_LIKE = re.compile(rf"</?\s*{TAG}[^>]*>", re.IGNORECASE)
INJECTION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in (
    r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above)\s+(instructions|rules)",
    r"ignore[rz]?\s+(toutes\s+)?les\s+(instructions|consignes|règles)",
    r"disregard\s+(the\s+)?(system|previous)",
    r"(you\s+are\s+now|tu\s+es\s+maintenant|from\s+now\s+on\s+you)",
    r"(system\s+prompt|prompt\s+système|new\s+instructions|nouvelles\s+instructions)",
    r"\b(propose_action|call\s+the\s+tool|appelle\s+l'outil)\b",
    r"\b(power_cut_rack|site_failover|emergency_shutdown)\b",
    r"^\s*(assistant|system|user)\s*:",
    r"</?\s*(tool_call|function_call|im_start|im_end)",
)]


@dataclass
class Sanitized:
    text: str
    suspicious: list[str] = field(default_factory=list)
    truncated: bool = False


def clean(text: str, max_chars: int = MAX_CHARS) -> Sanitized:
    text = _CONTROL.sub("", text)
    suspicious = [p.pattern for p in INJECTION_PATTERNS if p.search(text)]
    if _TAG_LIKE.search(text):
        suspicious.append("balise de délimitation dans la donnée")
        text = _TAG_LIKE.sub("[balise retirée]", text)
    lines = text.splitlines()
    truncated = any(len(ln) > MAX_LINE_CHARS for ln in lines)
    text = "\n".join(ln if len(ln) <= MAX_LINE_CHARS else ln[:MAX_LINE_CHARS] + "…" for ln in lines)
    if len(text) > max_chars:
        truncated = True
        text = text[:max_chars] + "\n[… tronqué]"
    return Sanitized(text, suspicious, truncated)


def wrap(text: str, origin: str) -> Sanitized:
    """Renvoie la donnée assainie, balisée comme non fiable."""
    s = clean(text)
    s.text = f'<{TAG} origine="{origin}">\n{s.text}\n</{TAG}>'
    return s
