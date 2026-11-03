"""Découpage des documents en passages, en suivant les titres Markdown."""
import re

MAX_CHARS = 1200
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")


def title_of(text: str, default: str) -> str:
    for line in text.splitlines():
        m = _HEADING.match(line)
        if m:
            return m.group(2).strip()
    return default


def chunk_markdown(text: str, max_chars: int = MAX_CHARS) -> list[str]:
    """Une section par passage ; une section trop longue est coupée entre paragraphes.
    Chaque passage garde le chemin de titres qui le situe (« Baie > Température »)."""
    sections: list[tuple[str, list[str]]] = []
    path: list[str] = []
    body: list[str] = []
    for line in text.splitlines():
        m = _HEADING.match(line)
        if m:
            sections.append((" > ".join(path), body))
            depth = len(m.group(1))
            path = path[: depth - 1] + [m.group(2).strip()]
            body = []
        else:
            body.append(line)
    sections.append((" > ".join(path), body))

    chunks: list[str] = []
    for heading, lines in sections:
        paragraphs = [p.strip() for p in "\n".join(lines).split("\n\n") if p.strip()]
        current = ""
        for para in paragraphs:
            for piece in _split_long(para, max_chars):
                if current and len(current) + len(piece) + 2 > max_chars:
                    chunks.append(_with_heading(heading, current))
                    current = piece
                else:
                    current = f"{current}\n\n{piece}" if current else piece
        if current:
            chunks.append(_with_heading(heading, current))
    return chunks


def _split_long(paragraph: str, max_chars: int) -> list[str]:
    return [paragraph[i:i + max_chars] for i in range(0, len(paragraph), max_chars)] or [paragraph]


def _with_heading(heading: str, text: str) -> str:
    return f"{heading}\n{text}" if heading else text
