"""Adaptateur du format JSON de Telegraf (collecteur de périphérie, D16).

Telegraf (outputs.http, data_format = "json") envoie
{"metrics": [{"name": "rack", "fields": {"temperature": 31.2}, "tags": {"equipment": "B12"}, "timestamp": 1730000000}]}
Chaque champ numérique devient un événement « <champ> » (ou « <name>.<champ> » si tags.prefix_name).
"""
from datetime import datetime, timezone
from typing import Any


def to_events(body: dict[str, Any]) -> list[dict[str, Any]]:
    metrics = body.get("metrics", [body] if "fields" in body else [])
    events: list[dict[str, Any]] = []
    for m in metrics:
        tags = m.get("tags", {})
        equipment = tags.get("equipment") or tags.get("host")
        ts = datetime.fromtimestamp(m.get("timestamp", 0), tz=timezone.utc).isoformat()
        for field, value in m.get("fields", {}).items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                continue
            metric = f"{m.get('name')}.{field}" if tags.get("prefix_name") else field
            events.append({
                "equipment": equipment,
                "metric": metric,
                "value": float(value),
                "timestamp": ts,
                "payload": {"collector": "telegraf", "tags": tags},
            })
    return events
