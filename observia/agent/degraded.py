"""Mode dégradé à règles simples (BR-08, UC-06) : sans modèle, l'administrateur reçoit
le contexte brut de l'incident et une consigne fixe, sans aucune action automatique."""
from typing import Any

HINTS = {
    "rack_temperature_high": "Vérifier la ventilation de la baie ; envisager une migration de charge (validation humaine).",
    "rack_temperature_critical": "Température critique : intervention immédiate sur la baie ou la climatisation de la zone.",
    "temperature_rising_fast": "Hausse rapide : vérifier ventilateurs et climatisation avant le seuil critique.",
    "equipment_silent": "Équipement muet : vérifier alimentation, réseau et capteur.",
    "temperature_frozen": "Capteur probablement bloqué : la température réelle n'est pas connue, vérifier sur site.",
    "ingestion_rejects": "Données rejetées : vérifier le format envoyé par la source (changement de version ?).",
    "fan_stopped": "Ventilateur à l'arrêt : intervention physique ou migration de charge à décider.",
    "error_rate_high": "Consulter les logs de l'équipement ; redémarrage du service à décider.",
    "source_silent": "Vérifier la source et son collecteur (réseau, alimentation, identifiants).",
}
DEFAULT_HINT = "Investigation manuelle requise."


def degraded_message(incident: dict[str, Any], reason: str) -> tuple[str, str]:
    subject = f"[Mode dégradé] {incident.get('summary', 'incident')}"
    body = "\n".join([
        f"Agent indisponible : {reason}",
        f"Incident : {incident.get('incident_id')} — sévérité {incident.get('severity')}",
        f"Équipement : {incident.get('equipment') or '—'} ; source : {incident.get('source') or '—'}",
        f"Règle : {incident.get('rule')} ; ouvert à {incident.get('opened_at')}",
        f"Consigne : {HINTS.get(incident.get('rule') or '', DEFAULT_HINT)}",
    ])
    return subject, body
