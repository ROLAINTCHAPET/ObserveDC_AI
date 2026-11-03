# Source silencieuse

Règle associée : source_silent (aucune donnée d'une source depuis 2 minutes).

## Vérifications
- Une source muette ne signifie pas que les équipements vont bien : c'est une perte de visibilité.
- Vérifier si toutes les données de la source manquent, ou seulement certains équipements.

## Actions possibles
- Relancer le job de supervision ou de collecte concerné (rerun_monitoring_job).
- Si la source reste muette : ouvrir un ticket (open_ticket) P1 pour vérifier réseau,
  alimentation et identifiants du collecteur.
