# Température élevée d'une baie

Règle associée : rack_temperature_high (température > 32 °C pendant 5 minutes).

## Vérifications
- Comparer la température de la baie à celle des baies voisines (get_topology, get_metrics).
  Si toute la zone chauffe, suspecter la climatisation (CRAC) plutôt que la baie.
- Vérifier la vitesse des ventilateurs de la baie (métrique fan_rpm). Un ventilateur à 0 tr/min
  explique souvent une hausse locale.
- Consulter l'historique : une baie déjà touchée par une panne de ventilateur récidive souvent.

## Actions possibles
- Ventilateur arrêté sur une baie isolée : migrer la charge (migrate_workload) en attendant
  l'intervention physique, puis ouvrir un ticket (open_ticket) pour le remplacement.
- Toute la zone chaude : ajuster la ventilation de la zone (adjust_cooling), toujours validé
  par un humain car l'action touche une zone entière.
- Ne jamais couper l'alimentation (power_cut_rack) pour une simple hausse de température :
  réservé aux dépassements critiques (> 45 °C) avec risque matériel, après validation.
