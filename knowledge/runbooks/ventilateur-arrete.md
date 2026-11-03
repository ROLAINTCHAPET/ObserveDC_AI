# Ventilateur à l'arrêt

Règle associée : fan_stopped (vitesse du ventilateur = 0).

## Vérifications
- Confirmer sur plusieurs mesures : une seule valeur à 0 peut venir du capteur ou du collecteur.
- Regarder la température de la baie sur la dernière heure : si elle ne monte pas, le capteur
  est probablement en cause plutôt que le ventilateur.

## Actions possibles
- Capteur douteux : augmenter la fréquence de collecte (increase_collection_rate) pour confirmer.
- Panne confirmée avec hausse de température : migrer la charge (migrate_workload) et ouvrir
  un ticket (open_ticket) de priorité P2 pour intervention physique.
