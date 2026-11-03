# Base de connaissances (RAG)

Runbooks Markdown indexés par `python -m knowledge.indexer` (plongements Ollama, pgvector).
Versionnés dans Git et relus comme le catalogue d'actions : un runbook modifié est réindexé
automatiquement, un runbook supprimé est retiré de l'index.

Les runbooks de `runbooks/` sont des **exemples de départ** à remplacer par les procédures
réelles de l'exploitation [CLI]. Un titre `#` par document, une section `##` par étape ou cas :
chaque section devient un passage recherchable. Ne jamais y mettre de secret.

Les incidents résolus ayant un verdict humain (mode ombre ou validation) sont indexés en plus,
depuis la base, sans fichier.
