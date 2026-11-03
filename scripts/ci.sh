#!/bin/bash
# Contrôles CI : isolation des modules (SAD §6), tests de politique OPA, tests Python.
# Intégration : définir OBSERVIA_TEST_DSN (base jetable) et OBSERVIA_TEST_OPA_URL.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
$PY scripts/check_isolation.py
docker run --rm -v "$PWD/policies:/policies:ro" openpolicyagent/opa:1.4.2 test /policies
(cd observia && "../$PY" -m pytest -q)
