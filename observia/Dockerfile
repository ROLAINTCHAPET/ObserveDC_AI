# Image unique des services Python d'ObservIA-DC (monolithe modulaire, un déployable par rôle).
# Le service lancé dépend de la commande (voir docker-compose.yml).
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
RUN useradd --create-home --uid 10001 observia
WORKDIR /app
# INSTALL_IMMUDB=1 : client immudb (D12). 0 au premier déploiement : audit PostgreSQL chaîné (profil A−)
ARG INSTALL_IMMUDB=0
COPY pyproject.toml ./
RUN INSTALL_IMMUDB=$INSTALL_IMMUDB python - <<'PY'
import os, subprocess, sys, tomllib
project = tomllib.load(open("pyproject.toml", "rb"))["project"]
deps = project["dependencies"]
if os.environ["INSTALL_IMMUDB"] == "1":
    deps += project["optional-dependencies"]["immudb"]
subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-cache-dir", *deps])
PY
COPY . .
USER observia
