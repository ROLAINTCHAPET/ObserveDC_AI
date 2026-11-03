# Image unique des services Python d'ObservIA-DC (monolithe modulaire, un déployable par rôle).
# Le service lancé dépend de la commande (voir docker-compose.yml).
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
RUN useradd --create-home --uid 10001 observia
WORKDIR /app
COPY pyproject.toml ./
RUN python - <<'PY'
import subprocess, sys, tomllib
project = tomllib.load(open("pyproject.toml", "rb"))["project"]
deps = project["dependencies"] + project["optional-dependencies"]["immudb"]
subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-cache-dir", *deps])
PY
COPY . .
USER observia
