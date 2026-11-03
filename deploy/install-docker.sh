#!/bin/bash
# Docker Engine + plugin Compose sur Debian 13, depuis le dépôt officiel Docker (phase 3).
# Usage : sudo bash deploy/install-docker.sh [utilisateur-à-ajouter-au-groupe-docker]
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "à lancer avec sudo"; exit 1; }
. /etc/os-release

if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  echo "Docker déjà installé : $(docker --version)"
else
  apt-get update -q
  apt-get install -y -q ca-certificates curl gnupg pciutils
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

# Journaux Docker limités (feuille de route, phase 3)
if [ ! -f /etc/docker/daemon.json ]; then
  mkdir -p /etc/docker
  cat > /etc/docker/daemon.json <<'JSON'
{ "log-driver": "json-file", "log-opts": { "max-size": "20m", "max-file": "5" } }
JSON
  systemctl restart docker
fi
systemctl enable --now docker

if [ -n "${1:-}" ]; then
  usermod -aG docker "$1"
  echo "Utilisateur $1 ajouté au groupe docker (se reconnecter pour en profiter)."
fi
docker run --rm hello-world >/dev/null && echo "Docker opérationnel : $(docker --version)"
