#!/bin/bash
# État des lieux de la VM (feuille de route, phase 2 et porte G1). LECTURE SEULE : ne modifie rien.
# Usage : bash deploy/preflight.sh      → affiche et enregistre preflight-<machine>-<date>.txt
set -u
OUT="preflight-$(hostname)-$(date +%Y%m%d-%H%M).txt"
exec > >(tee "$OUT") 2>&1

ok()   { echo "  [OK]    $*"; }
warn() { echo "  [ATTN]  $*"; }
ko()   { echo "  [KO]    $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "=== ObservIA-DC — état des lieux de $(hostname), $(date -Is)"

echo "== Système"
. /etc/os-release; echo "  $PRETTY_NAME, noyau $(uname -r), virtualisation : $(systemd-detect-virt 2>/dev/null || echo inconnue)"
[ "${ID:-}" = debian ] && [ "${VERSION_ID:-}" = 13 ] && ok "Debian 13" || warn "système attendu : Debian 13"

echo "== CPU"
CPUS=$(nproc); echo "  $CPUS vCPU — $(lscpu | sed -n 's/^Model name:\s*//p')"
[ "$CPUS" -ge 4 ] && ok "≥ 4 vCPU (profil A)" || ko "< 4 vCPU : profil A− au mieux"
grep -qw avx2 /proc/cpuinfo && ok "AVX2 présent (inférence CPU possible)" || warn "pas d'AVX2 : inférence CPU très lente"

echo "== Mémoire"
MEM_GB=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo); echo "  $MEM_GB Go"
if [ "$MEM_GB" -ge 16 ]; then ok "≥ 16 Go : profil A + modèle 7B sur CPU"
elif [ "$MEM_GB" -ge 12 ]; then warn "12–15 Go : profil A, modèle 3B conseillé sur CPU (ou 7B sur GPU)"
elif [ "$MEM_GB" -ge 8 ]; then warn "8–11 Go : profil A− (sans observabilité interne), modèle 3B"
else ko "< 8 Go : insuffisant pour le profil A"; fi

echo "== Disque"
lsblk -d -o NAME,SIZE,ROTA,TYPE | sed 's/^/  /'
DOCKER_DIR=/var/lib/docker; [ -d "$DOCKER_DIR" ] || DOCKER_DIR=/var
FREE_GB=$(df -BG --output=avail "$DOCKER_DIR" | tail -1 | tr -dc 0-9); echo "  libre sous $DOCKER_DIR : $FREE_GB Go"
[ "$FREE_GB" -ge 100 ] && ok "≥ 100 Go libres" || warn "< 100 Go libres : rétention à réduire (profil A−, 14 jours)"
lsblk -d -o ROTA | tail -n +2 | grep -q 0 && ok "SSD détecté" || warn "aucun SSD détecté"

echo "== GPU"
if have lspci; then
  GPU=$(lspci | grep -iE "nvidia|vga|3d controller"); echo "$GPU" | sed 's/^/  /'
  echo "$GPU" | grep -qi nvidia && ok "GPU NVIDIA visible dans la VM" || warn "aucun GPU NVIDIA visible (passthrough non fait ?)"
else warn "lspci absent (paquet pciutils)"; fi
have nvidia-smi && { nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader | sed 's/^/  /'; ok "pilote NVIDIA actif"; } \
  || warn "nvidia-smi absent : pilote non installé (déploiement sur CPU d'abord)"

echo "== Heure"
timedatectl 2>/dev/null | grep -E "synchronized|NTP service" | sed 's/^ */  /'
timedatectl 2>/dev/null | grep -q "synchronized: yes" && ok "horloge synchronisée" || ko "horloge non synchronisée (exigée : écart < 1 s)"

echo "== Réseau"
ip -br addr | sed 's/^/  /'; grep nameserver /etc/resolv.conf | sed 's/^/  /'
for url in https://registry-1.docker.io/v2/ https://download.docker.com https://ollama.com https://github.com; do
  code=$(curl -s -m 8 -o /dev/null -w "%{http_code}" "$url" || true)
  [ "$code" != "000" ] && ok "accès $url ($code)" || warn "pas d'accès à $url (archives hors ligne nécessaires)"
done

echo "== Docker"
if have docker; then ok "$(docker --version)"; docker compose version >/dev/null 2>&1 && ok "$(docker compose version)" || ko "plugin compose absent"
else warn "Docker absent : sudo bash deploy/install-docker.sh"; fi

echo "== Ports déjà occupés (8000 ingestion, 8080 console)"
have ss && ss -ltnH '( sport = :8000 or sport = :8080 )' | sed 's/^/  /' | grep . && warn "port déjà utilisé" || ok "ports libres"

echo "=== Rapport enregistré dans $OUT"
