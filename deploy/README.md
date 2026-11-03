# Déploiement sur la VM (Debian 13) — premier essai sur CPU

Ordre conforme à la feuille de route (phases 2 à 11). Le GPU sera activé dans un second temps.
Chaque étape est relançable sans risque.

## 1. État des lieux (lecture seule, porte G1)

```bash
git clone https://github.com/ROLAINTCHAPET/ObserveDC_AI.git observia && cd observia
bash deploy/preflight.sh
```

Le rapport `preflight-<machine>-<date>.txt` décide du profil (A, A−) et du modèle :

| RAM de la VM | Profil | Modèle sur CPU (`OBSERVIA_MODEL_NAME`) |
|---|---|---|
| ≥ 16 Go | A | `qwen2.5:7b-instruct` |
| 12 à 15 Go | A | `qwen2.5:3b` (7B quand le GPU sera actif) |
| 8 à 11 Go | A− | `qwen2.5:3b` |

## 2. Docker (phase 3)

```bash
sudo bash deploy/install-docker.sh $USER   # puis se déconnecter / reconnecter
```

## 3. Secrets et paramètres (phase 3)

```bash
bash deploy/gen-env.sh      # génère .env (droits 600) avec tous les mots de passe et jetons
nano .env                   # compléter : SMTP, destinataires, passerelle SMS, CONSOLE_BASE_URL, modèle
```

Ne jamais versionner ni copier `.env` hors de la VM.

## 4. Démarrage (phases 4 à 9)

```bash
bash deploy/up.sh
```

Construit l'image, démarre la base, applique les migrations, télécharge les modèles
(plusieurs Go la première fois, depuis la VM), démarre les services et vérifie leur santé.
En cas d'échec : `docker compose logs <service>`.

## 5. Données de référence

```bash
docker compose run --rm migrate python -m shared.admin add-equipment B12 rack HIGH PROD --zone Z1
docker compose run --rm migrate python -m shared.admin add-source iot-main IOT     # clé affichée une seule fois
```

Puis, quand les métriques réelles des sources sont connues (H5), activer les règles
correspondantes via l'API de la console (`PATCH /rules/{nom}`).

## 6. Essai de bout en bout (test T1)

```bash
bash deploy/smoke.sh
```

10 à 20 min sur CPU : surchauffe simulée sur une baie de test → incident → investigation par
le modèle local → décision du garde-fou → notification → retour à la normale → clôture →
vérification de l'audit. Nettoie derrière lui.

## Comptes de la console (pilote)

Sans SSO configuré, la console accepte des jetons HS256 signés avec `OBSERVIA_CONSOLE_JWT_SECRET` :

```bash
docker compose exec console-api python -c "import jwt,time,os; print(jwt.encode({'sub':'admin','roles':['admin'],'exp':int(time.time())+8*3600}, os.environ['OBSERVIA_CONSOLE_JWT_SECRET'], 'HS256'))"
curl -H "Authorization: Bearer <jeton>" http://localhost:8080/rules
```

## Points d'attention

- **Mode ombre** : `OBSERVIA_SHADOW_MODE=true` et `OBSERVIA_EXECUTION_ENABLED=false` ; rien n'est exécuté.
- **Ports 8000 (ingestion) et 8080 (console)** : en clair pour l'essai ; à placer derrière un proxy TLS
  avant l'exploitation (NFR-01).
- **Audit** : journal PostgreSQL chaîné (profil A−). Pour immudb : `INSTALL_IMMUDB=1`,
  `OBSERVIA_IMMUDB_ENABLED=true`, puis `docker compose --profile immudb up -d --build`.
- **Collecteur Telegraf** : `docker compose --profile collector up -d` une fois `collector/telegraf.conf`
  adapté et `CARD_SOURCE_KEY` renseigné.
- **GPU** (plus tard) : pilote NVIDIA + NVIDIA Container Toolkit, puis décommenter le bloc `deploy`
  du service `ollama` dans `docker-compose.yml`.
