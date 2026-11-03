# UnifiedGuard.cloud — LIVRAISON BÊTA 0.1

**Contenu** : la centrale (hub) complète avec dashboard web, agents Linux, et la console
SaaS (squelette). Version du code : commit Git + date de build (voir `/api/v1/ping`).

**Fichiers de livraison** (à côté de ce README) :
- `central-unified-latest.tar` — image Docker pré-buildée (`central-unified:latest`,
  ~24 Mo, `FROM scratch`) : `docker load -i central-unified-latest.tar` puis
  `docker compose up -d` (aucun build requis).

## Ce qui marche (testé E2E)

- **Dashboard** : login e-mail + mot de passe (Argon2id) + code MFA, thèmes clair/sombre/auto,
  liste des hôtes avec statut en ligne, télémétrie (CPU/RAM/disques/services), audit chaîné
  vérifiable (`/audit` → bouton Vérifier), ping applicatif avec RTT, file d'actions
  (livrées à la reconnexion d'un agent hors-ligne).
- **Enrollment** : token à usage unique (TTL 24 h, stocké hashé) créé dans l'UI `/enroll` ;
  l'agent s'enrôle en une commande et reçoit un certificat mTLS signé par la CA de la centrale.
- **Pare-feu commit-confirm (J4)** : règles appliquées en mode runtime + compte à rebours ;
  non confirmées → **rollback automatique** (l'agent est l'autorité : hub mort ou WS coupé →
  rollback immédiat). Snapshot du ruleset scellé avec la clé publique du site (AES-256-GCM +
  RSA-OAEP) — la centrale ne peut pas le lire. Timeline des sessions dans l'UI hôte.
  ⚠️ À recetter sur un hôte avec un vrai pare-feu (nftables/ufw/firewalld).
- **Agents** : heartbeat 30 s, self-hash (détection de binaire modifié), télémétrie 5 min,
  actions distantes (ping, inventaire paquets). Linux uniquement (Windows = J8).

## Ce qui manque (bêta, pas de production)

- **Mail** (J9) : le code de login MFA est écrit dans **les logs du hub**
  (`docker compose logs hub | grep "BETA login code"`). Jamais en GA — SMTP arrive en J9.
- **TLS** : le hub écoute en HTTP sur 8080. Mettez Caddy/Traefik/Nginx avec un vrai
  certificat devant (l'agent utilise `wss://` dès que l'URL est en `https://`).
- **Paquets** (J5), **groupes d'hôtes CRUD**, **maintenance planifiée**, **Windows** (J8),
  **SaaS global** (squelette).

## Démarrage express (Docker)

### Option A — image pré-buildée (recommandée pour la bêta)

```bash
# 1. Importez l'image (une seule fois — fournie dans la livraison) :
docker load -i central-unified-latest.tar        # → central-unified:latest

# 2. Configurez :
cp .env.example .env
# éditez .env : POSTGRES_PASSWORD, HUB_BOOTSTRAP_PASSWORD, HUB_DOMAIN…

# 3. Démarrez (AUCUN build — l'image est déjà prête) :
docker compose up -d
docker compose logs hub        # suivez : migrations 001→007, bootstrap admin
```

L'image `central-unified:latest` est `FROM scratch` (~24 Mo) : binaire hub
statique + agent + fleet embarqués, healthcheck intégré (`hub healthcheck`,
sans curl). Tags aussi disponibles : `central-unified:0.1`,
`ghcr.io/fs83500/central-unified:latest` (prêt pour un push registry).

### Option A2 — build automatisé par la forge (CI)

Deux workflows livrés, prêts à brancher :

- **Forgejo** (`.forgejo/workflows/build-image.yml`) : à chaque push sur `main`
  ou tag `v*`, build statique + `tools/mkimage` + push vers le **registry
  Docker intégré de Forgejo** → `git.dpnac.cloud/dpnac/central-unified:latest`.
  Prérequis côté instance : un runner (`act_runner`, label `docker-latest`),
  le registry intégré activé, `GITHUB_TOKEN` avec scope packages (défaut).
  Ensuite le compose devient :
  ```yaml
  image: git.dpnac.cloud/dpnac/central-unified:latest
  ```
- **GitHub Actions** (`.github/workflows/build-image.yml`) : publie sur
  **GHCR** `ghcr.io/fs83500/central-unified` (repo privé → `docker login
  ghcr.io` requis pour pull, ou rendre le package public).

### Option B — construire depuis la source

Décommentez la section `build:` du service `hub` dans `docker-compose.yml`
puis :

```bash
docker compose up -d --build
```

Ouvrez `http://<serveur>:8080/` :

1. Login = `HUB_BOOTSTRAP_ADMIN` / `HUB_BOOTSTRAP_PASSWORD` du `.env`.
2. Le code MFA à 6 chiffres est dans les logs : `docker compose logs hub | grep "BETA login code"`.
3. Changez le mot de passe… (TODO J9 : l'édition de compte arrive avec le mail ; en attendant
   re-créez la DB ou changez le mot de passe en SQL).

## Ajouter un hôte (agent Linux)

Sur le dashboard : **Enrollment → Nouveau token** (copiez-le, affiché une seule fois).
Sur la machine cible :

```bash
# téléchargez l'agent (binaire autonome) — depuis le serveur de livraison,
# ou copiez-le (scp). Puis :
./agent enroll --hub https://central.exemple.fr --token <TOKEN_DU_DASHBOARD>
./agent run          # en production : systemd (voir ci-dessous)
```

> Hub avec un certificat self-signed (ex. bêta interne sans Caddy) : ajoutez
> `UG_ENROLL_INSECURE=1` **pour la commande enroll uniquement** — l'agent y
> reçoit la CA de la centrale et toutes les connexions suivantes (WebSocket
> mTLS) vérifient la chaîne complète. Inutile derrière Caddy/Let's Encrypt.

L'identité mTLS est stockée dans `--state` (défaut `/var/lib/unifiedguard`, 0700/0600).
Le hub n'appelle **jamais** l'agent : c'est l'agent qui ouvre le WebSocket (règle d'or SPEC §2.1) —
aucun port à ouvrir côté agent.

### systemd (recommandé)

```ini
# /etc/systemd/system/unifiedguard-agent.service
[Unit]
Description=UnifiedGuard agent
After=network-online.target

[Service]
ExecStart=/usr/local/bin/unifiedguard-agent run
Environment=AGENT_STATE_DIR=/var/lib/unifiedguard-agent
Restart=always
User=root            # télémétrie + pare-feu nécessitent root

[Install]
WantedBy=multi-user.target
```

## Architecture livrée

```
compose (docker)
├── db     PostgreSQL 17 — données + audit chaîné (volume ug_db_data)
├── hub    centrale : UI + API + WS agents + CA mTLS + migrations auto
│          (image central-unified:latest — FROM scratch, statique)
└── agent  (optionnel, décommenter) — agent de démo conteneurisé
```

Volumes persistants : `ug_db_data` (base), `ug_hub_data` (CA + clé de site — **à sauvegarder,
perdre la clé de site = perdre les snapshots de pare-feu §6.3**).

## Sauvegardes

- `ug_db_data` : `pg_dump` quotidien recommandé.
- `ug_hub_data` : CA (révoquer tous les agents si perdue) + clé de site.

## Sécurité — rappels bêta

- Le port DB n'est **pas** publié sur l'hôte.
- `HUB_MFA_LOG_BETA=1` expose le code de login dans les logs du hub : acceptable
  pour une bêta interne, à retirer dès J9 (SMTP).
- Mettez un reverse proxy TLS avant d'exposer le dashboard à qui que ce soit.
- Audit chaîné : vérifiable publiquement via `GET /api/v1/audit/verify`.