# STACK TECHNIQUE — UnifiedGuard.cloud (validé 02/11/2026)

> Choix technologiques pour le socle gestion (ce repo) : agents, centrale (hub),
> console globale (fleet). Le socle backup (`backup.<domaine-client>`) réutilisera la
> même stack dans son propre projet.

## Tableau explicatif général

| Composant | Techno choisie | Pourquoi ce choix | Alternatives écartées (et pourquoi) |
|---|---|---|---|
| **Langage — agents** | **Go** | Binaire **statique unique** par OS (aucune dépendance à installer sur le device), compilation croisée Linux/Windows/ARM triviale, libs crypto stdlib (TLS, x509, AES, Ed25519), goroutines parfaites pour heartbeat + file d'actions, footprint minuscule (quelques Mo). Go tourne déjà partout chez dpnac (bot), compétence maison | Rust (courbe d'apprentissage, temps de dev), Python/Node (runtime à installer sur les devices — rédhibitoire), C (trop bas niveau, sécurité) |
| **Langage — hub + fleet (API)** | **Go** | Un seul langage pour TOUT (agents, hub, fleet) = base de code partagée (modèles, crypto, protocole), maintenance réduite, recrutement simple | Node/TypeScript (2ᵉ runtime), Java (mémoire, lourdeur) |
| **Frontend dashboards** | **HTML/CSS/JS vanilla** (sans framework) | Validé par Fabien : pas de build complexe, cohérent avec le module Bot, serveur statique simple, inspection/debug direct dans le navigateur, zero dette npm | React/Vue/Svelte (tooling, builds, complexité injustifiée pour un dashboard opérationnel) |
| **Lib graphique dashboard** | **Chart.js** (lib JS unique) | Graphes télémétrie (CPU/RAM/disque/réseau) en quelques lignes, CDN/fichier local, pas de build | D3 brut (trop bas niveau), Grafana embarqué (produit séparé, surdimensionné) |
| **Base de données** | **PostgreSQL 17** | Transactions ACID (audit chaîné N5), JSONB (télémétrie semi-flexible), index performants, éprouvé en docker-compose, backup/restauration standard | MySQL/MariaDB (JSONB inférieur), SQLite (mono-fichier, inadapté au SaaS), MongoDB (besoin ACID) |
| **Time-series (évolution)** | **TimescaleDB** (extension PostgreSQL) | SI le volume télémétrie devient énorme : c'est une extension PG = migration douce, pas de produit nouveau. Décision différée — MVP sur PG pur | InfluxDB/VictoriaMetrics (produits séparés, premature pour le MVP) |
| **Transport agent↔centrale** | **WebSocket over TLS (mTLS)** | Canal persistant **initié par l'agent** (règle d'or §2.1) : bidirectionnel sans port d'écoute sur le device, pousse heartbeat/télémétrie ET reçoit les commandes sur le même canal, reconnexion auto, standard, facile à diagnostiquer | gRPC (plus rigide, moins lisible), long-polling HTTP (latence, gaspillage), SSH (mauvais modèle d'auth par host) |
| **Format des messages** | **JSON versionné** (MVP) | Lisible, débogable, universel ; schémas versionnés (`"v":1`) pour compatibilité ascendante des agents | Protobuf/CBOR (compacité) — envisageable plus tard si la bande passante télémétrie devient critique ; JSON d'abord pour la simplicité |
| **API dashboard + fleet↔hub** | **REST/JSON** | Simple, curl-able, tests faciles, cohérent avec le frontend vanilla | GraphQL (surdimensionné), gRPC-Gateway (double abstraction) |
| **mTLS** | **crypto/tls + crypto/x509** (stdlib Go) | Zéro dépendance : CA interne de la centrale, certificats clients par agent, révocation par CRL locale | libs tierces (inutile — la stdlib Go est excellente) |
| **Signatures** (audit N5, manifestes N12, auto-update) | **Ed25519** (crypto/ed25519 stdlib) | Signatures rapides et petites ; parfait pour chaîner le journal d'audit et signer les binaires d'agent | RSA (plus lourd, moins moderne pour signatures) ; PQC (dilithium) à surveiller en évolution |
| **Chiffrement sauvegardes FW / blobs** | **AES-256-GCM** (crypto/aes stdlib) | Standard moderne authentifié : chiffre + integrité en une passe | ChaCha20-Poly1305 (équivalent, choix arbitraire AES pour conformité) |
| **Enveloppe de clé de site** | **RSA-4096-OAEP** ou **X25519+HKDF** | Clé de session AES enveloppée par la clé publique du site (§6.3) ; RSA-OAEP stdlib direct, X25519 plus moderne — décision d'implémentation au codage | HPKE (RFC 9180, pas encore en stdlib Go) |
| **Passphrase clé de secours (N14)** | **Argon2id** (golang.org/x/crypto) | Standard de facto du hachage de passphrase résistant GPU (RFC 9106) | PBKDF2 (plus faible face aux GPU), bcrypt (conçu mots de passe courts) |
| **Reverse proxy / TLS public** | **Caddy 2** | TLS Let's Encrypt automatique en 3 lignes de config, HTTP/2/3 natif, admin API simple, binaire unique dans le compose | Traefik (plus puissant mais config labels plus verbeuse), Nginx (certbot à gérer manuellement) |
| **Packaging agents** | **nfpm** (.deb/.rpm) + **WiX/go-msi** (.msi) | nfpm (goreleaser) : un YAML → .deb + .rpm propres ; WiX pour le .msi Windows (service Windows, upgrade propre) | Scripts d'install manuels (non maintenables), Ansible (hors périmètre produit) |
| **Build multi-plateforme** | **goreleaser** ou script Makefile** | Cross-compile linux/amd64, linux/arm64, windows/amd64 + checksums + signatures en une commande | Docker-in-Docker (lourd), CI opaque |
| **SMTP (mails tenants + N10)** | **net/smtp / go-mail** (SMTP configurable par env) | Confirmation d'inscription des tenants + notifications : SMTP sortant standard, s'adapte à n'importe quel serveur de mail (mailcow dpnac, Gmail, Proton bridge…) | API propriétaires (SendGrid/Mailjet) : dépendance externe, coûts, RGND (envoyé via le SMTP du client = mieux) |
| **Conteneurisation** | **Docker + docker-compose** | Validé depuis le début : 1 commande = centrale complète (api, postgres, caddy) ; compose aussi pour le fleet | Kubernetes (overkill pour centrales clients), Podman (moins universel) |
| **Gestion secrets compose** | **Variables d'environnement + .env** (jamais dans le repo) | Standard docker, secrets séparés par environnement | Vault (produit de plus à opérer, inutile au MVP), Docker secrets (couple avec swarm) |
| **Tests Go** | **go test** + **testify** | Stdlib + assertions lisibles ; table-driven tests idiomatics | — |
| **Linting** | **golangci-lint** (staticcheck, govet, errcheck…) | Un outil qui agrège tous les linters, config unique | linters séparés (maintenance) |
| **CI/CD** | **Gitea Actions** (git.dpnac.cloud) si activé, sinon Makefile local | Le repo vit déjà sur git.dpnac.cloud ; Gitea Actions = syntaxe compatible GitHub Actions ; sinon les cibles `make test/lint/build` font le job | GitHub Actions (repo pas sur GitHub), GitLab CI (autre infra) |
| **Docs** | **Markdown** (ce dossier) | Versionnées avec le code, lisibles dans Gitea | Wiki séparé (dérive du code) |

## Décisions d'implémentation notables

1. **Un seul langage (Go) des agents au SaaS** : partage des types de protocole et de la
   crypto entre agent/hub/fleet → moins de bugs d'incompatibilité.
2. **Pas de npm/node_modules côté dashboard** : fichiers statiques servis par l'API Go
   (embedded FS) → un seul binaire hub contient déjà l'UI.
3. **UI embarquée dans le binaire** (`go:embed`) : le compose de la centrale n'a pas besoin
   de conteneur front séparé — un conteneur de moins à sécuriser.
4. **JSON maintenant, binaire plus tard** : le protocole agent↔centrale est versionné dès
   le début (`"v":1`) ; on pourra ajouter CBOR/protobuf sans casser les agents existants.
5. **PostgreSQL pur au MVP** : TimescaleDB uniquement si les métriques 5 min × 250 devices
   deviennent lourdes — mesure d'abord, optimisation ensuite.
6. **Caddy devant tout** : une centrale cliente = `central.<domaine-client>` avec un vrai
   certificat Let's Encrypt automatique, sans intervention manuelle.

## Ce qui reste à décider au moment du codage (mineur)
- RSA-OAEP vs X25519+HKDF pour l'enveloppe de clé (les deux sont sains — je trancherai
  au codage, test de perf à l'appui).
- goreleaser vs Makefile pur (goreleaser si on veut publier des artifacts GitHub-like).
- Icônes UI : lib SVG inline (recommandé : Lucide) vs emojis (dépend du style visuel choisi).