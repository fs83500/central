# PLAN D'ATTAQUE — UnifiedGuard.cloud (socle gestion)

> Document de référence technique pour le développement. Décisions toutes validées par
> Fabien (SPEC.md v0.3 + TECHNO.md). Ordre acté : MVP agent Linux → hub → dashboard →
> agent Windows → console globale, en câblant dès J0 les socles vague 1
> (audit chaîné N5, intégrité agent N12, clé de secours N14, bus d'événements N10).
> Git : l'agent committe et pousse (accord Fabien 02/11). Historique conventionnel lisible.

## 0. Principes directeurs

1. **Règle d'or des flux** (SPEC §2.1) : l'agent initie TOUT. Hub→agent = messages sur le canal
   ouvert par l'agent. Hub→fleet = push. Fleet = pull uniquement, ne pousse rien.
2. **Ping applicatif uniquement** (SPEC §2.3) : jamais ICMP, jamais de connexion vers un port
   du device.
3. **La crypto et l'audit se câblent dès la migration 001** — pas de rétrofit.
4. **Un jalon = du code testé + linté + doc à jour + prompts de recette** pour validation par
   Fabien (préférence #155).
5. Monorepo Go unique : un module, trois binaires (`agent`, `hub`, `fleet`), UI embarquées.

---

## 1. Structure du repository

```
central/
├── cmd/
│   ├── agent/main.go          # binaire device (Linux puis Windows)
│   ├── hub/main.go            # centrale (docker-compose client)
│   └── fleet/main.go          # console SaaS global.unifiedguard.cloud
├── internal/                  # code partagé (importé par les 3 binaires)
│   ├── protocol/              # types de messages v1 (JSON versionné) — LE contrat
│   ├── cryptoutil/            # mTLS/CA, enveloppes clé de site, Ed25519, Argon2id, AES-GCM
│   ├── audit/                 # chaîne d'audit (append + verify + export)
│   ├── store/                 # PostgreSQL + migrations embedded (golang-migrate)
│   ├── events/                # bus d'événements + file de notifications (N10)
│   └── version/               # version build + self-hash (N12)
├── agent/
│   ├── runtime/               # boucle : WS client, reconnect expo, file d'actions locale
│   ├── enroll/                # token → CSR → certificat mTLS (clé privée JAMAIS exportée)
│   └── platform/              # par OS :
│       ├── linux/             #   apt/dpkg, dnf/rpm, nftables/firewalld/ufw, télémétrie
│       └── windows/           #   winget, Defender FW, perf counters, VSS (plus tard)
├── hub/
│   ├── server/                # WS mTLS agents + REST dashboard
│   ├── domain/                # hosts, actions, FW (commit-confirm), paquets (plans)
│   ├── federation/            # push vers fleet + pull quota/abonnement
│   └── web/                   # UI hub (HTML/CSS/JS vanilla, go:embed)
├── fleet/
│   ├── server/                # REST + endpoints pull des hubs + API orgs
│   ├── accounts/              # users/orgs/memberships, @dpnac.fr, mail confirmation
│   └── web/                   # UI fleet (vanilla, go:embed)
├── migrations/
│   ├── hub/                   # 001..NNN (SQL, embedded)
│   └── fleet/
├── deploy/
│   ├── hub/                   # docker-compose.yml + Caddyfile + .env.example
│   └── fleet/                 # idem
├── docs/                      # SPEC, TECHNO, ROADMAP, IDEES, PLAN-ATTAQUE (ce doc)
├── Makefile                   # build/test/lint/migrate/pack targets
├── go.mod                     # module git.dpnac.cloud/dpnac/central
└── AVANCEMENT.md
```

**Règles de code** : Go 1.26 · `golangci-lint` (staticcheck, errcheck, gosec) · tests
`go test ./...` table-driven · messages proto JSON `"v":1` · migrations SQL numérotées
sans retour arrière (jamais modifier une migration livrée, toujours en ajouter) ·
secrets uniquement via env/`.env` (jamais committés) · commentaires de code en anglais,
docs en français.

---

## 2. Schéma de base de données — HUB (centrale)

> PostgreSQL 17. Toutes les tables portent `created_at/updated_at` (trigger). L'audit est
> alimenté par l'application sur TOUTE mutation sensible (API, actions FW, enrollment).

### Migration 001 — socle + audit chaîné (N5, câblée d'entrée)

| Table | Colonnes clés | Notes |
|---|---|---|
| `settings` | key, value jsonb | config runtime hub : **fqdn verrouillé à l'init**, mode SSO (désactivé/optionnel/exclusif), MFA e-mail activée, **trusted_proxies (X-Forwarded-*)**, **cors_allowed_origins (OFF par défaut)** |
| `local_users` | id, email, email_verified, password_hash argon2id, role, sso_subject?, mfa_email bool, totp_secret_enc?, webauthn_creds jsonb?, recovery_codes jsonb | comptes dashboard hub — activation par mail (double opt-in), MFA e-mail + TOTP/WebAuthn optionnels (J9), ou identité SSO liée |
| `login_attempts` | email?, ip, ts, success | rate-limiting : 5 échecs → backoff IP ; 10 échecs compte → lockout + mail |
| `site_keys` | id, version, public_key, created_at | **clés PUBLIQUES** de site ; la privée vit dans le volume `keys/` (0600), jamais en DB, jamais envoyée |
| `audit_events` | id BIGSERIAL, ts, actor, actor_type, action, target_type, target_id, params jsonb, result, prev_hash, hash, signature | `hash = SHA256(prev_hash ∥ canon_json(event))`, signature Ed25519 du hub ; INSERT uniquement ; vérificateur en continu |
| `enroll_tokens` | token_hash, label, expires_at, used_at, used_by_host | usage unique, TTL court (défaut 24 h) |

### Migration 002 — hosts & télémétrie

| Table | Colonnes clés | Notes |
|---|---|---|
| `host_groups` | id, name, color, maint_default | |
| `hosts` | id, hostname, friendly_name, os, os_version, arch, agent_version, agent_hash (N12), fw_type, fw_backend, fw_version, fw_active, group_id, status, last_seen, rtt_ms, cert_serial, enrolled_at, revoked_at | `status` dérivé : online / stale / offline |
| `telemetry` | host_id, ts, cpu_pct, mem_pct, load1, uptime_s, disks jsonb, net jsonb, services jsonb | partition mensuelle dès J2 (simple `PARTITION BY RANGE`) ; rétention 90 j (job) |

### Migration 003 — file d'actions (idée n°2)

| Table | Colonnes clés | Notes |
|---|---|---|
| `actions` | id, host_id, type, payload jsonb, status, created_by, created_at, delivered_at, started_at, finished_at, result jsonb, error | status : pending → delivered → running → done/failed/canceled/timeout |
| `action_events` | action_id, ts, event | journal d'exécution détaillé |

### Migration 004 — firewall core (rollback commit-confirm)

| Table | Colonnes clés | Notes |
|---|---|---|
| `fw_rulesets` | id, name, group_id?, canonical jsonb, canonical_hash, version, created_by | modèle canonique (N2) : la traduction backend se fait côté agent |
| `fw_snapshots` | id, host_id, taken_at, blob_enc, envelope, key_version, prev_id | **chiffré AES-256-GCM**, clé enveloppée par la clé publique du site (SPEC §6.3) ; copie poussée au fleet (blob, illisible) |
| `fw_changes` | id, host_id, ruleset_id, snapshot_id, diff jsonb, status, deadline_at, confirmed_at, rolled_back_at, reason | status : pending → applied_runtime → confirmed / rolled_back ; **le rollback est déclenché par l'agent**, jamais par le fleet |
| `fw_health_probes` | host_id, kind, target, expect | sondes locales applicatives (DNS, service, TCP sortant) — jamais ICMP |

### Migration 005 — paquets

| Table | Colonnes clés | Notes |
|---|---|---|
| `package_inventory` | host_id, name, version, arch, status, installed_at, updated_at | PK (host_id, name, arch) |
| `update_available` | host_id, name, current, candidate, security bool, severity, size_bytes | rempli à chaque inventaire |
| `patch_plans` | id, host_id?, group_id?, items jsonb, simulation jsonb, status, override_by, created_at | simulate → apply ; refus auto si suppressions non approuvées |
| `version_blacklist` | id, name, version, reason, cve?, created_by | N9 |
| `pinned_versions` | host_id?, group_id?, name, version | known-good |

### Migration 006 — maintenance & profils

| Table | Colonnes clés | Notes |
|---|---|---|
| `maint_windows` | id, group_id, days, start, end, tz, max_hosts_parallel | idée n°3 |
| `patch_campaigns` | id, name, group_id, plan_id?, status, canary_host_ids jsonb, canary_until, promoted_at | N8 |
| `profiles` | id, name + `profile_versions` (version, expected_packages jsonb, ruleset_id, created_by) | N4 |
| `host_profile` | host_id, profile_id, version | |

### Migration 007 — fédération & quotas

| Table | Colonnes clés | Notes |
|---|---|---|
| `hub_state` | singleton : fleet_url, hub_id, registered, public_key, quota_plan, quota_devices, quota_checked_at, **pending_pull** (jsonb : ordres en attente dont revocations) | le hub PULL sa config + **ordres (révocations cert PIV)** ici (SPEC §2.1.5, §5.1.3) |
| `cert_registry` | serial PK, subject, user_id?, purpose (dashboard/api_machine), state, issued_at, expires_at, revoked_at, revoked_by, revoked_via (central/global), crl_seq | certificats PIV émis par la CA utilisateurs ; CRL locale signée Ed25519 ; révocation re-auth + audit |
| `federation_outbox` | id, kind, payload_enc?, status, attempts, last_error | **push** vers fleet : santé, événements, blobs chiffrés, head d'audit ; retry/backoff |
| `blob_store` | id, kind, blob_enc, envelope, size, host_id?, created_at | blobs chiffrés répliqués (illisibles) |

### Migration 008 — dérive, notifications, divers (vagues 2-3)

`fw_baseline` (host_id, expected_hash, adopted_at) · `drift_events` ·
`notification_rules` (kind, severity, channel, target) · `notification_log` ·
`breakglass_runs` (N1) · `connectivity_tests` (N6).

## 2b. Schéma de base de données — FLEET (SaaS)

> Base **séparée** (instance PG distincte dans le compose fleet). Le fleet ne stocke
> **aucune donnée en clair des sites** : que du consolidé chiffré ou agrégé.

| Migration | Tables | Notes |
|---|---|---|
| 001 | `users` (email, email_verified, password_hash argon2id, is_dpnac_admin) · `email_tokens` · `login_attempts` | **admin global réservé @dpnac.fr** ; inscription libre + **double opt-in obligatoire** ; **MFA e-mail obligatoire** (codes Argon2id TTL 10 min) + TOTP/WebAuthn optionnels (J9) ; rate-limit IP + lockout |
| 002 | `orgs` (slug, name, owner) · `memberships` (org_id, user_id, role owner/admin/viewer) | multi-appartenance (SPEC §5.1) |
| 003 | `hubs` (id, org_id, name, domain, public_key, plan, quota_devices, last_seen, status) · `subscription_events` | une centrale = une ligne, appartient à UNE org |
| 004 | `hub_pushes` (hub_id, kind, payload, ts) · `blob_store` (blobs chiffrés répliqués — illisibles) · `audit_heads` (hub_id, head_hash, ts) · **`revocation_orders` (hub_id, serial, requested_by, requested_at, served_at)** | témoins d'audit (N5) ; **ordres de révocation PIV servis aux hubs par PULL** (SPEC §5.1.3 — le global n'invoque jamais les hubs) |
| 005 | `audit_events` (chaîne fleet) · `sessions` | |

---

## 3. Protocole agent ↔ hub (v1)

### 3.1 Enrollment (idée n°1)

```
1. Opérateur génère un token sur le dashboard hub (TTL 24 h, usage unique).
2. Agent : `unifiedguard-agent enroll --hub https://central.acme.fr --token <t>
   --hostname p-dns-01`
   → génère SA paire de clés LOCALEMENT (clé privée jamais transmise)
   → POST /api/v1/enroll { CSR, token, hostname, os, agent_version, agent_hash }
     (token dans le CORPS JSON, jamais dans une URL — logs de proxy propres)
3. Hub : vérifie token (hash) + quota d'abonnement (si quota atteint → refus
   explicite « plan 25 devices complet »), signe le CSR (CA interne hub,
   SAN = agent UUID), renvoie { agent_id, cert, ca, hub_config }
4. Agent : écrit cert+clé dans /var/lib/unifiedguard/ (0600), démarre le service.
5. Hub : audit_event(enroll, host) + notification.
```

#### 3.1.1 One-liner curl (déploiement agent en 1 commande — décision 02/11)

```bash
curl -fsSL https://central.<domaine>/install.sh | bash -s -- --token=ug-<uuid>
```

```
1. Hub sert install.sh (GET entrant = pas un push, règle d'or OK).
2. Script : détecte distro → télécharge .deb/.rpm + manifest.json
   (manifest signé Ed25519, clé publique EMBARQUÉE dans le script →
    vérification SHA-256 du paquet AVANT installation).
3. Installe le paquet (systemd unit présente, service PAS démarré).
4. Script lance : unifiedguard-agent enroll --token $TOKEN
   (→ POST /api/v1/enroll, corps JSON — cf. 3.1).
5. systemctl enable --now unifiedguard-agent → WS mTLS se connecte.
```

- Token usage unique + TTL 24 h → fuite éventuelle inutilisable.
- Alternative « parano » documentée : `curl -o install.sh … && cat install.sh && bash install.sh`.
- Équivalent Windows (J8) : script PowerShell servi par le hub (`.ps1`).
- **Approvisionnement du hub en agents (décision 02/11 : le global ne sert JAMAIS
  les agents)** : paquets/binaires embarqués dans l'image Docker du hub (version
  liée au hub) + rafraîchissement optionnel depuis le **dépôt éditeur dpnac**
  (hub initiateur, manifest signé Ed25519) + upload manuel possible (air-gap,
  N11). Chaque centrale reste autonome pour installer ses agents.

### 3.2 Canal principal — WebSocket mTLS (l'agent initiateur)

- URL : `wss://central.<domaine>/agent/v1/ws` — le client WebSocket = **l'agent**.
- mTLS : certificat client par agent, révocable par `cert_serial` (CRL locale).
- Reconnexion : backoff exponentiel (1 s → 60 s), jitter ; à la reconnexion :
  l'agent reçoit les actions pending (file, idée n°2).
- Enveloppe unique : `{"v":1,"id":"<uuid>","type":"...","ts":"RFC3339","data":{...}}`.

| Sens | type | data | Fréquence |
|---|---|---|---|
| A→H | `heartbeat` | agent_version, agent_hash (N12), fw_type/backend/version/actif, uptime, cpu/mem (léger) | 30 s |
| A→H | `telemetry` | complet : disques, net, services, load | 5 min |
| A→H | `inventory` | liste paquets + candidates MAJ | 24 h / à la demande |
| H→A | `ping` | {} | à la demande (dashboard « Ping » ou auto-diagnostic) |
| A→H | `pong` | ref=id, agent_ts | réponse → RTT calculé hub-side |
| H→A | `action` | id, type, payload | file d'actions (même offline : délivrée à la reconnexion) |
| A→H | `action_result` | id, status, result, error | — |
| A→H | `fw_state` | hash canonique ruleset courant (→ dérive N3) | heartbeat + post-changement |
| H→A | `fw_confirm` | change_id | **confirm commit-confirm** (dans le délai) |

### 3.3 Ping applicatif (SPEC §2.3 — jamais ICMP)

```
Hub → Agent (canal WS) : {"v":1,"type":"ping","id":"x1"}
Agent → Hub            : {"v":1,"type":"pong","ref":"x1","ts":...}
RTT = now(hub) − envoyé(hub).  Timeout 10 s sans pong → canal dégradé.
Offline = last_seen + 2×heartbeat sans activité → status stale, puis offline.
Watchdog : systemd Restart=always / Windows service recovery → l'agent crashé
redémarre seul ; un silence prolongé = machine éteinte/réseau coupé (alerte N10).
```

### 3.4 Commit-confirm firewall (SPEC §3.5)

```
1. Hub → action {type:"fw_apply", ruleset canonique traduit backend, ttl:300}
2. Agent : snapshot runtime chiffré (clé publique du site) → fw_snapshot
   (stocké hub + répliqué fleet), copie locale temporaire
3. Agent : applique en RUNTIME uniquement ; démarre le compte à rebours T
4. Agent : sondes locales applicatives (fw_health_probes) + heartbeats continuent
5. Hub : si heartbeats OK + sondes OK → fw_confirm AVANT l'échéance
6. Agent : commit permanent (save), confirme fw_changes.status=confirmed
   — Sinon (timeout OU heartbeat perdu OU sonde KO) : rollback runtime depuis
   le snapshot local, status=rolled_back, alerte N10, audit.
```

### 3.5 Paquets — plan en 4 phases (SPEC §3.6)

```
simulate (apt-get --simulate / dnf --assumeno) → plan affiché
check    (paquets cassés ? suppressions non demandées ? → refus auto)
apply    (transaction réelle, timeout, capture output)
verify   (services impactés OK ? → résultat remonté, sinon échec + détail)
```

---

## 4. Sécurité câblée dès J0 (vague 1)

| Socle | Ce qui est en place dès le départ | Où |
|---|---|---|
| **N5 audit chaîné** | Table 001 + `internal/audit` + middleware API : TOUTE mutation passe par `audit.Append(actor, action, target, params, result)` ; page « Vérifier la chaîne » ; head poussé au fleet (témoin tiers) | hub + fleet |
| **N12 intégrité agent** | Build info + SHA-256 du binaire ; l'agent self-check au démarrage et remonte `agent_hash` à CHAQUE heartbeat ; hub alerte si hash inconnu | internal/version + protocol |
| **N14 clé de secours** | Génération clé de site à l'installation (si absente) ; `ugctl key export --passphrase` (PKCS#8 + Argon2id + AES-GCM) ; **test de restauration guidé à l'installation** (wizard : « déchiffrez ce fichier témoin ») | internal/cryptoutil + hub |
| **N10 bus d'événements** | `internal/events` : emit(event) → file → notification_log ; canaux stub en J0 (log), email/webhook/Telegram branchés J9 | internal/events |

---

## 5. UI — pages & maquettes textuelles (vanilla JS, go:embed)

### Hub `central.<domaine>`

| Page | Contenu |
|---|---|
| **/login** | utilisateur local hub (admin opérateur) |
| **/hosts** | LA page capture : tableau (Friendly name, hostname, OS badge, groupe, agent v+auto-update, statut online/stale/offline, RTT, FW type badge) ; recherche, filtres, colonnes, tri |
| **/hosts/{id}** | onglets : Aperçu (télémétrie Chart.js 24 h, services) · Paquets (inventaire + MAJ dispo + bouton plan) · Firewall (type détecté, ruleset actuel, diff N2, appliquer avec wizard commit-confirm + compte à rebours, snapshots chiffrés + restaurer) · Actions (historique file) · Dérive (N3 : baseline vs actuel, Resynchroniser/Adopter) |
| **/firewall** | rulesets par groupe, diff en langage clair avant apply, break-glass N1 (rouge, double confirmation), tests prédictifs N6 |
| **/packages** | MAJ dispo par host/groupe, campagnes canari N8 (pilotes → pause → promouvoir), blacklist N9 |
| **/maintenance** | fenêtres par groupe |
| **/audit** | chaîne d'événements + bouton « Vérifier l'intégrité » + export signé |
| **/settings** | tokens enrollment, clés de site (versions, export scellé N14), SMTP, notifications N10, intégration fleet (URL, état, quota), **auth : FQDN verrouillé, SSO OIDC/SAML (off/optionnel/exclusif), MFA e-mail, sessions/lockouts, certificats PIV (liste, émettre, révoquer — SPEC §5.1.3)** |

```
┌───────────────────────────────────────────────────────────────┐
│ UnifiedGuard ▸ Hosts                              [search □]  │
├───────────────────────────────────────────────────────────────┤
│ 13 online · 1 stale · 0 offline        [+ Token enrollment]    │
├───────────────────────────────────────────────────────────────┤
│ ◉ v-dns-01   Debian 12   [nftables 1.0.9]  agent 0.3.1  RTT 3ms│
│ ◉ v-dns-02   Debian 12   [nftables 1.0.9]  agent 0.3.1  RTT 2ms│
│ ◐ p-ntb-02   AlmaLinux 9 [firewalld 1.2]   agent 0.3.1  stale │
└───────────────────────────────────────────────────────────────┘
```

### Fleet `global.unifiedguard.cloud`

| Page | Contenu |
|---|---|
| **/register · /login** | inscription (mail confirmation) ; **admin global seulement si @dpnac.fr** |
| **/orgs** | organisations de l'utilisateur, invitation membres |
| **/hubs** | centrales de l'org : domaine, plan (5/25/…), quota utilisé, last push, statut |
| **/hubs/{id}** | santé consolidée (hosts online/offline, alertes, head d'audit), blobs chiffrés (taille, jamais lisibles), bouton « changer d'offre », **certificats PIV : demander une révocation (serial) — servie au hub par PULL (SPEC §5.1.3)** |
| **/admin** (dpnac) | toutes les orgs, plans, audit fleet |

---

## 6. Jalons de développement

> Effort indicatif en sessions de travail (l'agent travaille en étapes committables ;
> Fabien valide via l'interface Bot puis pousse). Chaque jalon se termine par :
> `go test` + `golangci-lint` verts, doc/AVANCEMENT à jour, **prompts de recette** livrés.

| # | Jalon | Contenu | Effort | Critère de sortie (recette) |
|---|---|---|---|---|
| **J0** | Socle repo | go.mod, cmd×3 squelettes, internal/{protocol,cryptoutil,audit,store,events,version}, migrations hub 001+fleet 001 avec **audit chaîné**, Makefile (build/test/lint/migrate), golangci config, README | S | `make build lint test` verts ; migration up/down fonctionne ; audit append+verify testé |
| **J1** | Agent Linux — collecte | enroll CSR+mTLS, heartbeat+telemetry+inventaire dpkg/apt, **détection FW lecture seule** (nft/firewalld/ufw), self-hash N12, systemd unit, reconnect backoff, **install one-liner curl (script servi par le hub, paquet signé + manifest Ed25519, `--token=` argument → corps JSON)** | M | 1 VM Debian enrolls, remonte heartbeat+télémétrie+inventaire+type FW ; revocation cert = agent rejeté ; one-liner `curl …/install.sh \| bash -s -- --token=…` installe+enrolle en une commande |
| **J2** | Hub MVP | WS mTLS serveur, stockage, REST, UI /login + /hosts + /hosts/{id} (aperçu+télémétrie), audit branché partout, events stub, **auth hub : FQDN verrouillé + comptes e-mail double opt-in + MFA e-mail + Argon2id + rate-limit** | M | Dashboard live : host apparaît, télémétrie 24 h tracée, actions auditées, chaîne vérifiable ; login sans code MFA impossible ; 6ᵉ échec → backoff |
| **J3** | Interactif | ping applicatif + RTT affiché, file d'actions (offline → reconnexion), groupes CRUD, filtres/recherche | S | Host coupé : action en file → passe online → exécutée → résultat affiché ; RTT visible |
| **J4** | Firewall core | snapshots chiffrés (clé de site), apply runtime, **commit-confirm + rollback auto**, restauration snapshot, détection FW complète (3 backends) | L | Test mécanique : ruleset qui coupe le canal → rollback automatique < TTL ; snapshot restauré ; blobs chiffrés illisibles |
| **J5** | Paquets core | simulate/check/apply/verify (apt puis dnf), MAJ dispo, refus si dépendances cassées, override manuel audité | M | Plan simulé affiché avant apply ; MAJ réelle OK ; MAJ cassante refusée |
| **J6** | Maintenance & compliance | fenêtres par groupe, patch campaign basique, export CSV compliance, profils v1 (N4 light) | M | Campagne planifiée s'exécute dans la fenêtre ; CSV conforme |
| **J7** | Fleet SaaS | users/orgs/memberships, @dpnac.fr rule, mail double opt-in (SMTP), **MFA e-mail obligatoire + sessions/lockout**, enregistrement hub, push consolidation + blobs + head audit, quotas par PULL, UI fleet | L | 2 hubs de test fédérés ; quota 5 atteint = enrollment refusé ; admin non-@dpnac.fr impossible ; login sans code MFA impossible |
| **J8** | Agent Windows | cross-build, winget, Defender FW (statut/profils), service Windows + recovery, MSI WiX | L | VM Windows : enroll, heartbeat, inventaire winget, FW détecté |
| **J9** | Finitions vagues 1-3 | auto-update signé, notifications email/webhook (N10 complet), clé secours wizard (N14), diff clair (N2), dérive (N3), break-glass (N1), canari (N8), blacklist (N9), **MFA forte : TOTP + WebAuthn + SSO OIDC/SAML (hub et fleet, SPEC §5.1.2)** | L | Recette par feature (prompts dédiés) ; SSO exclusif bloque les comptes locaux ; TOTP accepté/refusé correctement ; WebAuthn refuse un autre domaine |
| **J10** | Durcissement & déploiement | compose final hub/fleet + Caddy TLS auto, hardening guide, backup/restore DB, rétention données, doc install 1-commande, e2e | M | `docker compose up -d` sur serveur vierge → centrale opérationnelle avec vrai certificat |

### Positionnement des vagues (IDEES.md) dans les jalons

- **Vague 1 (N5, N12, N14, N10)** → câblée J0, complétée J9.
- **Vague 2 (N2 → N3 → N1 → N6)** → J4 pose le socle ; features complètes en J9.
- **Vague 3 (N8, N9, N4, N15)** → J6 (N4 light), J9 (N8, N9), N15 post-J8 (feeds CVE).
- **Vague 4 (N7, N11, N13)** → après J10, priorisation séparée.
- **Vague 5 (N16 backup)** → **projet distinct** (repo `backup`), hors ce plan.

---

## 7. Risques & pièges identifiés d'avance

| Risque | Parade |
|---|---|
| Rollback FW qui échoue aussi (règles corrompues) | Snapshot runtime TOUJOURS testé par rechargement à blanc avant apply ; break-glass N1 en dernier recours |
| Traduction canonique → backend imparfaite (règles exotiques) | Règles non traduisibles = « avancée — non analysée » affichée, jamais masquée ; diff honnête |
| mTLS + CA interne : clock skew | tolérance ±2 min, NTP requis documenté |
| WebSocket derrière Caddy : timeouts proxys | heartbeat 30 s < timeout proxys ; config Caddy livrée |
| Quota vs enrollment simultané | transaction PG sérialisable au comptage |
| Perte clé de site = blobs indéchiffrables | N14 : export scellé + test de restauration OBLIGATOIRE à l'installation |
| Fleet devient un SPOF pour les centrales | NON : les hubs fonctionnent 100 % offline (fédération = reporting) ; seul le quota est pullé avec cache local |

## 8. Livrables par jalon (rappel)

1. Code + tests (`go test ./...` vert, lint vert)
2. `AVANCEMENT.md` à jour + doc technique du jalon
3. **Prompts de recette** pour Fabien (validation manuelle guidée)
4. Le cas échéant : compose/`.env.example` à jour

*L'agent committe/pousse (accord Fabien 02/11 soir). Historique conventionnel, commits de taille humaine.*