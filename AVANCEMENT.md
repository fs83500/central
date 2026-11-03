# AVANCEMENT.md — UnifiedGuard.cloud

## Statut : 🎉 BÊTA 0.1 LIVRÉE (03/11 soir) — J4 + compose + binaires, E2E TLS complet validé

Dernière mise à jour : 2026-11-03 ~16h32

## Tâche en cours
- **BÊTA 0.1 livrée** : archive `unifiedguard-beta-0.1.tar.gz` à la racine du projet
  (sha256 `8ccd3a69…`, ~9,8 Mo) — code source complet + `docker-compose.yml` (db+hub) +
  `Dockerfile` (build Go multi-stage, binaires déjà construits inclus dans `bin/`) +
  `README-BETA.md` + `run-beta.sh` (lancement sans Docker) + `.env.example`.
- E2E bêta validé dans le sandbox : DB vierge → migrations auto 001→007 → bootstrap admin →
  login+MFA (code dans les logs, `HUB_MFA_LOG_BETA=1`) → enrollment token → agent natif
  enrôlé en https self-signed (`UG_ENROLL_INSECURE=1`) → **WS mTLS** (client cert + CA
  vérifiée) → heartbeat → hôte `online` → ping RTT → action inventory → audit chaîné OK.
- Recette restante chez Fabien : `docker compose up -d --build` sur une vraie machine,
  J4 confirm/rollback sur hôte avec pare-feu réel, preview UI.

## Livraison bêta (03/11 soir) ✅
- **c1d5f4d** : docker-compose.yml (postgres 17 + hub, migrations auto au boot,
  volumes `ug_db_data`/`ug_hub_data`), Dockerfile multi-stage (build → image finale
  debian-slim, envs via compose), `.env.example`, `README-BETA.md` (démarrage,
  enrollment agent, systemd, limites bêta), `run-beta.sh` (mode sans Docker).
- **Migrations unifiées** : SQL déplacé vers `internal/migrations/sql/hub/` (go:embed,
  appliquées automatiquement au boot sauf `HUB_MIGRATIONS=off`), `migrations/hub/`
  garde un README pointeur (Makefile psql mis à jour).
- **bin/ construits avec version** (hub 12 Mo, agent 6,6 Mo, fleet 5,8 Mo, ldflags
  commit+date) — inclus dans l'archive pour un `run-beta.sh` sans compilation Go.
- gitignore : `bin/`, `/data/`, `*.tar.gz` (artefacts de livraison hors git).

## J4 — Pare-feu commit-confirm (03/11 après-midi) ✅ code / 🔶 recette hôte réel
Machine à états §3.5 sur l'AGENT (autorité du compte à rebours) :
- **Snapshot → scellement → apply runtime → compte à rebours → confirm OU rollback**.
- Le snapshot du ruleset runtime est scellé avec la **clé publique du site**
  (AES-256-GCM + RSA-OAEP, `internal/cryptoutil/sitekey.go` : clé de site générée par
  la centrale, clé privée JAMAIS envoyée au global) puis remonté au hub (`fw_snapshots`,
  stockage opaque — le hub ne peut pas lire le ruleset).
- L'agent applique en mode RUNTIME uniquement, ouvre une session live, démarre son
  compte à rebours (défaut 300 s, max 3600). **Hub mort / WS coupé / timeout → rollback
  immédiat** (fwRollbackAllOnDisconnect sur toute perte de canal). Une seule session live
  par agent. Payload `FWApply` : SessionID, FWType, TTLSec, Rules, SitePubKey.
- `agent/runtime/fwcommit.go` : startFWApply (bloquant), fwConfirm, fwRollback,
  seams platformSnapshot/platformRestore/platformApply (indirection pour tests + hosts
  sans CAP_NET_ADMIN). Tests `fwcommit_test.go` (fake platform) : snapshot scellé
  récupérable avec la clé de site, rejet payload incomplet, rollback au timeout,
  confirm ferme la session, rollback sur déconnexion.
- Hub `hub/server/fw.go` : SiteKey() lazy (table site_keys), HandleHostFWApply
  (valide rules/TTL/hosts.fw_type, 409 si session pending), HandleHostFWConfirm,
  HandleHostFWSessions, HandleHostFWSnapshots, HandleHostFWSnapshotDownload,
  jumeaux GET dev. `fw_apply` direct via POST /actions interdit (whitelist élargie
  mais HandleHostActionCreate ne l'accepte pas — passe uniquement par /fw/apply).
- **Race corrigée en E2E** : la ligne `fw_sessions` est insérée AVANT l'enqueue de
  l'action (action_id nullable) — l'agent peut échouer en quelques ms et
  completeFWSession doit toujours trouver sa ligne quand l'action_result arrive.
- Migration 007 : `site_keys`, `fw_snapshots` (ciphertext+envelope+sha256, opaque),
  `fw_sessions` (états pending_confirm|confirmed|rolled_back|failed + detail JSONB).
- UI : panneau « Pare-feu — commit-confirm » sur host.html (type détecté, saisie
  règles, TTL, Appliquer/Confirmer, compte à rebours, timeline sessions).
- E2E (conteneur dev, agent fw_type forcé `AGENT_FORCE_FW_TYPE=nftables`) :
  apply → 200 {action_id, session_id, ttl_s} → livraison → échec snapshot
  (`nft` absent du sandbox, attendu) → action failed → session `failed` +
  detail → API /fw/sessions reflète l'état. Le vrai pare-feu se teste sur hôte cible.

## J3 — Ping applicatif + file d'actions (03/11 matin)

### Livré
- **Ping applicatif** (SPEC §2.3, jamais ICMP) : le hub envoie `ping` sur le
  WebSocket OUVERT PAR L'AGENT, mesure le RTT côté hub (pong.ref → waitPong),
  10 s de timeout, résultat persisté `hosts.rtt_ms` → visible dashboard.
  Agent hors-ligne → 409 (le hub n'initie JAMAIS de connexion — règle d'or).
- **File d'actions** (idée n°2 du 02/11) : `actions` + `action_events`
  (migration 006). L'opérateur empile une action (`inventory_refresh`,
  `pkg_list` — whitelist J3). Hôte hors-ligne → `pending` ; à la
  reconnexion le hub livre TOUT le pending sur le socket de l'agent →
  `delivered` → l'agent exécute et répond `action_result` → `done/failed`.
  Garde d'ownership : un agent ne peut clore que SES actions.
- **API** : `POST /api/v1/hosts/{id}/ping`, `POST|GET /api/v1/hosts/{id}/actions`,
  `GET /api/v1/hosts/{id}/actions` (50 dernières) + jumeaux GET dev
  (`/dev/hosts/{id}/ping`, `/dev/hosts/{id}/actions`) car le proxy preview
  ne forward que GET. Tout est audité (N5) : host.ping, action.create.
- **Agent** : répond `pong{ref}` au ping ; exécute `inventory_refresh`/`pkg_list`
  (collecteur existant) et renvoie l'inventaire en résultat ; refuse
  silencieusement les types inconnus (fwd compat J4/J5).
- **UI** : panneau « Actions distantes » sur la page hôte — bouton Ping
  (affiche RTT), bouton Rafraîchir l'inventaire (empile l'action, message
  « livrée à sa reconnexion » si hors-ligne), tableau statut
  pending/delivered/done/failed + horodatages.
- **Registre de connexions** (`registry.go`) : map agentID → conn live,
  writer goroutine par agent (gorilla interdit les writes concurrents),
  file d'envoi 64, remplacement last-wins à la reconnexion.

### Bug critique trouvé et corrigé en route
- **WS 500 silencieux derrière le wrapper preview** : `prefixedRedirect`
  (strip du prefix HUB_UI_PREFIX) n'implémentait pas `http.Hijacker` →
  gorilla ne pouvait pas hijacker la connexion → 500 sans log. Le hub dev
  (= toute config avec HUB_UI_PREFIX) n'aurait JAMAIS pu servir un agent.
  Fix : Hijack + Flush forwardés (cmd/hub/prefixed_redirect.go). Prod
  (prefix vide) non concernée mais le bug valait pour tous les dev/review.

### Infra sandbox (03/11 matin, après redémarrage)
- PostgreSQL retrouvé dans `/tmp/pgdata-test`, relancé sur **port 55433**
  (55432 occupé par le cluster bot) — DSN dev mis à jour dans
  scripts/hub-dev.sh. Landlock interdit /var/run en écriture → toujours
  `-c unix_socket_directories=/tmp` au pg_ctl.
- E2E réel validé : enrollment → agent mTLS WS → ping RTT 0 ms → action
  empilée agent arrêté → relance agent → livraison auto → done → visible UI.

### Tests
- 5 nouveaux (`actions_test.go`) : ping offline 409, ping live RTT persisté,
  file d'actions livrée à la reconnexion (agent réel + TLS réel), ownership,
  whitelist. Suite complète verte (hub/server, auth, audit, version).

## Pont de session preview — 02/11 ~21h (retour « après le login : JSON unauthenticated »)

### Cause racine (3ᵉ découverte, la bonne)
Le proxy preview ne strippe pas seulement les POST : il **isole les cookies
dans les 2 sens**. Preuve en base : la session Android de Fabien (20:53:42,
audit seq 120) a été **créée** mais **jamais re-vue** — ni `Set-Cookie` ne
repart vers le navigateur, ni `Cookie` ne revient vers le hub. Comportement
sain côté plateforme (une preview ne doit pas toucher les cookies du domaine
partagé bot.dpnac.cloud), fatal pour notre session par cookie.

### Solution livrée : session dans l'URL (dev-only, pont one-shot)
- **dev-login** réussit serveur-côté → émet un **token pont one-shot** (32 o
  aléatoires, en mémoire process, TTL 90 s, usage unique) → redirect
  `hosts?t=<token>`.
- **session.js** (nouveau) : au chargement, échange `?t=` contre le token de
  session (`GET /dev/session/redeem` → `{ok, st}`), le stocke en
  **sessionStorage**, purge l'URL, et le porte sur **chaque appel API** via
  `ugApi()` (`?st=…`) ; toutes les pages JS attendent `ugBridgeReady` avant
  le premier fetch ; hook logout purger `ug-st`.
- **RequireUser** accepte `?st=` en dev seulement (`acceptSessionParam`) ;
  **ClearSessionCookie** révoque aussi via `?st=` (logout preview).
- **Pages HTML dégatées en dev uniquement** (elles ne portent aucune donnée :
  les tableaux sont remplis par les API gated ; en prod le gate reste —
  vérifié par simu `HUB_DEV` vide → 401 sur /hosts sans session).
- 401 du gate → vrai `application/json` (plus de text/plain brut à l'écran).

### Preuves (recette E2E sans cookie du tout)
- dev-login → `303 /preview/codex/8802/hosts?t=<64 hex>` ; redeem → `{ok,st}` ;
  rejeu du one-time → **401** (usage unique) ; APIs `?st=` → 200 ; mauvais
  st → 401 ; logout `?st=` → révocation (me → 401 ensuite).
- `go test ./...` ok ; go vet ok ; gofmt ok ; node --check 7 fichiers JS ok.
- Simu prod (HUB_DEV vide) : /hosts sans session → 401, /login → 200.

## Correctif CSP — 02/11 soir (2ᵉ retour Fabien : « toujours pas, thème KO »)

### Cause racine (la pièce manquante des 2 tentatives précédentes)
Le proxy preview de la plateforme Bot applique une **CSP stricte** :
`script-src 'self'; style-src 'self'` — **sans `'unsafe-inline'`**. Or les
5 pages du dashboard avaient TOUT leur JavaScript dans des `<script>` inline
(+ attributs `style=""` inline). Résultat dans le Chrome de Fabien :
- **Aucun script ne s'exécutait** (blocage CSP silencieux) → le handler du
  formulaire login ne s'installait jamais (submit natif → recharge de page),
  le sélecteur de thème ne réagissait pas, l'encart dev-login était invisible
  — symptômes exacts « toujours pas » + « le thème ne fonctionne pas ».
- C'est aussi pourquoi les correctifs 5e2b19b (fetch relatifs, dev-login)
  n'ont rien changé : ils vivaient dans des scripts inline eux aussi bloqués.

### Correctifs livrés (zéro inline sur les 5 pages)
- **Anti-FOUC externalisé** : `static/theme-boot.js` (applique le thème
  sauvegardé avant première peinture).
- **1 fichier JS par page** : `login.js`, `hosts.js`, `host.js`, `audit.js`,
  `enroll.js` — extraction à l'identique de la logique inline (login 2 étapes,
  MFA dev, dev-login GET 1-clic, fallback GET sur 405, KPIs, sparklines,
  tableaux, audit).
- **Classes CSS de remplacement** pour tous les `style=""` inline
  (`brand-acc`, `logout-btn`, `mt12`, `mb8`, `mfa-code`, `verify-panel`,
  `verify-sub`, `spark`, `statut`, `chart-title`, `leg-acc/ok/grid`,
  `oneliner`, `preview-note`) — `style-src 'self'` bloque aussi les attributs.
- Les pages n'ont plus QUE des `<script src="static/….js">` externes —
  conformes à `script-src 'self'`.

### Preuves
- `grep` : 0 `<script>` inline, 0 `style=""` sur les 5 pages.
- `node --check` : les 7 fichiers JS passent la vérification de syntaxe.
- E2E préfixé : `dev-login` → `303 Location: /preview/codex/8802/hosts` +
  cookie ; `GET hosts` contient `static/hosts.js` ; `GET static/hosts.js`
  et `static/theme-boot.js` → 200.
- POST login direct mauvais mdp → `401 {"error":"invalid credentials"}` JSON.
- `go test ./...` : ok partout.

### Recette preview (pour Fabien — la 3ᵉ, avec JS enfin exécutable)
1. Ouvrir https://bot.dpnac.cloud/preview/codex/8802/login — **Ctrl+F5** (purger
   le cache : l'ancienne page aux scripts bloqués peut être en cache).
2. L'encart « Preview sandbox : connexion directe en un clic (GET) » doit
   maintenant être VISIBLE.
3. Renseigner `admin@test.fr` / `S3cret!pass` → cliquer le lien direct →
   atterrir sur `/hosts`.
4. Le sélecteur de thème (topbar) doit réagir immédiatement.

## Correctif login preview — 02/11 soir (1ᵉʳ retour : échec connexion)

### Diagnostic (3 causes indépendantes)
1. **Bug UI (cause principale côté hub)** : les 2 `fetch` de `login.html`
   (`/api/v1/auth/login`, `/api/v1/auth/mfa`) étaient en chemin ABSOLU — le fix
   `64af7a4` avait corrigé HTML/CSS/nav mais raté les 2 fetch JS. Sous le préfixe
   preview, le POST sortait du proxy → 405/HTML → message trompeur
   « Identifiants invalides » alors que la requête n'atteignait jamais le hub.
2. **Bloqueur infrastructure (proxy preview Bot)** : le proxy ne proxifie que
   GET/HEAD — le 405 (`allow: GET, HEAD`) est émis par SON routeur AVANT tout
   check d'auth (sinon les POST non authentifiés seraient 302 vers `/auth/login`
   comme les GET). **Le POST ne passera donc JAMAIS via preview, même authentifié.**
3. **Erreurs serveur non conformes** : tous les `http.Error` envoyaient des corps
   JSON en `Content-Type: text/plain` — parsing fragile, messages génériques.

### Correctifs livrés
- **`login.html`** : fetch RELATIFS (`api/v1/auth/login|/mfa`) ; `post()` distingue
  échec réseau / réponse non-JSON / 405 proxy ; `apiErr()` affiche un message
  distinct par classe (réseau, 405 preview, 429 throttle, 401 login vs MFA, 5xx).
- **`/dev-login` (dev uniquement, gated `HUB_DEV=1`)** : login 1-clic en GET pour
  contourner le proxy preview GET-only — vérifie password + throttle, émet ET
  consomme le code MFA dev côté serveur, set le cookie session, redirect `hosts`.
  Bouton visible sur la page login UNIQUEMENT sous préfixe `/preview/`; échecs →
  redirect `login?err=<raison>` affiché dans l'encart erreur. MAIS dev seulement
  — la route renvoie 404 hors DevMode.
- **Jumeaux GET dev** pour les actions non-GET bloquées par le proxy preview :
  `GET /dev/enroll/tokens?label=` (création token), `GET /dev/me/theme?theme=`
  (sélecteur thème) — mêmes règles auth/audit/validation que les POST/PATCH ;
  fallback automatique côté UI quand le POST/PATCH renvoie 405.
- **Re-préfixage des redirects** : le middleware dev strippe `/preview/.../` en
  entrée mais Go résout les `Location` relatives contre le chemin STRIPPÉ → le
  navigateur sortait du préfixe (bug prouvé : `Location: /hosts` au lieu de
  `/preview/codex/8802/hosts`). `prefixedRedirect` ré-écrit maintenant tout
  `Location` absolue en lui rendant le préfixe.
- **`apiError()` serveur** : remplace tous les `http.Error` JSON → vrai
  `Content-Type: application/json` + code HTTP, sur TOUTES les routes dashboard.
- **`HandleLogout`** : double révocation session supprimée (ClearSessionCookie
  fait déjà tout).

### Preuves (curl)
- POST login mauvais mdp → `401 {"error":"invalid credentials"}` en JSON.
- 6 échecs consécutifs → `401×5 puis 429` (throttle intact).
- `dev-login?…&password=S3cret!pass` préfixé → `303 Location: /preview/codex/8802/hosts` + `Set-Cookie: ug_session=…` → `GET hosts` 200.
- mauvais mdp → `303 /preview/codex/8802/login?err=invalid+credentials`.
- `GET /dev/enroll/tokens?label=preview` → `{"token":"ug-…"}` ; `GET /dev/me/theme?theme=dark` → `{"ok":true}`.
- Tests Go : `ok` partout (`hub/auth`, `hub/server`, `internal/audit`, `internal/version`).

### Recette preview (pour Fabien)
1. Ouvrir le lien preview → page login → l'encart « Preview sandbox : POST
   bloqués — connexion directe en un clic (GET) » est visible.
2. Renseigner `admin@test.fr` / `S3cret!pass` → cliquer le lien de connexion
   directe → atterrit sur `/hosts` connecté.
3. Thème, hosts, détail hôte, audit (lecture) fonctionnent ; création de token
   d'enrollment et changement de thème passent par les fallbacks GET.
4. Le mot de passe passe dans l'URL du lien direct (compte dev uniquement).

## J2 livré le 02/11 soir — commit 3511b37 (tests verts, E2E OK, poussé origin/main)
- **Télémétrie partitionnée** : migration `005_telemetry_partitions.sql` (une seule
  transaction, idempotente, zéro perte) — table `telemetry PARTITION BY RANGE (ts)`
  mensuelle, PK `(host_id, ts)`, index `(host_id, ts DESC)`, backfill fenêtre 90 j,
  `ug_telemetry_retention(months)` purge > 90 j (boucle quotidienne hub),
  `EnsureTelemetryPartitions()` au boot (mois courant + suivant).
  Recette : RUN1/RUN2 idempotent, insert OK, purge OK, row -120 j droppée avec la legacy.
- **Preview cliquable dev** (demande Fabien « donne-moi les liens avec les comptes ») :
  - `HUB_DEV_UI_LISTEN` = 2ᵉ listener HTTP pour l'UI/dashboard (le port principal
    garde le mTLS agents `:8801`) → le proxy preview Bot ne proxifie que du HTTP.
  - **Code MFA dev affiché dans l'UI** (`dev_mfa_code` dans la réponse login en
    DevMode + encart sur l'étape MFA) — SMTP réel = J9.
  - **CA persistant** : `HUB_CA_DIR` + `cryptoutil.LoadOrCreateCA()` — l'agent garde
    son identité entre les restarts (avant : ré-enrollment à chaque restart).
  - `scripts/hub-dev.sh` : lanceur dev du hub (preview Bot, port 8802 UI).
  - URL : **https://bot.dpnac.cloud/preview/codex/8802/login** — admin@test.fr /
    S3cret!pass, code MFA affiché à l'écran (dev) ; hosts, détail hôte (courbes),
    enroll, audit vérifiés E2E (2 runs Puppeteer verts).

## Thème clair/sombre/auto — livré (02/11 soir, demande Fabien)
- **3 modes** : ☀ clair / ◐ auto (suit l'OS via `prefers-color-scheme`) / ☾ sombre,
  sélecteur dans la topbar des 5 pages (`data-set-theme`).
- **Persistance double** : `localStorage` (immédiate, machine) **ET profil utilisateur**
  (`hub_users.theme`, colonne `003`, CHECK auto/light/dark) via `PATCH /api/v1/me/theme`
  (validé côté serveur, 400 si invalide). Sur machine partagée, le thème du profil
  serveur prime et re-synchronise le localStorage (`initThemeFromServer`).
- **Anti-FOUC** : script inline dans chaque `<head>` applique le thème sauvegardé
  avant la première peinture (pas de flash blanc en sombre).
- **CSS par variables** (`app.css`) : palette claire + sombre, overrides manuels
  `data-theme="light|dark"` prioritaires sur la media query. Bug corrigé : le sélecteur
  `:root` nu dans la media query dark écrasait le choix manuel clair sur OS sombre.
- **E2E puppeteer (DOM réel Chromium)** : auto suit l'OS ✔, manuel surpasse l'OS ✔,
  persistance reload ✔, sync profil machine partagée ✔ (`ASSERT-SERVER-SYNC ok:true`).
  Scripts conservés `.shots/theme-e2e.js` + `theme-profile-e2e.js` (hors git, à
  reconvertir en test Go si besoin).

## Correctifs audit chaîne N5 découverts en testant (02/11 soir)
- **Fork lexicographique** : le trigger chaînait sur `MAX(hash)` — maximum TEXT
  lexicographique, PAS le dernier row. Dès qu'un hash triait plus bas qu'un ancien
  (vérifié en pratique : seq 3 < seq 2 → seq 4 re-chaînait sur seq 2 = FOURCHE,
  chaîne cassée silencieusement). Fix : sous-SELECT scalaire `(SELECT hash …
  ORDER BY seq DESC LIMIT 1)` + migration **004** pour les bases déjà déployées.
- **Chaîne vide** : le premier `SELECT INTO` sans ligne laissait `v_prev=NULL`
  (COALESCE jamais appliqué) → `prev_hash=NULL` → violation NOT NULL, INSERT
  impossible sur table vide après TRUNCATE. Fixé pareil (004 + 001).
- **ts zéro Go** : `PGStore.Append` insérait `time.Time{}` → `0001-01-01` en base
  quand le code appelant ne remplit pas TS. Fix : `COALESCE($1, now())`.
- **Test pgchain** laissait la base polluée (falsification non annulée) →
  `t.Cleanup(TRUNCATE)` ajouté.
- Vérifs : 40 events consécutifs → 0 fourche, `ug_audit_verify()`=true,
  `/api/v1/audit/verify` ok, e2e 5 logins complets chaîne intacte.

## Maquettes UI — livrées (02/11 soir)
- **6 pages HTML/CSS statiques** dans `docs/maquettes/` : données fictives, zéro JS,
  servables par `make preview-maquettes` (port 8799). Vue cible de J2 — le dashboard
  réel (go:embed, données live) implémentera ces pages : index, hub-login, hub-hosts
  (dashboard), hub-host (détail + télémétrie + audit), hub-enroll, fleet-hubs (SaaS).
- Documentées dans PLAN-ATTAQUE.md **§5.4 Vues UI (maquettes)**.
- Le thème CSS (chips ok/warn/crit/info/off, topbar, sidenav) servira de base au
  dashboard réel.
- **Règle confidentialité commerciale (02/11, Fabien)** : revenus/MRR/facturation
  visibles UNIQUEMENT par l'admin global `@dpnac.fr` — jamais par les orgs, MSP ni
  membres (owner/admin/viewer). Gravée dans SPEC §5.2 (note rôles) + §7 (détail,
  API 403 audité), appliquée dans la maquette fleet-hubs (carte MRR chip « dpnac »,
  nav « Offres » marquée dpnac). Les vues org ne montrent que quota/plan, pas de prix.
- **Makefile corrigé** : `test-pg` n'utilise plus le flag `-dsn` inexistant ; il exporte
  `UG_TEST_DSN` et sépare les bases — run 1 : tout sauf `internal/audit` sur
  `ug_hub_test`, run 2 : `internal/audit` seul sur `ug_hub_audit` (TRUNCATE audit ne
  collide plus avec les tests hub/server). Nouvelle cible `preview-maquettes`.

## J1 — livré (02/11 soir)
- **Enrollment complet (PLAN §3.1, SPEC §6.1)** : token `ug-<32hex>` (hash SHA-256 stocké,
  usage unique, TTL 24 h, jamais en URL ni dans les logs) → agent génère clé ECDSA P-256 +
  CSR → hub vérifie token, contrôle le **quota** (402 Payment Required, défaut 5 en attendant
  les abonnements fleet), signe le certificat (CA interne ECDSA, CN=UUID agent), crée le
  host `offline`, audite `host.enroll` (N5). Consommation atomique du token (anti-rejeu
  en course). `NewEnrollToken()` côté hub (helper dev `HUB_DEV_TOKEN`, J2 → dashboard).
- **Runtime agent (PLAN §3.2)** : boucle WebSocket **agent initiateur** (règle d'or SPEC
  §2.1), TLS avec la CA du hub (mTLS client cert), heartbeat 30 s immédiat à la connexion,
  télémétrie 5 min, inventaire 24 h, reconnexion backoff exponentiel 1 s→60 s + jitter,
  ping/pong ref + self-hash N12 dans le heartbeat. Plateforme Linux : CPU/mémoire/charge/
  uptime/disques/net/processes via /proc et statfs.
- **Hub WS** : `/agent/v1/ws` mTLS (X-Agent-ID du proxy vérifié OU certificat client direct),
  host révoqué → 403 + audit `ws.denied`. Messages gérés : heartbeat (update hosts),
  télémétrie (insert table `telemetry`), inventaire (audit du compte, stockage complet J5),
  pong. Host online/offline + last_seen maintenus.
- **CLI agent** : `unifiedguard-agent version | enroll --hub --token | run`.
- **Tests e2e contre PostgreSQL réel (UG_TEST_DSN)** : TestEnrollFlow (token→CSR→200→rejeu
  403→host en base→audit chaîné→token invalide audité) + TestAgentWebSocketHeartbeat (vrai
  runtime agent → hub TLS mTLS → host passe online, last_seen en base). go vet OK,
  golangci-lint **0 issue**, gofmt propre.
- **Migration hub 002** : `hosts`, `host_groups`, `telemetry`, `enroll_tokens`.

## J0 — livré (02/11)

- **Agents servis UNIQUEMENT par la centrale (décision 02/11, SPEC §8)** : le
  global n'héberge aucun binaire/paquet agent téléchargeable — un site reste
  autonome pour installer (règle d'or + indépendance du SaaS). Appro du hub :
  paquets embarqués dans l'image Docker (version liée) + rafraîchissement
  optionnel depuis le dépôt éditeur dpnac (hub initiateur, manifest signé
  Ed25519) + upload manuel (air-gap N11).
- **Install agent one-liner curl DÉCIDÉ (02/11, SPEC §8 + plan §3.1.1)** :
  `curl -fsSL https://central.<domaine>/install.sh | bash -s -- --token=ug-<uuid>`
  — script servi par la CENTRALE (règle d'or OK : réponse à un GET), paquet
  .deb/.rpm signé + manifest Ed25519 vérifié AVANT installation, enrollment
  ensuite (token dans corps JSON), `systemctl enable --now`. Token usage
  unique + TTL 24 h. Alternative « parano » (télécharger+lire) documentée.
  Équivalent PowerShell prévu J8. Intégré au jalon J1.
- **Audit chaîné (N5) double vérification** : trigger PostgreSQL `ug_audit_hash` +
  `ug_audit_verify()` côté DB, ET vérificateur Go **indépendant** `VerifyChainPG`
  (forme canonique jsonb reproduite en Go : clés triées par longueur puis binaire,
  espacement `": "`, µs fixes). Smoke test hub : chaîne vide ✅, chaîne saine ✅,
  falsification détectée ✅ (`/api/v1/audit/verify` → `ok:false`).
- **3 bugs corrigés en route** : (1) flag test `-dsn` cassait `go test ./...` sur les
  autres packages → déplacé en TestMain + variable d'env `UG_TEST_DSN` ;
  (2) `Append` ne renvoyait pas le `ts` généré par la DB (time zéro → hash Go ≠ DB) ;
  (3) `params` vide insérait SQL `NULL` au lieu de `{}` → COALESCE + défaut `[]byte("{}")`.
- **Migration hub 001** : `audit_events` + trigger chaîné + `ug_audit_verify()`.
- **Migration fleet 001** : `users` (Argon2id, admin global @dpnac.fr).
- **Binaires squelettes** : `agent` (version + self-hash N12), `hub` (:8080,
  `/api/v1/ping`, `/api/v1/audit/verify`, migrations auto), `fleet` (:8081).
- **Qualité** : `go vet` OK, `golangci-lint` **0 issue**, `go test ./...` OK contre
  PostgreSQL réel (port 55432, détection falsification incluse).
- **Makefile** : `build` (ldflags version), `migrate-hub`, `migrate-fleet`, `run-hub`.

## Business / positionnement (02/11 soir)
- **Grille tarifaire + scénarios CA intégrés à la SPEC** (commit 10649a1, poussé) :
  Starter 15 €/mois → Platinum 300 €/mois par centrale, annual −17 %, options
  (backup +20 %, support premium, onboarding). CA : An1 ~25-35 k€ → An3 ~300-500 k€.
- **Angle NIS2 posé (SPEC §15, N17-N19 dans IDEES/ROADMAP)** : UnifiedGuard vendu comme
  brique technique de conformité NIS2 (patching, FW, audit chaîné infalsifiable,
  rapport 1 clic) via MSP/conseil — pas comme « un RMM de plus ». Module premium
  +39/+49 € HT/mois, pack conformité ~990 €. N17-N19 en Vague 6, statut ⏳ proposition
  (à faire valider par Fabien).

### Option « Conformité NIS2 » (02/11 soir, SPEC §7.1 + §15.4)
- DÉCISION : le module conformité est une **OPTION PAR CENTRALE** (+39 € HT/mois
  Starter→Silver, +49 € Gold/Platinum). Frontière : « le socle ENREGISTRE
  (audit chaîné N5 dans tous les plans), l'option PROUVE » (N17 rapport signé,
  N18 scoring, N19 dérogations, consolidé multi-centrales, veille).
- Mécanique : `hubs.options` jsonb (fleet migration 003) servi au hub par PULL ;
  gate `/api/v1/nis2/*` (absente → 404 + upgrade UI). SKU refactable par les MSP.

## Fait (suite)
- **CORS & reverse proxy (03/11, SPEC §6.2bis)** : same-origin strict par défaut (UI+API même
  binaire/origine, zéro header CORS) ; jamais `Access-Control-Allow-Origin: *` ; filtre
  Origin lié au FQDN verrouillé ; `TRUSTED_PROXIES` pour les X-Forwarded-* (anti-usurpation
  IP pour le rate-limit) ; option `CORS_ALLOWED_ORIGINS` liste blanche OFF par défaut ;
  snippet Caddyfile + Nginx livré dans `deploy/` (timeouts WS > heartbeat 30 s).
- **Re-auth actions critiques — LISTE ARRÊTÉE (03/11)** : break-glass (N1), gestion des clés
  de site (N14), création de tokens enrollment. PAS de re-auth pour le FW apply (protégé
  par le commit-confirm §3.5).
- **MFA forte optionnelle VALIDÉE (03/11, SPEC §5.1.2)** : TOTP + WebAuthn (clé physique)
  + SSO pour chaque compte hub/fleet, en plus de la MFA e-mail de base. Ordre conseillé :
  WebAuthn > TOTP > e-mail. Codes de secours, écran de choix du facteur, procédure de
  récupération anti-hijack (admin + mail + délai 24 h). Livrés J9.
- **Clé USB à certificat (SPEC §5.1.3, 03/11)** : OUI avec une clé à puce **PIV**
  (YubiKey/Nitrokey — clé privée générée dans la puce, non exportable, X.509 installé
  dessus) → option « mTLS utilisateur / PKI d'entreprise » post-J9 (CA utilisateurs dédiée
  + CRL, mapping certificat→compte) ; utile aussi pour auth API/scripts. WebAuthn reste le
  facteur principal (anti-phishing par domaine que PIV n'a PAS). Un `.p12` sur clé USB de
  stockage = documenté mais déconseillé (clé copiable = faux facteur matériel).
- **Révocation PIV via centrale ET global (03/11)** : centrale = révocation IMMÉDIATE
  (CRL locale signée, re-auth + audit) ; global = **enregistre l'ordre**, le hub l'applique
  à son PULL suivant (≤ 5 min, respect règle d'or §2.1) puis confirme par push fédération.
  Tables : hub `cert_registry` + `pending_pull` (migration 007), fleet `revocation_orders`
  (migration 004). revoked_at/revoked_by/revoked_via tracé dans les DEUX chaînes d'audit.
- **Global : double opt-in confirmé obligatoire** (lien usage unique TTL court, hash Argon2id,
  aucun compte actif sans réception mail).
- **PLAN D'ATTAQUE livré (02/11)** : monorepo Go (cmd agent/hub/fleet + internal protocol/
  cryptoutil/audit/store/events/version), migrations hub 001-008 (audit chaîné en 001,
  clé publique de site en DB/privée en volume, file d'actions, FW commit-confirm, paquets,
  maintenance, fédération+quota PULL) + fleet 001-005 (users/orgs/memberships @dpnac.fr,
  hubs, blobs chiffrés, témoins d'audit), protocole WS mTLS v1 (enrollment CSR, heartbeat,
  ping applicatif, action/ack, fw_confirm), 10 jalons J0→J10 avec critères de sortie et
  prompts de recette, risques/parades, vagues 1-5 positionnées.
- **Clarification poll/ping (02/11, corrigée)** : la centrale PEUT poller/pinger l'agent
  UNIQUEMENT en applicatif (message « ping » sur le canal WebSocket déjà ouvert PAR L'AGENT,
  RTT mesuré). **PAS de ping ICMP** (décision Fabien) : diagnostic offline via last_seen +
  erreurs du canal + watchdog systemd/Windows qui redémarre l'agent ; jamais de connexion
  directe vers un port du device. Intégrée SPEC.md §2.3.

## Fait
- Besoin reformulé et validé : architecture 3 niveaux (agents Linux+Windows → centrales locales
  docker-compose → console globale SaaS), paquets/firewalls/télémétrie, chiffrement partout,
  abonnements 5/25/50/100/250 devices.
- Idées fondatrices 1-10 ✅ (dont rollback FW commit-confirm, détection type FW, sauvegardes
  chiffrées par clé de site, paquets sans casser les dépendances).
- **N1-N15 toutes validées le 02/11** (« 15 très bonnes idées ») : break-glass, diff clair,
  dérive, profils versionnés, audit chaîné, connectivité prédictive, repo cache, canari,
  blacklist versions, notifications, air-gap, intégrité agent, automatisation, clé de secours,
  CVE par sévérité. Détails : `docs/IDEES.md`.
- **N16 backup ✅ « à terme »** (recadré 02/11 soir) : la plateforme « type UrBackup » sera
  **SÉPARÉE du socle gestion** (séparation des services pour la sécurité) — socle
  `backup.<domaine-client>`, agents/clés/compose distincts, chunks CDC dédup zstd AES-256-GCM,
  même règle d'or des flux. **Projet distinct à créer** (repo `backup`) — hors périmètre du
  repo central. UrBackup = cible fonctionnelle uniquement.
- Docs livrés : `AGENTS.md`, `AVANCEMENT.md`, `docs/SPEC.md` (v0.3 — toutes questions
  tranchées, §2.3 ping applicatif), `docs/TECHNO.md` (stack validée, tableau explicatif),
  `docs/PLAN-ATTAQUE.md` (repo, schémas DB, protocole v1, UI, jalons J0-J10),
  `docs/ROADMAP.md` (fondatrices + N1-N16 + vagues 1-5), `docs/IDEES.md` (N1-N16 détaillées).
- Nom de marque : **unifiedguard.cloud**.

## Reste à faire
- [x] **J1 — agent Linux** ✅ (02/11 soir) : enrollment token→CSR→mTLS (SPEC §6.1), WebSocket
      heartbeat 30 s (agent initiateur, règle d'or §2.1), self-hash vérifié par le hub.
- [x] **J2 — hub MVP + dashboard** (commit 3511b37) : liste hosts, statut en ligne, audit UI,
      tokens enrollment depuis l'UI + install.sh servi par la centrale (décisions SPEC §8 du 02/11).
- [x] **J3 — ping applicatif + file d'actions** ✅ (03/11 matin, commits 3cb8941 + d635509) :
      ping RTT hub-side sur WS agent (jamais ICMP), actions pending livrées à la reconnexion,
      whitelist inventory_refresh/pkg_list, UI « Actions distantes », fix Hijacker preview.
- [x] **J4 — pare-feu commit-confirm** ✅ (03/11 après-midi) : snapshot scellé clé de site,
      apply runtime, compte à rebours AGENT (rollback si hub meurt / timeout), fw_sessions
      timeline UI. E2E chemin failed validé ; chemin confirm à recetter sur hôte réel.
- [ ] Puis J5 (paquets),
      J6 (maintenance), J7 (fleet), J8 (Windows), J9 (MFA forte/SSO), J10 (compose+Caddy).
- [ ] Questions SPEC.md §13 restantes (non bloquantes pour J1/J2) : 1) stack frontend
      (proposition : HTML/JS sans build lourd), 4) périmètre agent Windows (winget seul ?).
- [ ] Valider/réordonner les vagues 1-5 (proposées dans IDEES.md/ROADMAP.md).
- [x] Fabien : autorisation commit+push accordée le 02/11 (règle « lecture seule » abrogée) — J0+J1 poussés sur origin/main.

## Décisions
- **Règle des flux** : agent push/pull vers centrale (agent initiateur), centrale push vers
  global, global ne pousse rien (répond aux pulls). Le SaaS ne contrôle aucune machine.
- **Multi-tenant** : admin global @dpnac.fr uniquement ; orgs libres avec mail de confirmation ;
  modèle multi-appartenance (un user, plusieurs orgs) = **MON CONSEIL, à confirmer par Fabien**
  — couvre clients finaux auto-gérés ET MSSP externes (une org par client géré).
- Go pour agents et backends ; PostgreSQL ; docker-compose partout ; mTLS agents↔centrale ;
  TLS+auth pour centrale↔global ; sauvegardes chiffrées par enveloppe de clé de site
  (AES-256-GCM + RSA-OAEP/HPKE), clé privée jamais envoyée au global.
- Audit chaîné (N5), intégrité agent (N12), clé de secours (N14), notifications (N10) : à
  câbler DÈS LA CONCEPTION (vague 1), pas rétrofitables à moindre coût.
- **Backup : plateforme SÉPARÉE** (socle `backup.<domaine-client>`, projet distinct) — UrBackup
  = cible fonctionnelle uniquement.
- Git : lecture seule ABROGÉE le 02/11 soir (accord explicite de Fabien « Tu as le droit de commit et push ») — l'agent committe et pousse, historique conventionnel lisible.

## Notes
- Repo parti d'un README d'une ligne (commit 5cdb25f). Tous les docs créés le 02/11 sont
  COMMITTÉS et poussés par l'agent le 02/11 soir après accord explicite (J0+J1 sur origin/main, commit 476da45).
- Capture de référence : interface type PatchMon (hosts 14, groupes, agent auto-update,
  compliance) + UrBackup dans les onglets du navigateur (d'où l'idée N16).