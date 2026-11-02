# AVANCEMENT.md — UnifiedGuard.cloud

## Statut : 🎉 J2 (hub MVP + dashboard) EN COURS — auth + dashboard + thème livrés, non encore committés

Dernière mise à jour : 2026-11-02 ~19h15

## Tâche en cours
- **J2 en cours** (PLAN-ATTAQUE.md §6) : auth hub (login e-mail + MFA + sessions),
  dashboard go:embed (5 pages), **thème clair/sombre/auto demandé par Fabien — TERMINÉ**.
  Reste J2 : partitionnement télémétrie, page détail hôte finition, recette complète.

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
- [ ] **J2 — hub MVP + dashboard** : liste hosts, statut en ligne, audit UI, tokens enrollment
      depuis l'UI + install.sh servi par la centrale (décisions SPEC §8 du 02/11).
- [ ] Puis J3 (ping applicatif + file d'actions), J4 (FW commit-confirm), J5 (paquets),
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