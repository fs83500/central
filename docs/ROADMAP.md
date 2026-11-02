# ROADMAP — UnifiedGuard.cloud

Légende : ✅ validé par Fabien · 🔵 proposé (à trier) · ❌ refusé

## R. Idées fondatrices (toutes ✅ — intégrées à SPEC.md)

1. ✅ **Enrollment sécurisé** — token à usage unique, cert mTLS par agent.
2. ✅ **File d'actions** — commandes en attente pour hosts offline, exécutées au retour.
3. ✅ **Fenêtres de maintenance** — patching planifié par groupes de hosts.
4. ✅ **Compliance & inventaire** — export CSV, rapports par client/site.
5. ✅ **Auto-update de l'agent** — piloté par la centrale, binaires signés.
6. ✅ **Durcissement sécurité** — mTLS, aucun flux sortant agent, secrets en env.
7. ✅ **Rollback FW automatique** — commit-confirm avec compte à rebours + snapshot chiffré.
8. ✅ **Détection du type de firewall** — remontée type/backend/version/statut par l'agent.
9. ✅ **Sauvegardes chiffrées multi-sites** — AES-256-GCM + enveloppe clé publique du site ;
   stockées centrale + global ; seul le site déchiffre ; rotation prévue.
10. ✅ **Vérification des paquets** — simulation/dry-run + contrôle de dépendances avant
    application, refus si risque, override manuel possible, post-vérification services.

## N. Idées N1-N15 — VALIDÉES le 02/11/2026 par Fabien (« 15 très bonnes idées »)

Toutes ✅. Détail complet dans `docs/IDEES.md`. Résumé :

1. ✅ **Break-glass** — ruleset de confinement d'urgence (host/groupe), retour arrière 1 clic.
2. ✅ **Diff FW en langage clair** — modèle canonique + phrases humaines, confirmation renforcée.
3. ✅ **Détection de dérive** — hash canonique vs référence, Resynchroniser / Adopter.
4. ✅ **Profils/baselines versionnés** — « Serveur DNS », « Poste bureautique », diff inter-versions.
5. ✅ **Journal d'audit chaîné** — actions signées + hash chaîné (tamper-evident), export signé.
6. ✅ **Test de connectivité prédictif** — « si j'applique, l'agent perdra la centrale:443 ».
7. ✅ **Miroir de dépôts (repo cache)** — cache apt/dnf local à la centrale.
8. ✅ **Canari de patching** — pilotes → pause d'approbation → vague complète.
9. ✅ **Blacklist de versions** — versions bogguées exclues, pinning « known-good ».
10. ✅ **Notifications multi-canal** — email / webhook / Telegram, routage par sévérité.
11. ✅ **Mode air-gap** — fédération en file persistante, enrollment hors ligne, repo cache.
12. ✅ **Vérification d'intégrité de l'agent** — manifeste signé, self-check, hash au heartbeat.
13. ✅ **Moteur d'automatisation simple** — règles « si … pendant … alors … » (YAML).
14. ✅ **Clé de secours scellée** — export chiffré par passphrase, gardée hors ligne par le client.
15. ✅ **Suivi CVE par sévérité** — feeds distro → score de risque par host, vue « sécurité d'abord ».

### Vagues de réalisation (proposées, en attente de réordonnancement éventuel)

| Vague | Idées | Logique |
|-------|-------|---------|
| 1 · Socles à câbler dès la conception | N12 · N14 · N10 · N5 | Impossibles/3× plus coûteux à ajouter après coup |
| 2 · Puissance firewall | N2 → N3 → N1 → N6 | Le diff canonique ouvre dérive, break-glass, prédictif |
| 3 · Échelle | N8 · N9 · N4 · N15 | Canari, blacklist, profils, CVE |
| 4 · Différenciateurs | N7 · N11 · N13 | Repo cache, air-gap, automatisation |
| 5 · Sauvegarde natif (à terme) | N16 — B1 → B2 → B3 → B4 | Voir ci-dessous |

## B. Socle BACKUP séparé — idée N16 (✅ « à terme », recadré 02/11 soir)

16. ✅ **Plateforme de sauvegarde type UrBackup — AUTRE plateforme, SÉPARÉE** (décision
    Fabien : séparation des services pour plus de sécurité).
    - Domaine : `backup.<domaine-client>` — le socle gestion vit sur `central.<domaine-client>`,
      le SaaS opérateur sur `global.unifiedguard.cloud`.
    - Isolation complète : compose, clés, agents et comptes distincts. Compromettre un socle
      n'implique pas l'autre.
    - Cible fonctionnelle (UrBackup = référence uniquement, pas d'intégration) : fichiers
      complet/incrémental → chunks CDC dédup SHA-256 + zstd + AES-256-GCM ; images disque ;
      restauration fichier/arborescence/bare-metal ; accès web ; rétention GFS.
    - Même règle d'or des flux que le socle gestion (§2.1 SPEC) : agent backup → centrale
      backup bidirectionnel, push vers global uniquement, global ne pousse rien.
    - Phasage : **B1** fichiers Linux → **B2** CDC/dédup/réplication → **B3** Windows VSS
      + web → **B4** images disque.
    - **Statut projet** : repo distinct (ex. `backup`) à créer le moment venu — HORS périmètre
      du repo central. Specs complètes : `docs/SPEC.md` §11.

## Triage en cours
- N1-N15 : ✅ toutes validées (02/11).
- N16 (backup natif) : ✅ validé « à terme » — **à coder comme la plateforme** ; phasage B1-B4
  à confirmer, quotas de stockage par offre à définir.
- Questions ouvertes SPEC.md §13 : stack frontend, ordre de construction, mono/multi-tenant
  SaaS, périmètre agent Windows, phasage backup + quotas stockage.