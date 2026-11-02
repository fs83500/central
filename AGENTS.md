# AGENTS.md — consignes du projet central

## Projet
**UnifiedGuard.cloud** — plateforme de gestion de paquets, firewalls et télémétrie multi-OS (Linux + Windows), architecture 3 niveaux :
agents → centrales locales (self-hosted, docker-compose) → console globale SaaS (fédération, abonnements 5/25/50/100/250 devices).

## Règles de travail (Fabien)
- **Git : lecture+écriture AUTORISÉES depuis le 02/11** (accord explicite de Fabien « Tu as le droit de commit et push »). Commits conventionnels de taille humaine + push vers origin ; jamais de force-push.
- Le travail se fait dans `/workspace/projets/central`.
- Fichier d'avancement obligatoire : `AVANCEMENT.md` à la racine du repo (tâche en cours, fait, reste à faire, décisions).
- Livrables spec : `docs/SPEC.md` (spécification fonctionnelle) et `docs/ROADMAP.md` (idées/évolutions, tri par priorité).
- Pas de push Git sans accord explicite — le régime du projet (G4.1) autorise commit/push/fusion ; à chaque jalon, utiliser les outils git_auto_commit/git_push.

## Vocabulaire
- **Agent** : binaire installé sur un device (Linux/Windows), remonte télémétrie + exécute actions paquets/FW.
- **Centrale** (hub) : serveur d'administration local, self-hosted, docker-compose, reçoit les agents.
- **Console globale** (fleet) : SaaS de Fabien, fédère les centrales, gère les abonnements.
- **Hôte / device / host** : machine administrée.
- **Sauvegarde FW chiffrée** : backup des règles de firewall, chiffré par clé du SITE (seul le site peut déchiffrer), stocké sur la centrale ET sur la console globale.
- **Rollback FW** : réapplication automatique de la dernière config FW saine après coupure de service.

## Décisions techniques (validées par Fabien)
- Agents : Go (binaire statique unique, Linux + Windows).
- Backend centrales + console globale : Go + PostgreSQL, déployés en docker-compose.
- Chiffrement : mTLS agents ↔ centrale ; TLS + auth pour centrale ↔ console globale.
- Sauvegardes FW : chiffrement hybride (AES-GCM 256 des données, clé du site enveloppée par RSA-OAEP) — seule la centrale du site détient la clé privée.
- Vérification des paquets sans casser les dépendances : simulation apt/dnf --simulate + winget dry-run avant application, test de cohérence des dépendances, refus si risque (sauf override manuel).
- Nom de marque : **unifiedguard.cloud**.