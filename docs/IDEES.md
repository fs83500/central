# IDEES N1-N20 — développement détaillé (N1-N15 ✅ validées 02/11 · N16 ✅ « à terme » · N17-N19 ⏳ proposition 02/11, angle NIS2 · N20 ✅ validée 02/11)

> Statut : 🔵 toutes proposées, aucune encore validée/refusée.
> Légende effort : **S** = jours · **M** = 1-2 semaines · **L** = 2-4 semaines · **XL** = chantier majeur.
> Légende priorité : **P1** = socle, câbler dès la conception · **P2** = forte valeur, phase 2 · **P3** = différenciateur.

## Tableau récapitulatif

| N° | Idée | Ce que ça fait concrètement | Valeur | Effort | Prio | Dépend de |
|----|------|------------------------------|--------|--------|------|-----------|
| N1 | Break-glass | Bouton « Urgence » : applique un ruleset minimal (tout bloqué sauf canal management + SSH admin) sur 1 host ou 1 groupe, journalisé + notifié, retour arrière 1 clic | Sécurité absolue en cas d'incident (compromission, attaque en cours, host suspect) | M | P2 | Agent FW, snapshot/rollback (socle ✅) |
| N2 | Diff FW en langage clair | Avant toute application : « + Autoriser SSH depuis 10.0.0.0/24 · − Supprimer règle #12 (port 8080) » ; confirmation renforcée si action destructrice | Éradique les erreurs humaines, adoption par des non-experts ; socle technique de N3/N6 | L | P1 | Agent FW, modèle canonique de règles |
| N3 | Détection de dérive | Hash canonique des règles actives comparé périodiquement à la référence ; alerte si modif manuelle ; 2 boutons : « Resynchroniser » (écrase avec la référence) ou « Adopter » (le current devient la référence) | Le vrai besoin de la gestion centralisée : personne ne modifie plus le FW en catimini | M | P1 | N2 (diff) |
| N4 | Profils/baselines versionnés | « Serveur DNS », « Poste bureautique » : paquets attendus/interdits + ruleset FW de référence, applicables à un groupe, versionnés avec historique et diff inter-versions | Opérer 250 devices sans répéter 250 fois la même config | L | P2 | N2, N3, gestion paquets |
| N5 | Journal d'audit chaîné | Chaque action (qui/quoi/quand/résultat/depuis quelle IP) signée + hash chaîné au précédent ; page « Vérifier l'intégrité de la chaîne » ; export signé | Tamper-evident : aucune action effaçable sans que ça se voie ; argument compliance fort (clients régulés, RSSI) | M | P1 | Rien — à câbler dès le schéma DB |
| N6 | Test de connectivité prédictif | Dans le diff : « ⚠️ si j'applique, l'agent ne pourra plus joindre la centrale:443 » ; simulation locale du ruleset (match packet) + sonde réelle optionnelle | Anti-blocage en amont ; complète le rollback commit-confirm | M | P2 | N2 |
| N7 | Miroir de dépôts (repo cache) | Conteneur cache apt/dnf (approx/apt-cacher-ng, createrepo) dans la centrale ; agents téléchargent en local | Bande passante, rapidité, indispensables aux sites isolés | M | P3 | Rien |
| N8 | Canari de patching | Une MAJ se déploie en 2 temps : 1-2 hosts pilotes → pause (durée configurable) → promotion manuelle si OK → reste du groupe | Évite de casser tout un parc d'un coup ; sérénité | M | P2 | Gestion paquets, fenêtres maintenance ✅ |
| N9 | Blacklist de versions | Liste centrale de versions bogguées/dangereuses ; exclues des plans de MAJ ; pinning « known-good » géré depuis la centrale | Interdit les régressions connues à l'échelle du parc | M | P2 | Gestion paquets, N4 (rattachement profils) |
| N10 | Notifications multi-canal | Règles de routage par type/sévérité → email / webhook / Telegram ; events : host offline, échec patch, rollback déclenché, dérive, quota 90 % | Opérationnel indispensable : un parc non surveillé est un parc non géré | M | P1 | Bus d'événements interne |
| N11 | Mode air-gap | Centrale fonctionne sans internet : fédération en file rattrape au retour du lien, enrollment offline (token généré/importé manuellement), repo cache obligatoire | Sites industriels/ISOLÉS — segment de marché mal servi | L | P3 | N7, file d'actions ✅ |
| N12 | Vérification d'intégrité de l'agent | Manifeste signé des binaires ; self-check (checksum + signature) au démarrage ; hash remonté dans chaque heartbeat ; alerte si altéré | Anti-tampering : on ne peut pas remplacer l'agent par une version modifiée sans que ça se voie | S-M | P1 | Auto-update signé ✅ |
| N13 | Moteur d'automatisation simple | Règles YAML « si condition pendant X → action » (si CPU > 90 % 10 min → webhook ; si offline > 24 h → alerte) ; évaluateur sur le flux de télémétrie | Différenciateur type « Automation » (visible dans ta capture de référence) | XL | P3 | Télémétrie, N10 |
| N14 | Clé de secours scellée | Export de la clé privée du site chiffrée par passphrase (PKCS#8 + AES-GCM), conservée HORS LIGNE par le client ; procédure de restauration + test de restauration périodique | Sans elle : perdre la centrale = perdre TOUTES les sauvegardes FW ; c'est le garde-fou de l'idée 9 ✅ | S-M | P1 | Sauvegardes chiffrées ✅ |
| N15 | Suivi CVE par sévérité | Mapping paquets→CVE (feeds distro : Debian security-tracker, ALAS/ELSA, OVAL) ; badge criticité par MAJ ; vue « sécurité d'abord » : hosts avec vulnérabilités critiques en tête | Argument commercial n°1 d'un patch manager : montrer LE risque, pas 400 MAJs | L | P2 | Gestion paquets, source de données CVE |
| N16 | Backup natif type UrBackup | Moteur de sauvegarde à CODER nativement dans l'agent (Go) : fichiers puis images disque, chunks CDC dédup (SHA-256) + zstd + AES-256-GCM, restauration fichier/bare-metal, réplication chiffrée centrale+glob (aucun ne peut lire sans la clé du site) | Vision complète patch + FW + backup sous UNE marque, UN seul agent à installer | M (B1) → XL (B4) | P3 (« à terme ») | Socle, canal mTLS, gestion paquets, clé de site |
| N17 | Rapport de conformité NIS2 | Rapport 1 clic généré depuis l'audit chaîné : inventaire, % patching par sévérité CVE, hygiène FW (dérives N3, rollbacks), incidents, preuves crypto (signatures, self-hash), export PDF/JSON signé + horodaté | Le jour du contrôle, on PROUVE : piste infalsifiable + synthèse par mesure NIS2 ; module premium facturable | L | P1 (module premium NIS2) | N5 ✅, N15, N3, N13 |
| N20 | Détection des conteneurs (Docker/Podman) | L'agent détecte les runtimes, les conteneurs, les ports publiés (flag 0.0.0.0) et les chaînes DOCKER/DOCKER-USER ; remonte tout dans heartbeat/inventaire ; l'UI montre la surface d'attaque ; règles FW conteneurs via DOCKER-USER | Docker CONTOURNE ufw/firewalld : « protégé par ufw » + port publié = trou béant sans que l'admin le sache ; finding de premier plan pour NIS2 | M | P1 (J4) | Agent inventaire ✅, agent FW (J4) |
| N18 | Scoring par mesure NIS2 | Badge « conformité » par host/site : à jour / à surveiller / non conforme, calculé en continu sur patching, FW, agents, incidents ; visible dashboard + global | La démo « parle contrôle ANSSI », pas seulement des graphes ; ancre la marque conformité | M | P1 (avec N17) | N17, télémétrie |
| N19 | Registre des dérogations | Toute MAJ non appliquée ou règle FW tolérée doit être justifiée (qui, pourquoi, échéance) ; registre consultable, alimente le rapport NIS2 ; alerte à l'échéance | Le registre NIS2 classique, sinon le rapport montre des trous inexpliqués | S-M | P1 (avec N17) | Gestion paquets, N3 |

## Détail par idée

### N1 · Break-glass
- **Fonctionnement** : opérateur clique « Urgence » (host ou groupe) → l'agent applique le ruleset
  secours minimal : allowlist management (mTLS vers centrale), SSH admin restreint à une IP/plage,
  tout le reste DROP. Snapshot de l'état précédent conservé, retour arrière en 1 clic.
- **Points d'attention** : le ruleset break-glass doit être testé à l'installation (sinon il risque
  d'être lui-même boggué) ; journalisation maximale (qui a déclenché, pourquoi si champ commentaire).
- **Risque si absent** : en cas d'incident réel (cryptolocker qui se propage), l'opérateur n'a aucun
  geste de confinement rapide.

### N2 · Diff FW en langage clair
- **Fonctionnement** : parser par backend (nftables/firewalld/ufw/Defender) → **modèle canonique**
  (allow/deny, direction, proto, port, source, cible, service nommé) → diff canonic → phrases
  humaines + badges « + ajout / − suppression / ± modification ». Toute suppression d'une règle
  liée au canal de management déclenche l'avertissement N6 et exige une confirmation renforcée.
- **Points d'attention** : c'est le socle de N3 et N6 — à concevoir tôt ; les exceptions non
  traduisibles dans le canonique s'affichent en « règle avancée — non analysée » (jamais masquée).
- **Valeur cachée** : rend le produit utilisable par un technicien non expert nftables.

### N3 · Détection de dérive
- **Fonctionnement** : à chaque inventaire, l'agent calcule le hash canonique de son ruleset actif
  et l'envoie au heartbeat ; la centrale compare avec la référence du host/groupe ; si diff →
  événement « dérive » (notification N10) ; deux réponses : **Resynchroniser** (la référence
  l'emporte, avec commit-confirm) ou **Adopter** (l'état constaté devient la nouvelle référence,
  journalisé).
- **Points d'attention** : une dérive n'est pas toujours malveillante (intervention légitime du
  client) → d'où le choix Adopter/Resynchroniser plutôt qu'un écrasement aveugle.

### N4 · Profils/baselines versionnés
- **Fonctionnement** : un profil = nom + paquets attendus/interdits/versions pinned + ruleset FW
  de référence + fenêtre de maintenance par défaut. Association à un host ou un groupe. Toute
  évolution crée une nouvelle version (v2, v3…), historique consultable, diff inter-versions (réutilise N2).
  L'UI propose ensuite « Ce host n'est pas conforme au profil X : voir l'écart ».
- **Valeur** : c'est ce qui transforme « un dashboard » en « un outil d'exploitation » — la
  conformité devient déclarative.

### N5 · Journal d'audit chaîné
- **Fonctionnement** : table `audit_events` : (id, acteur, action, cible, paramètres, résultat,
  horodatage, prev_hash, hash, signature Ed25519). hash = SHA-256 de toutes les colonnes + prev_hash
  → toute modification/effacement d'une ligne casse la chaîne ; page de vérification en continu
  (« Chaîne intégrée ✓ / corrompue depuis l'événement #4821 ») ; export signé PDF/CSV pour audit externe.
- **Ancrage renforcé (optionnel)** : hash de tête publié périodiquement à la console globale
  (elle devient témoin tiers sans voir le contenu — elle ne stocke que le hash).
- **À câbler dès la conception** : impossible de « rajouter » une chaîne proprement après coup.

### N6 · Test de connectivité prédictif
- **Fonctionnement** : moteur « match packet » local à l'agent (étant donné le ruleset CIBLE, ce
  flux passerait-il ?) ; l'UI teste automatiquement les flux critiques (agent→centrale:443 mTLS,
  DNS, gateway) et liste « ✅ passe / ⛔ sera coupé » dans l'écran de diff. Option : sonde réelle
  (l'agent tente le flux pendant une brève fenêtre de test runtime sans commit).
- **Valeur** : le commit-confirm (✅) protège APRÈS coup ; N6 prévient AVANT coup.

### N7 · Miroir de dépôts
- **Fonctionnement** : conteneur supplémentaire du docker-compose centrale (apt mirror/Proxy :
  approx, apt-cacher-ng ; dnf : reposync+createrepo ; Windows : cache winget/choco si faisable).
  Les agents reçoivent l'URL locale par configuration ; volumes avec TTL/quotas de rétention.
- **Valeur** : 250 devices qui patchent le même soir ne tirent pas 250× les mêmes paquets d'internet.

### N8 · Canari de patching
- **Fonctionnement** : un « déploiement de MAJ » a 4 états : brouillon → pilotes (1-2 hosts
  marqués canary) → **pause d'approbation** (durée configurable, auto-promulgue si 0 incident) →
  vague complète. Incident sur pilote = blocage + alerte N10.

### N9 · Blacklist de versions
- **Fonctionnement** : registre central de versions interdites (paquet, version, motif, lien
  CVE si dispo), applicable globalement, par profil (N4) ou par host ; le planificateur de MAJ
  (socle paquets ✅) exclut ces versions et propose la version supérieure saine ; les versions
  « pinned known-good » figent un paquet au contraire.
- **Valeur** : « on ne met JAMAIS plus le paquet qui a cassé la prod en mars » — mémoire d'entreprise.

### N10 · Notifications multi-canal
- **Fonctionnement** : bus d'événements interne (host offline, échec patch, rollback FW déclenché,
  dérive détectée, quota ≥ 90 %, agent altéré, chaîne d'audit cassée) → règles de routage par
  type × sévérité × site → email / webhook / Telegram ; retries avec backoff ; page « test de notification ».
- **Sévérités** : info / warning / critical ; silence planifiable pendant les fenêtres de maintenance.

### N11 · Mode air-gap
- **Fonctionnement** : la centrale fonctionne sans internet sortant : la fédération centrale→global
  passe par une **file persistante** qui se vide au retour du lien (jamais de perte d'événement) ;
  enrollment par token importé manuellement (QR/fichier) ; MAJ d'agents et paquets servies par le
  repo cache local N7 ; option « fédération par lien intermittent » (4G temporaire).
- **Marché** : industrie, healthcare, collectivités — sites isolés par politique de sécurité.

### N12 · Vérification d'intégrité de l'agent
- **Fonctionnement** : à chaque distribution d'agent (install + auto-update ✅) : manifeste
  signé (binaire, version, SHA-256, date) ; l'agent self-checke au démarrage + à intervalle
  régulier ; le hash de son propre binaire est remonté dans le heartbeat → la centrale alerte
  si un agent a un hash inconnu au bataillon (« agent altéré ou non officiel »).
- **Valeur** : boucle le trou laissé par l'auto-update signé (qui protège la MAJ mais pas la
  modification à chaud sur disque).

### N13 · Moteur d'automatisation simple
- **Fonctionnement** : règles YAML côté centrale : `si metric(cpu) > 90% pendant 10 min alors
  webhook(jira)` ; `si host offline depuis 24h alors alerte(ticket)` ; évaluateur à fenêtre
  glissante sur la télémétrie ; actions limitées au départ (alerter/webhook) puis étendues
  (exécuter un plan de remédiation).
- **Prudence** : XL, langage + évaluateur + documentation UI ; ne pas commencer avant que le
  socle télémétrie + notifications soient solides. À découper plus tard.

### N14 · Clé de secours scellée
- **Fonctionnement** : commande centrale `ugctl key-backup export --passphrase` → fichier
  PKCS#8 chiffré (AES-256-GCM, PBKDF2 fort) de la clé privée du site ; le client le conserve
  hors ligne (coffre, papier, USB scellé) ; restauration `key-backup import` ; page de
  procédure dans l'UI avec checklist ; **test de restauration guidé à l'installation**
  (« vérifiez que vous savez déchiffrer »).
- **Argumentaire** : l'idée 9 ✅ garantit que même Fabien ne peut pas lire les sauvegardes
  des clients ; N14 garantit que le CLIENT ne perd pas tout s'il perd sa centrale.
  Les deux ensembles = proposition de confiance complète.

### N15 · Suivi CVE par sévérité
- **Fonctionnement** : ingestion de feeds par distribution (Debian security-tracker/OVAL,
  AlmaLinux errata, winget/MSRC côté Windows) → mapping local paquet installé × version →
  CVE × sévérité ; score de risque par host = Σ criticités pondérées ; dashboard trie par
  « hosts les plus exposés » ; badge rouge sur les MAJ critiques ; filtre « montrer seulement
  les correctifs de sécurité ».
- **Points d'attention** : la qualité dépend des feeds ; prévoir fallback manuel (l'opérateur
  peut marquer une MAJ « critique » à la main).

### N16 · Plateforme backup séparée « type UrBackup » (recadré 02/11 soir)
- **Statut** : ✅ « à terme » — **AUTRE plateforme, SÉPARÉE** du socle gestion (décision
  Fabien : séparation des services pour plus de sécurité). Hors périmètre du repo central.
- **Domaines** : socle gestion = `central.<domaine-client>` ; socle backup =
  `backup.<domaine-client>` ; SaaS opérateur = `global.unifiedguard.cloud`.
- **Isolation** : compose, clés, agents, comptes distincts. Compromettre un socle n'implique
  pas l'autre. UrBackup = cible fonctionnelle uniquement, pas d'intégration du produit.
- **Cible fonctionnelle** : fichiers (complet/incrémental → chunks CDC dédup SHA-256 + zstd
  + AES-256-GCM) puis images disque, restauration fichier/arborescence/bare-metal, accès web,
  rétention GFS, fenêtres de sauvegarde.
- **Règle d'or des flux** (identique au socle gestion) : agent backup ↔ centrale backup
  (connexions initiées par l'agent), push centrale→global uniquement, global ne pousse rien.
- **Phasage** : B1 fichiers Linux → B2 CDC/dédup/réplication chiffrée → B3 Windows VSS + web
  → B4 images disque + bare-metal. À traiter comme un PROJET DISTINCT (repo `backup`).

### N20 · Détection des conteneurs — Docker & Podman (✅ validée 02/11)
- **Fonctionnement** : l'agent identifie les runtimes actifs (docker/podman, compose,
  containerd, k8s à part), énumère conteneurs et ports publiés
  (proto, host_ip, host_port, conteneur, réseau), détecte les chaînes iptables
  `DOCKER` / `DOCKER-USER`, et le mode réseau (`--network host` = criticité haute).
- **Pourquoi** : Docker écrit ses règles AVANT ufw/firewalld — un port publié sur
  0.0.0.0 est ouvert quelle que soit la politique ufw affichée. Piège documenté,
  source de trous réels ; personne ne le remonte dans un RMM généraliste.
- **Design dérive (N3)** : hash canonique = chaînes STABLES seulement
  (INPUT/FORWARD + DOCKER-USER) ; les chaînes dynamiques `DOCKER*` ne déclenchent
  pas de fausse dérive ; l'état d'exposition (ports publiés) est comparé et alerté
  séparément. Dérive ≠ exposition.
- **Gestion (avec J4)** : règles conteneurs appliquées dans `DOCKER-USER` (ré-injection
  au démarrage du service par l'agent, elles ne survivent pas seules au reboot) ;
  snapshot/rollback capturent DOCKER-USER + NAT, pas seulement ufw/nft.
- **Profil N4 « Hôte Docker »** : INPUT strict + DOCKER-USER restreinte + alerte sur
  tout publish 0.0.0.0 non déclaré.
- **Kubernetes — périmètre honnête** : durcissement de l'INPUT du node + surveillance
  (remontée) du CNI ; on ne gère PAS kube-proxy. Pas de promesse de vente.
- **Effort** : M — détection/remontée seule S-M (livrable avec J3-J4), gestion
  DOCKER-USER avec J4, intégration au rapport N17 (NIS2) en Vague 6.

## Proposition de vagues (N1-N15 toutes ✅ 02/11 ; N16 ✅ « à terme »)

- **Vague 1 — socles à câbler dès la conception** : N12, N14, N10, N5
  *(impossibles ou coûteux à rajouter après coup)*
- **Vague 2 — puissance firewall** : N2 → N3 → N1 → N6 → **N20 (✅ 02/11)**
  *(diff canonique → dérive → break-glass → prédictif ; N20 s'y greffe : détection
  conteneurs d'abord (remontée seule), gestion DOCKER-USER avec J4)*
- **Vague 3 — exploitation à l'échelle** : N8, N9, N4, N15
- **Vague 4 — différenciateurs marché** : N7, N11, N13
- **Vague 5 — sauvegarde natif (à terme)** : N16 — moteur type UrBackup à CODER, phasage B1→B4
- **Vague 6 — conformité NIS2 (module premium, SPEC §15)** : N17 → N19 → N18
  *(le rapport d'abord — c'est l'argument de vente ; le registre alimente ; le scoring last)*

## À trancher

1. ~~Valider/refuser chaque N~~ → **fait le 02/11 : N1-N15 toutes validées** + N16 « à terme ».
2. Valider ou réordonner les vagues (proposition ci-dessus).
3. Confirmer les questions ouvertes de SPEC.md §13 (frontend, ordre de construction,
   mono/multi-tenant, périmètre Windows, niveau UrBackup initial).