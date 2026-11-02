# UnifiedGuard.cloud — Spécification v0.1

> Plateforme de gestion des paquets, des firewalls et de télémétrie pour Linux et Windows.
> Architecture 3 niveaux : agents → centrales locales → console globale SaaS.
> Statut : spécification en cours de validation. Aucun code écrit.

## 1. Vision

UnifiedGuard.cloud permet à un opérateur (Fabien / son équipe) d'administrer depuis une console
unique des parcs de machines répartis sur plusieurs sites clients :

- **Patch management** : inventaire, installation, mise à jour de paquets, **sans casser les dépendances**.
- **Firewall management** : pilotage des firewalls Linux (ufw, firewalld, nftables) et Windows
  (Defender Firewall), avec **détection automatique du type de firewall** par l'agent.
- **Télémétrie** : remontée continue de l'état des machines.
- **Résilience** : **rollback automatique** des règles FW en cas de coupure de service.
- **Confidentialité** : **sauvegardes chiffrées** stockées à la fois sur la centrale locale ET sur la
  console globale, mais **déchiffrables uniquement par le site propriétaire**.

## 2. Architecture

```
┌────────────────────────────────────────────────────────────┐
│  CONSOLE GLOBALE (fleet.unifiedguard.cloud)                │
│  SaaS privé de l'opérateur — fédère toutes les centrales   │
│  Abonnements : 5 / 25 / 50 / 100 / 250 devices              │
│  Stocke les sauvegardes chiffrées (illisibles pour lui)     │
└───────────────┬────────────────────────────────────────────┘
                │  TLS + auth de service (fédération)
      ┌─────────┴─────────┐
      │                   │
┌─────▼─────────────┐ ┌───▼─────────────────┐
│  CENTRALE SITE A  │ │  CENTRALE SITE B     │   une par client/site
│  (self-hosted)    │ │  (self-hosted)       │   docker-compose
│  • API agents     │ │                      │
│  • dashboard      │ │                      │
│  • sauvegardes    │ │                      │
│    chiffrées      │ │                      │
│  • clés du SITE   │ │                      │
└───▲───────────────┘ └───▲───────────────────┘
    │  mTLS (certificats par agent)
    │                     │
┌───┴─────────────────────────────┐
│  AGENTS (Linux + Windows)       │
│  télémétrie · paquets · FW      │
└─────────────────────────────────┘
```

| Niveau | Rôle | Déploiement |
|---|---|---|
| Agent | Collecte + exécution locale | Binaire statique (service systemd / service Windows) |
| Centrale | Admin locale du site, API, stockage | docker-compose (API Go, PostgreSQL, dashboard) |
| Console globale | Fédération, abonnements, vue multi-sites | docker-compose (API Go, PostgreSQL, dashboard) |

### 2.3 La centrale peut-elle poller/pinger l'agent ? (clarification 02/11, corrigée : PAS d'ICMP)

| Mécanisme | Autorisé ? | Comment | Limites |
|---|---|---|---|
| **Ping d'agent = applicatif** | ✅ **OUI, à tout moment** | Message « ping » sur le **canal WebSocket déjà ouvert PAR l'AGENT** : réponse immédiate chiffrée mTLS, **RTT mesuré**. Aucun ICMP, aucune nouvelle connexion | Uniquement si l'agent est connecté |
| **Poll applicatif** (état/inventaire/règles à la demande) | ✅ **OUI** | Même mécanisme : demande/réponse sur le canal établi par l'agent | Idem |
| **ICMP** | ❌ **NON — décision Fabien 02/11** : pas de ping via ICMP | La centrale ne sonde pas l'IP du device | Le diagnostic offline se fait par les signaux du canal (voir ci-dessous) |
| **Connexion directe vers un port du device** | ❌ **JAMAIS** | Aucun service d'écoute sur les agents ; TCP/UDP de la centrale vers le device interdit | Si l'agent est déconnecté → file d'actions (idée n°2), on attend la reconnexion |

**Comment la centrale distingue « machine morte » vs « agent mort » SANS ICMP** :

1. **Horodatage last_seen** (dernier heartbeat/activité sur le canal) — l'indicateur principal.
2. **Erreurs/fermetures du canal WebSocket** (timeout TCP, reset, close propre) : un reset
   brutal suggère machine tombée/réseau coupé ; un close propre suivi d'absence de
   reconnexion suggère agent arrêté.
3. **Watchdog local** : l'agent est un service systemd (`Restart=always`) / service Windows
   (recovery auto-restart) → si l'agent plante, il redémarre localement en quelques secondes
   et se reconnecte. La panne « agent mort » est donc **auto-réparée sur le device** ; si le
   canal reste silencieux malgré tout, la machine est probablement éteinte ou coupée du réseau.
4. En dernier recours, un **humain** sur site vérifie — la centrale n'a pas besoin de sonde
   IP pour conclure : stale = alerte (N10), et la file d'actions reprend au retour.

Concrètement : l'agent maintient **une connexion WebSocket sortante permanente** vers la
centrale. Toutes les demandes de la centrale (ping applicatif, poll, commandes) transitent
sur **ce canal que l'agent a établi lui-même** (modèle tunnel inverse). **Le seul « ping »
d'agent est applicatif et chiffré** — jamais ICMP.

Sondes post-FW (§3.5) : c'est le **silence du heartbeat/ping applicatif** qui déclenche le
rollback — jamais un signal ICMP (non fiable et exclu).

## 3. Agents

### 3.1 Systèmes supportés (MVP →)
1. **MVP** : Debian/Ubuntu (dpkg/apt), AlmaLinux/RHEL (dnf/rpm)
2. **Ensuite** : Windows 10/11/Server (winget, choco, MSI, Defender Firewall)

### 3.2 Détection du firewall (remontée obligatoire par l'agent)
L'agent détecte, à chaque inventaire et à chaque heartbeat :
- le **type de firewall actif** : nftables / firewalld / ufw / iptables-legacy / Windows Defender FW ;
- le **backend réel** (ex. firewalld peut utiliser nftables ou iptables comme backend) ;
- la **version** et le **statut** (actif/inactif) ;
- le mode (runtime/permanent côté firewalld, profils Windows : domain/private/public).

Ordre de détection Linux : nftables direct → firewalld → ufw → iptables-legacy.
L'UI affiche un badge par host (ex. `firewalld 1.2.4 · backend nftables`).

### 3.3 Télémétrie remontée
CPU, RAM, disques, réseau (débit/latence), uptime, load, températures si dispo,
liste des services clés et leur état, versions des paquets (inventaire), état du firewall,
statut online/offline/stale, version de l'agent.

Fréquence : heartbeat 30 s (statut), télémétrie complète 5 min, inventaire paquets 24 h
(paramétrable). File d'actions pour les hosts offline (idées validées n°2).

### 3.4 Actions exécutables par l'agent
- Paquets : install / upgrade / remove / hold / inventaire.
- Firewall : activer/désactiver, lister les règles, appliquer un ruleset, restaurer un backup.
- Système : redémarrage planifié, exécution de scripts (plus tard — à trier).

### 3.5 Rollback FW automatique (« commit-confirm »)
Chaque application de règles FW suit ce protocole :

1. **Snapshot** : export du ruleset courant complet AVANT toute modification.
2. **Chiffrement + envoi** : le snapshot est chiffré sur l'agent (clé publique du site) et
   envoyé à la centrale, qui le stocke et le réplique vers la console globale.
3. **Application provisoire** : les nouvelles règles sont appliquées en mode *runtime*
   (jamais directement en permanent) ; le canal agent→centrale est toujours autorisé
   (allowlist management).
4. **Compte à rebours** (ex. 5 min) : l'agent doit recevoir un **confirm** de la centrale
   dans le délai. La centrale ne confirme que si elle a toujours reçu les heartbeats de l'agent
   ET que les sondes de santé passent (DNS, services critiques — paramétrables par host ;
   sondes applicatives locales, jamais ICMP).
5. **Sinon rollback** : sans confirm à l'échéance, ou si le heartbeat tombe, l'agent
   **réapplique automatiquement le snapshot chiffré** (il garde une copie locale temporaire).
   Firewalld : reset runtime. nftables : rechargement atomique du ruleset sauvegardé.
   ufw : reload des rules saved. Windows : `netsh advfirewall import <fichier.wfw>`.
6. **Alerte** : le rollback est journalisé, remonte à la centrale puis au global, notification
   à l'opérateur (idée n°9 à trier : canaux de notification).

### 3.6 Vérification des paquets sans casser les dépendances
Toute opération de paquet passe par un **plan d'installation** à 4 phases :

1. **Simuler** : `apt-get --simulate` / `dnf --assumeno` (transaction test) /
   `winget --dry-run` (ou `choco --whatif`). Le plan liste exactement ce qui sera installé,
   mis à jour, supprimé, et la taille téléchargée.
2. **Vérifier la cohérence** : le plan est refusé si la simulation indique des paquets cassés
   (`apt-get check`, `dnf check`), des dépendances non satisfaites, ou des suppressions non
   demandées explicitement. L'opérateur doit cocher un override manuel pour forcer.
3. **Appliquer** : exécution réelle, uniquement si le plan est validé. Les versions précédentes
   sont notées pour un retour arrière éventuel (`dnf history undo`, cache apt des .deb
   précédents, `winget uninstall` + réinstall).
4. **Post-vérification** : l'agent contrôle que les services impactés tournent toujours
   et remonte le résultat (succès/rollback/échec) à la centrale.

### 3.7 Auto-update de l'agent (idée n°5 validée)
Mises à jour distribuées par la centrale, binaires **signés** ; l'agent vérifie la signature
avant de s'auto-remplacer (rollback vers le binaire précédent si le nouveau ne démarre pas).

## 4. Centrale locale

- API Go (REST + WebSocket pour le temps réel) + PostgreSQL + dashboard web.
- Fonctions : enrollment des agents, dashboard hosts (cf. capture : recherche, groupes,
  filtres, colonnes, statut connecté/offline, version agent), file d'actions offline,
  fenêtres de maintenance par groupe, compliance/rapports (CSV), dépôts (repos),
  patching planifié, stockage des sauvegardes chiffrées.
- **Les clés privées du site vivent uniquement sur la centrale** (voir §6.3).

### 4.1 Authentification des utilisateurs de la centrale (décision 02/11 + durcissement 03/11)

**Modèle** : compte local par e-mail **+ SSO optionnel** + FQDN verrouillé à l'init.

1. **FQDN verrouillé à l'initialisation** : à l'installation, la centrale exige son FQDN
   (ex. `central.acme.fr`) et le fixe en configuration : tout accès par un autre Host/
   domaine reçoit 421/403. Le certificat TLS est émis par Caddy pour CE domaine uniquement
   (le dashboard et l'API agents ne répondent que sur ce nom).
2. **Comptes locaux** : identité = adresse e-mail locale (l'utilisateur, pas un login
   libre) — activation par lien envoyé à CETTE adresse (double opt-in local), pas de
   création de compte possible sans réception du mail.
3. **SSO** : support OIDC/SAML en option (permet de brancher Entra ID, Keycloak, mailcow…) ;
   si activé, l'accès local peut être restreint à « SSO uniquement » pour les orgs qui le
   veulent (les hubs restent accessibles aux comptes locaux sinon).
4. **MFA par e-mail** : code à usage unique envoyé sur l'adresse du compte (code =
   Argon2id/stockage court, TTL 10 min, unique, jetable) — disponible dès J2 pour la
   centrale, en complément du mot de passe. Option « SSO seul » = pas de MFA local car
   la politique MFA est gérée par l'IdP client (documenté).
5. **Durcissement standard (non négociable)** : Argon2id pour les mots de passe,
   rate-limiting sur login (5 échecs → backoff croissant, délai IP), session cookie
   `HttpOnly+Secure+SameSite=Strict` avec rotation du token à chaque élévation de
   privilège, TTL session 8 h inactivité 30 min, **re-authentification obligatoire
   UNIQUEMENT pour** (liste arrêtée par Fabien 03/11) : **break-glass (N1), gestion des
   clés de site (export/rotation N14), création de tokens enrollment** — le FW apply
   reste protégé par le commit-confirm §3.5, pas de re-auth supplémentaire. Expiration
   des sessions « tout appareil », journal de chaque login (succès/échec) dans l'audit chaîné.
6. **MFA forte optionnelle (J9)** : au-delà de la MFA e-mail de base, chaque compte peut
   activer **TOTP**, **SSO** ou **clé physique WebAuthn** — détails communs hub/fleet en §5.1.2.

> Pourquoi ce niveau : la centrale administre des firewalls et des paquets sur les machines
> du site — c'est le point le plus sensible après l'agent lui-même. Un mot de passe seul
> ne suffit pas ; e-mail + MFA local ou SSO entreprise + verrouillage FQDN + re-auth des
> actions critiques (liste ci-dessus) forment une défense en profondeur acceptable sans
> dépendre exclusivement d'un IdP externe.

## 5. Console globale SaaS — global.unifiedguard.cloud

### 5.1 Modèle de comptes — multi-organisations (décision 02/11)

- **Administrateur global** : inscription réservée aux adresses **`@dpnac.fr`** (contrôle de la
  racine SaaS ; dpnac = opérateur de la plateforme).
- **Organisations (tenants)** : création libre (n'importe quel mail) avec **confirmation par
  e-mail double opt-in OBLIGATOIRE** (lien à usage unique, TTL court, hash Argon2id côté
  serveur) — aucun compte ni org n'est actif sans réception du mail (SMTP sortant, N10).
- **Multi-appartenance (modèle éprouvé GitLab/GitHub)** : un compte utilisateur peut être
  membre de **plusieurs organisations** avec un rôle. Ce modèle couvre les deux profils
  sans hiérarchie rigide :
  - **Client final** : crée son org, y attache ses centrales, administre lui-même.
  - **Opérateur / MSSP externe** : crée une org par client qu'il gère, invite ses techniciens
    dans chaque org — sa « vue consolidée » = la liste de ses orgs.
  - **dpnac (opérateur racine)** : comptes @dpnac.fr = super-admin plateforme ; peut aussi
    être membre admin des orgs de ses clients.
- **Une centrale appartient à UNE organisation.** L'accès se gère par membres + rôles.
- Tables à câbler dès le schéma DB initial : `users` / `orgs` / `memberships(org_id,
  user_id, role)` / `hubs(org_id)`.

### 5.1.1 Authentification des comptes global (décision 02/11 + durcissement 03/11)

**Modèle** : compte e-mail + MFA e-mail OU SSO — les deux proposés, l'un des deux exigé.

1. **Mot de passe + MFA e-mail obligatoire** : un compte mot-de-passe-seul n'existe pas ;
   le code MFA est envoyé à l'adresse du compte (TTL 10 min, usage unique, hash Argon2id
   côté serveur, tentative unique). Un attaquant qui vole le mot de passe ne peut pas se
   connecter sans la boîte mail.
2. **SSO** (OIDC/SAML) : si activé sur le compte/org, la MFA est celle de l'IdP
   (recommandation affichée : activer la MFA côté IdP). Un compte peut basculer
   local→SSO, mais SSO→local exige une re-vérification par mail de confirmation.
3. **Durcissement plateforme** : Argon2id, rate-limiting 5 échecs/IP + backoff,
   verrouillage temporaire du compte à la 10ᵉ tentative globale (alerte mail),
   sessions HttpOnly/Secure/SameSite=Strict + rotation à l'élévation de privilège,
   TTL 12 h / inactivité 30 min, re-authentification pour tout changement de rôle, de
   plan ou de hub, journal complet dans l'audit chaîné fleet, notification mail à chaque
   nouvelle connexion depuis un nouvel appareil/navigateur.
4. **Honnêteté sur la MFA e-mail** : la MFA par e-mail est plus faible que TOTP/WebAuthn
   (délai de livraison, phishing de boîte mail). Choix assumé pour le lancement
   (simplicité : pas d'app à installer), avec **TOTP, WebAuthn et SSO en renfort
   optionnel dès J9** (§5.1.2) pour les comptes qui le veulent.

### 5.1.2 MFA forte optionnelle — TOTP, WebAuthn, SSO (décision Fabien 03/11)

Chaque compte (hub ET fleet) peut activer, en plus de la MFA e-mail :

| Méthode | Comment ça marche | Ce qu'il faut | Niveau |
|---|---|---|---|
| **TOTP** (RFC 6238) | QR code à scanner → code 6 chiffres qui change toutes les 30 s ; le secret est stocké hashé côté serveur (jamais en clair), un code usagé est refusé | Une app : Aegis (Android, open source), 2FAS (iOS/Android, open source), Google Authenticator, KeePassXC (PC) | 🟢 Très bon |
| **WebAuthn / clé physique** (passkeys) | La clé privée vit DANS la clé USB/NFC (YubiKey, SoloKey, Nitrokey) ou dans le secure enclave du téléphone ; le serveur ne stocke que la clé publique + un compteur de signatures ; chaque connexion exige le toucher + le domaine vérifié (anti-phishing natif : la clé refuse de signer pour un autre domaine que le FQDN verrouillé §4.1) | Acheter une clé : YubiKey 5 (~55 €), Nitrokey 3 (~50 €, open source), SoloKey (~35 €) — ou un iPhone/Android moderne en passkey Bluetooth | 🟢🟢 Le meilleur (résiste au phishing) |
| **SSO** (OIDC/SAML) | L'org branche son IdP (Entra ID, Keycloak, mailcow…) ; la MFA est gérée par l'IdP | Un IdP côté client | 🟢 Dépend de l'IdP |

**Ordre de préférence conseillé pour dpnac et clients exigeants** :
1. Clé physique WebAuthn (2 clés recommandées : principale + secours au coffre)
2. TOTP (si pas de budget clé)
3. MFA e-mail (base, déjà incluse partout)

### 5.1.3 Option « certificat utilisateur sur clé USB » (PIV) — réponse 03/11

Une clé USB **à puce** (YubiKey 5, Nitrokey 3) embarque un module **PIV** (NIST SP 800-73) :
la paire de clés est générée **dans la puce** et un certificat X.509 y est installé —
la clé privée est **non exportable** (≠ un fichier .p12 posé sur une clé USB de stockage,
qui est copiable et donc n'est PAS un facteur matériel).

- **Deux usages possibles pour UnifiedGuard** :
  1. **mTLS utilisateur** au dashboard : le hub accepte un certificat client TLS émis par
     une **CA « utilisateurs » dédiée** (séparée de la CA des agents §6.1), révocable par
     CRL. Utile aux orgs qui ont déjà des badges/smartcards PIV, et aux connexions
     **API/scripts** (certificat machine révocable plutôt que token permanent).
  2. Complément de WebAuthn sur la même clé (FIDO2 + PIV cohabitent).
- **Honnêteté sécurité** : le certificat client PIV n'a **pas d'anti-phishing par
  domaine** (le navigateur peut proposer le certificat sur une autre page, l'utilisateur
  touche la clé sans vérifier le domaine) — contrairement à WebAuthn qui refuse de signer
  pour un autre FQDN. Donc : **WebAuthn = facteur MFA principal**, PIV = option « PKI
  d'entreprise » pour les clients concernés (et l'auth machine/API).
- **Statut** : optionnel, **post-J9** (nécessite CA utilisateurs + gestion CRL + mapping
  certificat→compte dans le hub) — à acter dans la roadmap v2 auth si des clients le
  demandent. Le fichier `.p12` sur clé USB de stockage est **documenté mais déconseillé**
  (clé privée copiable = faux facteur matériel).

**Révocation des certificats PIV — via centrale ET via global (décision 03/11)** :

La révocation est **immédiate côté centrale** (c'est elle qui valide la connexion TLS au
dashboard) ; le global, lui, ne peut pas « pousser » un ordre aux centrales (règle d'or
§2.1) — il **enregistre l'ordre de révocation et le sert aux hubs lors de leur PULL**.

1. **Table `cert_registry`** (côté hub) : serial, subject, user_id?, purpose
   (dashboard/API machine), hub_state, issued_at, expires_at, revoked_at, revoked_by,
   revoked_via (central/global), crl_seq.
2. **Côté centrale** : page *Sécurité → Certificats* — liste des certificats émis,
   statut, bouton **« Révoquer »** (re-auth exigée, audit chaîné N5). Effet immédiat :
   le serial rejoint la CRL locale, la connexion TLS en cours est coupée à l'expiration
   de session, toute reconnexion est refusée.
3. **Côté global** : dans la fiche d'une org/hub, **« Demander la révocation d'un
   certificat »** (champ serial ou liste importée). Le global ne révoque pas directement
   (il n'a pas la CA de l'org) : il **enregistre la demande** et les hubs la **récupèrent
   par PULL** (comme le quota §2.1.5) à leur prochain cycle (≤ 5 min par défaut, ou au
   prochain pull après redémarrage). La CRL du hub est mise à jour, la révocation
   s'applique ensuite localement. Le statut remonte ensuite au global via le push
   fédération (revoked_at confirmé).
4. **Proposition CRL** : chaque hub publie sa CRL signée (Ed25519) sur un endpoint interne
   servi aux navigateurs de l'org ; OCSP inline (stapling) non requis — un dashboard
   interne n'a pas de contrainte de latence publique, une CRL à 5 min de fraîcheur suffit.
5. **Chaîne d'audit** : toute révocation (via centrale OU via global) trace `revoked_via`,
   l'acteur, l'horodatage — des deux côtés (hub + fleet), le global n'ayant qu'un
   **témoignage** (head d'audit) pas le détail exécutable (règle d'or).

**UX actée** : à l'activation, l'UI affiche le QR TOTP / lance l'enregistrement WebAuthn
(navigator.credentials), puis exige UNE vérification de confirmation + propose de stocker
les codes de secours à usage unique (10 codes, imprimés). À chaque login : mot de passe
→ écran « choisissez votre second facteur » selon ce qui est actif. Un facteur peut être
désactivé par l'utilisateur avec re-auth ; la perte de TOUS les facteurs = procédure de
récupération par un admin + mail de confirmation + délai de grâce de 24 h (anti-hijack).

### 5.2 Rôles (MVP)
| Rôle | Portée |
|---|---|
| admin global (@dpnac.fr) | Plateforme entière, abonnements, toutes les orgs |
| owner (créateur d'org) | Inviter des membres, gérer les centrales de son org |
| admin | Administrer centrales/hosts de l'org |
| viewer | Lecture seule |

### 5.3 Fonctions
- Fédération : chaque centrale s'enregistre auprès du global (auth de service, TLS) et pousse
  ses données consolidées (règle d'or §2.1 : le global ne pousse JAMAIS rien).
- Vue multi-sites : santé des centrales, hosts vs quota d'abonnement, alertes consolidées,
  blobs chiffrés (stockés, jamais lus), head de la chaîne d'audit (témoin tiers, N5).
- Abonnements 5 / 25 / 50 / 100 / 250 devices par centrale — quota servi par PULL (§2.1.5).
- **Les actions restent locales** : le global affiche les données consolidées et fournit des
  raccourcis/SSO vers les UI centrales ; aucune commande ne transite par le cloud.

## 6. Sécurité & chiffrement

### 6.1 Enrollment (idée n°1 validée)
Token d'inscription à usage unique généré sur la centrale, expiration courte.
L'agent obtient ainsi son certificat client mTLS ; aucun secret partagé en clair.

### 6.2 Transport
- Agent ↔ centrale : **mTLS** (certificat client unique par agent, révocable).
- Centrale ↔ globale : **TLS + auth de service** (bearer signé / mTLS).
- Aucun flux sortant de l'agent vers autre chose que sa centrale.
- UI centrale et globale : HTTPS obligatoire (Caddy), HSTS, cookies de session
  HttpOnly+Secure+SameSite=Strict, en-têtes CSP/X-Frame-Options/Referrer-Policy stricts.

### 6.2bis CORS & exposition derrière un reverse proxy (décision 03/11)

**Politique : CORS fermé par défaut — tout doit fonctionner en same-origin.**

- L'UI (vanilla JS) et l'API vivent **dans le même binaire, même origine** (`central.<fqdn>`
  sert `/` et `/api/v1/…`) → **aucun header CORS requis** en usage normal. Même chose pour
  le fleet (`global.unifiedguard.cloud`).
- L'API n'envoie **jamais** `Access-Control-Allow-Origin: *` et ne répond pas aux
  préflight `OPTIONS` par défaut.
- **Aucune origine cross-origin n'est censée appeler l'API** : les dashboards n'appellent
  que leur propre origine ; les agents parlent WebSocket mTLS (le CORS ne s'applique pas
  aux clients non-navigateur) ; le hub↔fleet est serveur-à-serveur (pas un navigateur).
- **Filtre Host/Origin par FQDN verrouillé** (§4.1) : requête dont le `Origin` (si présent)
  ne correspond pas au FQDN verrouillé de la centrale → rejet 403 par le hub (et non
  simplement relayée). Ceinture + bretelles avec le reverse proxy.
- **Derrière un reverse proxy** (Caddy recommandé, mais le modèle est volontairement
  compatible Nginx/Traefik/APM client) :
  1. Le hub attend `X-Forwarded-For`, `X-Forwarded-Proto` (rate-limiting par IP réelle,
     redirection HTTPS, binds de session sécurisés). Config fournie par Caddy nativement ;
     pour Nginx : les en-têtes standard `proxy_set_header` documentés dans `deploy/`.
  2. Le hub **refuse les X-Forwarded-* s'ils viennent d'une IP non déclarée comme proxy
     de confiance** (paramètre `TRUSTED_PROXIES`) → un client ne peut pas usurper son IP
     pour esquiver le rate-limit ni maquiller HTTPS.
  3. **Pas d'API exposée en cross-origin** même derrière proxy : si un client veut malgré
     tout embarquer l'UI dans son portail (rare, non recommandé), une option
     `CORS_ALLOWED_ORIGINS` (liste blanche stricte par FQDN verrouillé, jamais `*`,
     sans credentials par défaut) existe — **désactivée par défaut**, documentée avec
     l'avertissement CSRF associé.
  4. WebSocket : `proxy_read_timeout` > heartbeat (30 s) ; exemple de config livré dans
     `deploy/hub/` (Caddyfile + snippet Nginx équivalent).
- **Le fleet, SaaS exposé**, suit la même règle : same-origin strict, liste blanche
  uniquement si un besoin documenté apparaît (ex. widgets d'un portail client), jamais `*`.

### 6.3 Sauvegardes chiffrées « seul le site peut déchiffrer »

### 6.3 Sauvegardes chiffrées « seul le site peut déchiffrer »
Schéma hybride (enveloppe) :

- À l'installation de la centrale, une **paire de clés du SITE** est générée
  (recommandation : X25519 ou RSA-4096) ; la **clé privée ne quitte JAMAIS la centrale**
  (fichier Docker volume, jamais envoyée au global).
- La **clé publique** est enregistrée auprès de la console globale.
- Chaque sauvegarde (ruleset FW, et plus tard inventaires complets) est chiffrée côté
  agent/centrale : clé de données **AES-256-GCM** aléatoire, elle-même enveloppée avec la
  **clé publique du site** (RSA-OAEP / HPKE).
- La console globale stocke le blob chiffré + l'enveloppe → elle est **incapable de le lire**
  (elle n'a que des clés publiques). Pareil pour la centrale d'un autre site.
- **Restauration** : possible uniquement sur la centrale du site (clé privée locale).
- **Rotation des clés** : prévue (les nouvelles sauvegardes utilisent la nouvelle clé ; les
  anciennes restent déchiffrables via un « keyring » local versionné).
- **Honnêteté technique** : aucune méthode n'est mathématiquement « infaillible » ; la garantie
  ici est structurelle — le secret ne quitte jamais le site. Contre-risque : si le site perd sa
  clé privée, les sauvegardes sont indéchiffrables → prévoir une **clé de secours scellée**
  (export chiffré par passphrase, gardée hors ligne par le client — à trier).

## 7. Abonnements (offres)

### 7.1 Grille (proposition 02/11, B2B HT, par centrale)

| Offre | Devices | €/mois | €/an (−17 %) | €/device/mois | Cible |
|---|---|---|---|---|---|
| Starter | 5 | 15 € | 150 € | 3,00 € | très petits sites (produit d'appel) |
| Bronze | 25 | 45 € | 450 € | 1,80 € | TPE/PME |
| Silver | 50 | 80 € | 800 € | 1,60 € | PME |
| Gold | 100 | 140 € | 1 400 € | 1,40 € | PME+ |
| Platinum | 250 | 300 € | 3 000 € | 1,20 € | ETI / multi-équipes |
| Entreprise | >250 / multi-centrales | sur devis | — | ~1 € | ETI multi-sites |

Positionnement (02/11) : grille volontairement **sous les RMM SaaS** (JumpCloud
~9 €/utilisateur, Atera ~2-3 €/device) mais payante face aux outils gratuits
(Tactical RMM, MeshCentral) grâce à la valeur sécurité : audit chaîné, mTLS,
sauvegarde FW chiffrée, rollback. Palier 5 devices = produit d'appel (15 €/mois
pour qui ne paierait jamais Lansweeper/JumpCloud). Chaque centrale = 1 licence :
un client multi-sites achète N licences → le multi-sites fait monter l'ARPU.

Options facturables (02/11) :
- **Module backup chiffré** (§11.5) : +20 % du plan (ex. Gold 140 → 168 €/mois).
- **Support premium** (SLA 4 h, assistance config FW) : 500-1 500 €/an.
- **Onboarding / installation initiale** : 300-500 € ponctuel.

Le quota s'applique par centrale (hosts enrollés). Le suivi de quota vit sur la console
globale, qui le pousse aux centrales. (Facturation hors périmètre technique pour l'instant.)

### 7.2 CA réalisable (scénarios 02/11, mix de ventes pondéré petits > gros)

| Horizon | Centrales actives | Mix exemple | CA mensuel | CA annuel |
|---|---|---|---|---|
| Année 1 — lancement | ~40 | 18 Starter + 12 Bronze + 6 Silver + 3 Gold + 1 Platinum | ~2 600 € | **25-35 k€** |
| Année 2 — traction | ~120 | montée du mix (30 % Bronze, 30 % Silver, 20 % Gold) | ~9 000-11 000 € | **100-130 k€** |
| Année 3 — scale | ~250-400 | dont ETI multi-centrales (10 % des clients ≈ 3 500-5 000 €/mois) | — | **300-500 k€** |

Marge brute excellente : l'infra SaaS (console globale) coûte ~50-100 €/mois
pour plusieurs centaines de clients — le vrai coût est le temps humain
(commercial + support). Les concurrents gratuits plafonnent le prix ~2 €/device ;
au-delà, il faut vendre du directory/identité (ce que fait JumpCloud).

## 8. Déploiement

- `docker-compose.yml` pour chaque centrale : API, PostgreSQL, dashboard (reverse proxy
  Caddy/Traefik avec TLS automatique recommandé).
- `docker-compose.yml` pour la console globale : API, PostgreSQL, dashboard.
- Agents : paquets d'installation `.deb` / `.rpm` / `.msi` + binaires signés.
- **Installation agent en 1 commande (curl one-liner)** :
  ```bash
  curl -fsSL https://central.<domaine-client>/install.sh | bash -s -- --token=ug-<uuid>
  ```
  - Le script est servi par **la centrale** (jamais le global — règle d'or §2.1 : c'est
    une réponse à un GET entrant, la centrale ne pousse rien).
  - **Les binaires/paquets agents ne sont servis QUE par chaque centrale**
    (décision 02/11) : le global n'héberge aucun agent téléchargeable — un site
    reste autonome pour installer, même si le SaaS est indisponible.
  - Détecte la distro, télécharge le paquet `.deb`/`.rpm`, vérifie le SHA-256 contre un
    **manifest signé Ed25519** (clé publique embarquée dans le script), installe le
    paquet (service pas encore démarré), puis lance l'enrollment
    `unifiedguard-agent enroll --token …` (token dans le **corps JSON** du POST, jamais
    dans une URL), puis `systemctl enable --now`.
  - Mode « parano » documenté (2 lignes) : télécharger le script, le lire, l'exécuter.
  - Équivalent Windows prévu (J8) : `irm https://central.<domaine>/install.ps1 | iex`.
- Objectif : une centrale s'installe en une commande sur un serveur Docker du client.

## 11. Backup & restore natif — à CODER comme la plateforme (décision 02/11 soir)

La solution de sauvegarde (cible fonctionnelle : « une solution comme UrBackup ») sera **codée
par nous dans UnifiedGuard** — même stack Go, mêmes agents, même architecture 3 niveaux, même
modèle de chiffrement. **PAS d'intégration du produit UrBackup** : le module sera natif, marque
unifiedguard.cloud.

Positionnement : UnifiedGuard gère patching + firewalls + télémétrie + sauvegardes de configs
FW chiffrées ; le module natif ajoutera la sauvegarde de **fichiers** puis d'**images disque**.

### 11.1 Cible fonctionnelle (parité UrBackup progressive)
- Sauvegardes de fichiers : complètes → incrémentales → chunks avec déduplication
- Images disque complètes/incrémentales (niveau bloc) — phase avancée
- Restauration : fichier par fichier via explorateur de snapshots, arborescence complète,
  restauration bare-metal (média de secours bootable)
- Accès web distant aux fichiers sauvegardés (pour les clients finaux)
- Fenêtres de sauvegarde, rétention GFS (quotidien/hebdo/mensuel), notifications (N10)

### 11.2 Architecture technique
- **Le moteur vit DANS l'agent** (pas de second logiciel à installer) : il scanne, découpe,
  compresse, chiffre et pousse — réutilise le canal mTLS existant agent→centrale.
- Conteneur **storage** dédié dans le docker-compose de la centrale (API de stockage de chunks
  + volumes disques).
- Format : chunks CDC (content-defined chunking) ; index de snapshots par host ;
  déduplication par hash SHA-256 (approche éprouvée type restic/borg) ; compression zstd.
- **Chiffrement de bout en bout** : AES-256-GCM par chunk, côté agent ; clé de session
  enveloppée par la clé publique du SITE (même pattern que les backups FW, §6.3).
- Réplication chiffrée centrale → console globale : le global **stocke sans pouvoir lire**.
- Reprise sur interruption : chunks manquants re-demandés à l'agent.

### 11.3 Points durs identifiés (honnêteté d'ingénieur)
- **Windows VSS** (Volume Shadow Copy) pour sauvegarder les fichiers ouverts : indispensable,
  c'est LE point dur natif de Windows.
- **Cohérence Linux** : snapshots LVM / fsfreeze pour les bases de données.
- **Images disque** : lecture bloc + restauration bare-metal = chantier à part entière.
- Effort global : **XL** — le module le plus lourd de la plateforme → d'où sa place en
  vague 5, après le socle.

### 11.4 Phasage proposé

| Phase | Contenu | Effort |
|---|---|---|
| B1 | Fichiers Linux : complète + incrémentale fichier, rétention GFS, restauration par fichiers, dashboard | M |
| B2 | Chunks CDC + déduplication + zstd + reprise sur interruption + réplication globale chiffrée | L |
| B3 | Windows : VSS + sauvegarde fichiers + accès web aux fichiers | L |
| B4 | Images disque + restauration bare-metal | XL |

### 11.5 Impact offres & abonnements
- Nouvelle dimension de quota : **stockage de sauvegarde par site** (en plus du nombre de
  devices) — à intégrer à la grille 5/25/50/100/250 (ex. Starter 25 Go → Platinum 1 To,
  à définir).
- La sauvegarde devient un module facturable à part entière (option par abonnement).

## 12. Ce qui est validé (résumé mis à jour 02/11 soir)

- Architecture 3 niveaux, mTLS, docker-compose, abonnements 5/25/50/100/250.
- Idées fondatrices 1-10 (enrollment, file d'actions, fenêtres, compliance, auto-update,
  durcissement, rollback FW, détection FW, sauvegardes chiffrées par site, paquets sûrs).
- **N1-N15 toutes validées** le 02/11 : break-glass, diff clair, dérive, profils, audit chaîné,
  connectivité prédictive, repo cache, canari, blacklist, notifications, air-gap, intégrité agent,
  automatisation, clé de secours, CVE. Détails : `docs/IDEES.md`.
- **N16 backup natif** : validé « à terme » — le moteur de sauvegarde (cible UrBackup) sera
  **codé comme la plateforme** (Go, dans l'agent, 3 niveaux, chiffrement par site) — phasage B1-B4.
- Nom : **unifiedguard.cloud**.

## 13. Questions ouvertes — TOUTES TRANCHÉES le 02/11 ✅

1. **Stack frontend** → ✅ HTML/CSS/JS vanilla, sans framework ni build (Chart.js pour les
   graphes). Détails : `docs/TECHNO.md`.
2. **Ordre de construction** → ✅ MVP agent Linux → centrale → dashboard, puis Windows,
   puis console globale — en câblant dès le départ N5 (audit chaîné), N12 (intégrité agent),
   N14 (clé de secours), N10 (bus de notifications).
3. **SaaS multi-tenant** → ✅ multi-organisations avec multi-appartenance (users/orgs/
   memberships) — admin global réservé `@dpnac.fr`, orgs créées librement avec mail de
   confirmation ; couvre clients finaux ET MSSP externes.
4. **Périmètre initial agent Windows** → ✅ winget seul au départ (choco/MSI en évolution).
5. **Backup** → ✅ plateforme SÉPARÉE (`backup.<domaine-client>`), projet distinct.
6. **Règle des flux** → ✅ actée (§2.1) : agent↔centrale (agent initiateur), centrale→global
   push, le global ne pousse rien (répond aux pulls).

## 14. Stack technique (validée 02/11 — détails dans `docs/TECHNO.md`)

Go partout (agents + hub + fleet) · PostgreSQL 17 · WebSocket mTLS (agent initiateur) +
REST/JSON · HTML/CSS/JS vanilla (UI embarquée via go:embed, zéro npm) · Chart.js ·
Caddy 2 (TLS auto) · Docker Compose · Ed25519 (signatures) + AES-256-GCM (chiffrement) +
RSA-OAEP/X25519 (enveloppe clés de site) + Argon2id (clé de secours) · nfpm/WiX (packaging
agents) · golangci-lint + go test · Gitea Actions si activé sur git.dpnac.cloud.

## 15. Réponse NIS2 — alignement réglementaire (analyse 02/11)

L'objectif n'est PAS de vendre « un RMM de plus » : UnifiedGuard se positionne comme
**la brique technique de conformité NIS2** pour les entités couvertes (essentielles
et importantes) — patching, gestion des FW, piste d'audit infalsifiable — avec en
plus la souveraineté des données (rien ne quitte le site).

### 15.1 Le marché visé par NIS2

- Transposition française (LopMI 2 / ordonnance) : ~1 500-3 000 entités **essentielles**
  (énergie, transport, santé, finance, eau, administration…) et **importantes**
  (PME/ETI de 50-250 salariés dans les secteurs couverts), **plus leurs sous-traitants
  et prestataires** — qui doivent démontrer leur conformité pour garder le contrat.
- Ce qui se vend aujourd'hui à ces entités : du conseil (audits à 10-30 k€) et des
  GRC démesurés (ServiceNow, OneTrust). **Le maillon manquant : l'outil opérationnel
  qui fait la conformité au quotidien** et produit la preuve le jour du contrôle.
- Fenêtre temporelle : la conformité se joue sur 2026-2028 (période de contrôle ANSSI).

### 15.2 Mapping mesures NIS2 → plateforme (ce qui est déjà prévu au SPEC)

| Mesure NIS2 (annexe I) | Fonction UnifiedGuard | Statut SPEC |
|---|---|---|
| Gestion des vulnérabilités (analyse + correctifs) | Patch manager avec CVE par sévérité (N15), fenêtres de maintenance, canari (N8) | ✅ prévu |
| Sécurité du réseau (segmentation, FW) | Gestion centralisée des FW, détection de dérive (N3), rollback commit-confirm | ✅ prévu |
| Gestion des incidents (détection, réponse) | Bus de notifications (N10), break-glass (N1), automatisation (N13), télémétrie | ✅ prévus |
| Sécurité de la chaîne d'approvisionnement | Auto-update signé, intégrité agent (N12), manifeste Ed25519, audit chaîné | ✅ prévus |
| Contrôle d'efficacité (audits, pentests) | **Audit chaîné hash-link (N5)** — piste d'audit infalsifiable, double vérification | ✅ **codé (J0)** |
| Continuité d'activité | Backup chiffré par site (§11), restauration | ✅ prévu |
| Gestion des comptes / MFA | MFA forte WebAuthn/TOTP (§5.1.2), rôles, break-glass tracé | ✅ prévus |
| **Preuve / reporting de conformité** | **Rapport de conformité 1 clic** (extraction de l'audit chaîné) | ❌ **À CODER — le gap** |

### 15.3 Le gap à combler : le rapport de conformité 1 clic

La réglementation exige de **prouver**. Il manque donc un livrable, le vrai argument
commercial : un **rapport NIS2 de conformité technique** généré depuis l'audit chaîné :

1. **Inventaire des actifs** (hosts, OS, agents en ligne, FW actifs) — J5.
2. **État de patching par host** : % à jour, retard par sévérité CVE (N15), dérogations
   tracées dans l'audit (qui, quand, pourquoi).
   → mesure « gestion des vulnérabilités ».
3. **Hygiène FW** : règles actives vs référence, dérives détectées (N3), historique
   des rollbacks et incidents → mesure « sécurité du réseau ».
4. **Journal des incidents et actions** : extrait horodaté + **preuve d'intégrité**
   (chaîne de hash + résultat `/api/v1/audit/verify`) → « contrôle d'efficacité ».
5. **Preuves cryptographiques** : signatures Ed25519 des binaires agent, self-hash
   dans chaque heartbeat (N12) → « chaîne d'approvisionnement ».
6. **Export** : PDF signé + JSON horodaté, conservé côté client — valable le jour du
   contrôle même si la plateforme a évolué depuis.

Ce rapport transforme l'audit chaîné (déjà codé en J0) en argument commercial.
Il devient le **module Premium NIS2**, facturable par site.

### 15.4 Tarification alignée NIS2 (option premium par centrale)

| Élément | Prix indicatif |
|---|---|
| Module « Conformité NIS2 » (rapports 1 clic, scoring par mesure, export signé) | +39 € HT/mois par centrale (petites offres), +49 € pour Gold/Platinum |
| Pack conformité (audit initial : entretien + état des lieux + rapport) | ~990 € HT ponctuel |
| Support premium (SLA 4 h) | 500-1 500 €/an |

Raisonnement : le contrôle NIS2 n'est pas un abonnement que la DSI peut couper en
crise — c'est une **assurance**. Un pack à ~50 €/mois contre un risque de sanction
jusqu'à 10 M€ ou 2 % du CA pour les essentielles, ou 7 M€ / 1,4 % pour les importantes,
est une vente par le budget « conformité » (qui existe déjà), pas par le budget
« tooling » (qu'il faut créer). On vend la couche conformité, pas la couche outil.

### 15.5 Positionnement commercial

1. **Ne pas se battre sur le terrain RMM saturé** (NinjaOne, Atera, Tactical RMM…).
2. **Vendre la conformité** : « l'outil qui fait NIS2 au quotidien et prouve le jour
   du contrôle » — budget existant, urgence réglementaire, différenciation claire.
3. **Le canal** : plutôt que la vente directe TPE (grind interminable), passer par
   (a) les **MSP/ESN** qui accompagnent déjà ces entités (une centrale par client,
   console de fédération = vue MSP), (b) les **cabinets de conseil** qui prescrivent
   la brique technique à leurs clients NIS2 (l'audit initial à 990 € peut être
   refacturé par le cabinet).
4. **Preuve souveraineté** : données métier chiffrées par site, jamais lisible par
   l'éditeur — argument face aux outils US (CLOUD Act), naturel en France.

### 15.6 Ce que ça change au produit (à intégrer au backlog)

- **N17 — Rapport de conformité NIS2** (P1, module premium) : extraction depuis
  l'audit chaîné : inventaire, patching par sévérité, hygiène FW, incidents, preuves
  cryptographiques, export PDF/JSON signé. Dépend de : N15 (CVE), N3 (dérive), J5.
- **N18 — Scoring par mesure NIS2** : badge « conformité » par host/site (à jour /
  à surveiller / non conforme), visible sur le dashboard — le vendeur a une démo
  qui « parle contrôle ANSSI », pas seulement des graphes.
- **N19 — Registre des dérogations** : chaque MAJ non appliquée ou règle FW tolérée
  doit être justifiée (qui, pourquoi, jusqu'à quand) — le registre NIS2 classique.
  Alimente le rapport.
- Jalon J10 suggéré (après J8-J9) : livraison du module conformité NIS2.

### 15.7 Honnêteté de la vente (ce qu'on ne revendique PAS)

- **Pas un logiciel « certifié ANSSI »** ni un référentiel : la certification NIS2
  n'existe pas — l'entité démontre, l'ANSSI apprécie. On fournit des **preuves
  techniques**, pas une conformité « garantie ».
- **Pas un GRC** : pas de gestion de politique documentaire, ni de formation du
  personnel, ni d'analyse de risque EBIOS au sens formalisée. Le périmètre est le
  **pilotage technique** (patching, FW, inventaire, audit, restauration) — brique
  parmi d'autres de la conformité globale.
- Position recommandée : « UnifiedGuard ne remplace pas votre consultant — il le
  rend audité et vérifiable. »
### 15.8 Conclusion : est-ce une niche ?

- Le marché RMM global : non, saturé.
- La **niche** : « brique technique de conformité NIS2 pour entités françaises
  couvertes + leurs prestataires », vendue via MSP/conseil, appuyée sur l'audit
  chaîné (existant) et le rapport de conformité (à coder, N17-N19).
- C'est une fenêtre temporelle — les concurrents majeurs ajouteront des modules
  NIS2 ; la fenêtre est de quelques années.

