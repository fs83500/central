# Recette J0 — squelette + audit chaîné

> Version testée : j0 (built 2026-11-02T17:00:00Z). PostgreSQL 15+ requis.
> Durée : ~10 minutes. Tout se fait depuis la racine du repo.

## 0. Préparation (une fois)

```bash
# PostgreSQL de test sur port non standard (évite tout conflit)
docker run -d --name ug-pg -p 55432:5432 \
  -e POSTGRES_PASSWORD=test1234 -e POSTGRES_USER=unifiedguard \
  -e POSTGRES_DB=ug_hub_test postgres:15
```

## 1. Lint + tests

```bash
export UG_TEST_DSN="postgres://unifiedguard:test1234@127.0.0.1:55432/ug_hub_test?sslmode=disable"
go vet ./...
golangci-lint run ./...        # attendu : 0 issue
go test ./... -count=1         # attendu : ok pour tous les packages
```

**Attendu** : `ok git.dpnac.cloud/dpnac/central/internal/audit` — les tests
vérifient la chaîne côté DB **et** la détection de falsification.

## 2. Migrations + binaires

```bash
make migrate-hub   DSN="postgres://unifiedguard:test1234@127.0.0.1:55432/ug_hub_test?sslmode=disable"
make migrate-fleet DSN="postgres://unifiedguard:test1234@127.0.0.1:55432/ug_fleet_test?sslmode=disable"
make build
```

**Attendu** : `bin/agent`, `bin/hub`, `bin/fleet` créés.

## 3. Version + self-hash de l'agent (N12)

```bash
./bin/agent version
```

**Attendu** : `unifiedguard-agent j0 (built …)` puis `self-hash <64 hex>`.
Le hash change si le binaire change — c'est le garde-fou d'intégrité.

## 4. Hub : ping + audit

```bash
HUB_DATABASE="$UG_TEST_DSN" ./bin/hub &
sleep 1
curl -s localhost:8080/api/v1/ping         # {"ok":true,"version":"j0 …","hash":"…"}
curl -s localhost:8080/api/v1/audit/verify # chaîne vide → {"ok":true,"events":0}
```

## 5. Audit chaîné — le cœur de la recette

```bash
# deux événements d'exemple (le hub réel les créera via l'API)
psql "$UG_TEST_DSN" <<'SQL'
INSERT INTO audit_events (ts, actor, actor_type, action, target_type, target_id, params, result)
VALUES (now(), 'admin@acme.fr', 'user', 'boot', 'system', 'hub', '{}', 'ok');
INSERT INTO audit_events (ts, actor, actor_type, action, target_type, target_id, params, result)
VALUES (now(), 'agent:u1', 'agent', 'host.enroll', 'host', 'h1', '{}', 'ok');
SQL
curl -s localhost:8080/api/v1/audit/verify   # {"ok":true,"events":2}
```

### 5b. Falsification — doit être DÉTECTÉE

```bash
psql "$UG_TEST_DSN" -c "UPDATE audit_events SET result='denied' WHERE seq=1;"
curl -s localhost:8080/api/v1/audit/verify   # {"ok":false,"error":"chain verification failed"}
```

**Attendu** : `ok:false` — et ce, même si on recalcule les hashes à la main :
la modification d'un champ SANS recalculer les hash casse la chaîne, et le
vérificateur Go indépendant **et** `ug_audit_verify()` SQL le voient tous les
deux. Remettre la valeur d'origine :

```bash
psql "$UG_TEST_DSN" -c "UPDATE audit_events SET result='ok' WHERE seq=1;"
curl -s localhost:8080/api/v1/audit/verify   # {"ok":true,"events":2}
```

### 5c. Suppression — doit être DÉTECTÉE

```bash
psql "$UG_TEST_DSN" -c "DELETE FROM audit_events WHERE seq=1;"
curl -s localhost:8080/api/v1/audit/verify   # ok:false (prev_hash ne raccroche plus)
psql "$UG_TEST_DSN" -c "TRUNCATE audit_events RESTART IDENTITY;"
curl -s localhost:8080/api/v1/audit/verify   # {"ok":true,"events":0} (chaîne vide = valide)
```

## 6. Critères de passage J0

- [ ] `go vet` + `golangci-lint` : 0 problème
- [ ] `go test ./...` : tout `ok` (avec `UG_TEST_DSN`)
- [ ] `./bin/agent version` : version + self-hash affichés
- [ ] `/api/v1/ping` : `ok:true`
- [ ] `/api/v1/audit/verify` : `ok:true` chaîne vide ET chaîne saine
- [ ] Falsification (UPDATE) → `ok:false` **détectée**
- [ ] Suppression (DELETE) → `ok:false` **détectée**
- [ ] Restauration → `ok:true`

## Notes techniques

- La chaîne d'audit est **tamper-evident**, pas chiffrée : n'importe qui avec
  un accès SQL peut lire, mais ne peut pas modifier/supprimer sans que ça se
  voie. La signature de tête (Ed25519, `SignHead`) arrive avec la fédération
  (J7) pour lier la chaîne hub → global.
- Double vérification = défense en profondeur : `ug_audit_verify()` (SQL) et
  `VerifyChainPG` (Go, forme canonique jsonb reproduite à l'octet près)
  doivent être d'accord ; un désaccord entre les deux = alerte.
- Les tables appartiennent à `unifiedguard` (OWNER) — le hub ne doit JAMAIS
  tourner avec le superuser PostgreSQL.