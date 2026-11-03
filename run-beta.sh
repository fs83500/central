#!/bin/sh
# UnifiedGuard BÊTA — lancement SANS Docker (binaire + PostgreSQL existant).
# Prérequis : PostgreSQL 14+ accessible, bin/ (hub + agent) construits.
#
#   ./run-beta.sh                # première fois : pose 3 questions
#   HUB_DATABASE=… ./run-beta.sh # tout en env
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"

DB="${HUB_DATABASE:-}"
if [ -z "$DB" ]; then
  echo "DSN PostgreSQL requis, ex : postgres://user:pass@127.0.0.1:5432/unifiedguard?sslmode=disable"
  printf "DSN : "; read -r DB
fi
DOMAIN="${HUB_DOMAIN:-central.localhost}"
ADMIN="${HUB_BOOTSTRAP_ADMIN:-}"
if [ -z "$ADMIN" ]; then
  printf "Email du premier admin : "; read -r ADMIN
fi
PASS="${HUB_BOOTSTRAP_PASSWORD:-}"
if [ -z "$PASS" ]; then
  printf "Mot de passe de cet admin : "; read -r PASS
fi

mkdir -p "$DIR/data" "$DIR/data/ca" "$DIR/data/sitekey" "$DIR/data/tls"

HUB_LISTEN="${HUB_LISTEN:-:8080}" \
HUB_DOMAIN="$DOMAIN" \
HUB_DATABASE="$DB" \
HUB_MIGRATIONS=on \
HUB_CA_DIR="$DIR/data/ca" \
HUB_SITE_KEY_DIR="$DIR/data/sitekey" \
HUB_BOOTSTRAP_ADMIN="$ADMIN" \
HUB_BOOTSTRAP_PASSWORD="$PASS" \
HUB_MFA_LOG_BETA=1 \
HUB_DEV_TLS=1 \
HUB_TLS_DIR="$DIR/data/tls" \
exec "$DIR/bin/hub"