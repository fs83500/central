#!/bin/sh
# Dev launcher for the UnifiedGuard hub (J2): main listener = agent mTLS
# (HUB_LISTEN, TLS), second listener = dashboard UI (HUB_DEV_UI_LISTEN, plain
# HTTP) so the sandbox preview proxy can reach it. Dev only — NEVER prod.
cd "$(dirname "$0")/.."
export HUB_LISTEN=:8801 HUB_DEV_UI_LISTEN=:8802 HUB_DEV_TLS=1 HUB_CA_DIR=/tmp/hub-ca
# Preview proxy prefix (stripped server-side IF the proxy forwards it as-is;
# relative-path UI means it also works when the proxy already strips it).
export HUB_UI_PREFIX=${HUB_UI_PREFIX:-/preview/codex/8802}
export HUB_DATABASE='postgres://unifiedguard:test1234@127.0.0.1:55433/ug_hub_test?sslmode=disable'
export HUB_DOMAIN=central.test.fr HUB_DEV=1
export HUB_DEV_ADMIN=admin@test.fr HUB_DEV_ADMIN_PASSWORD='S3cret!pass'
exec ./bin/hub