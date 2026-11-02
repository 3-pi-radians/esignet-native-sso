#!/usr/bin/env bash
# Start a LOCAL, Docker-free Native SSO environment:
#   PostgreSQL (port 5455, data under demo/.run/pg, trust auth: local dev only)
#   identity-stub (port 8082; local test double for MOSIP mock-identity-system, see its main.go)
#   esignet-service built from ../esignet with the Native SSO changes (port 8088)
#   oidc-ui, eSignet's login/consent web UI, Vite dev server (port 3000)
#
# Usage: demo/local/start.sh        # start everything, wait for health
#        demo/local/stop.sh         # stop everything
#
# With Docker available prefer demo/docker-compose.yml, which uses the official MOSIP images.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN="$ROOT/demo/.run"
mkdir -p "$RUN"

: "${PG_PORT:=5455}"
: "${ESIGNET_PORT:=8088}"
: "${STUB_ADDR:=127.0.0.1:8082}"
: "${MOSIP_ESIGNET_HOST:=http://localhost:$ESIGNET_PORT}"
# hCaptcha's public test site key (always passes; same as eSignet CI). With no
# MOSIP_ESIGNET_CAPTCHA_VALIDATOR_URL set, eSignet does not validate captcha tokens server-side.
# Short-lived by default so expiry can be demonstrated; raise for real use.
: "${MOSIP_ESIGNET_DEVICE_SECRET_EXPIRY_SECONDS:=3600}"

wait_for() { # url, name
  for _ in $(seq 1 90); do
    if curl -fsS "$1" >/dev/null 2>&1; then echo "  $2 is up"; return 0; fi
    sleep 1
  done
  echo "  $2 did not become healthy; see $RUN/*.log" >&2
  return 1
}

echo "[1/4] PostgreSQL on :$PG_PORT"
if [ ! -d "$RUN/pg" ]; then
  initdb -D "$RUN/pg" -U postgres -A trust --locale=en_US.UTF-8 -E UTF8 >"$RUN/initdb.log"
fi
if ! pg_ctl -D "$RUN/pg" status >/dev/null 2>&1; then
  pg_ctl -D "$RUN/pg" -o "-p $PG_PORT -k $RUN" -l "$RUN/postgres.log" start >/dev/null
  for _ in $(seq 1 30); do pg_isready -h 127.0.0.1 -p "$PG_PORT" >/dev/null 2>&1 && break; sleep 1; done
fi
if ! psql -h 127.0.0.1 -p "$PG_PORT" -U postgres -lqt | cut -d'|' -f1 | grep -qw mosip_esignet; then
  psql -h 127.0.0.1 -p "$PG_PORT" -U postgres -q -v ON_ERROR_STOP=1 \
    -f "$ROOT/esignet/docker-compose/init-ci.sql" >"$RUN/schema.log" 2>&1
  echo "  schema created"
fi

echo "[2/4] identity-stub on $STUB_ADDR"
(cd "$ROOT/demo/identity-stub" && go build -o "$RUN/identity-stub" .)
IDENTITY_STUB_ADDR="$STUB_ADDR" nohup "$RUN/identity-stub" </dev/null >"$RUN/identity-stub.log" 2>&1 &
echo $! >"$RUN/identity-stub.pid"
wait_for "http://$STUB_ADDR/health" identity-stub

echo "[3/4] esignet-service on :$ESIGNET_PORT"
(cd "$ROOT/esignet/esignet-service" && CGO_ENABLED=0 go build -o "$RUN/esignet" ./cmd/esignet)
(
  cd "$ROOT/esignet/esignet-service"
  PORT="$ESIGNET_PORT" \
  MOSIP_ESIGNET_HOST="$MOSIP_ESIGNET_HOST" \
  DATA_DIR=./data \
  DATABASE_HOST=127.0.0.1 DATABASE_PORT="$PG_PORT" DATABASE_NAME=mosip_esignet \
  DATABASE_USERNAME=postgres DATABASE_PASSWORD=postgres \
  MOSIP_ESIGNET_CACHE_TYPE=inmemory \
  KEYMANAGER_DB_SCHEMA=esignet KEYMANAGER_KEYSTORE_TYPE=PKCS12 \
  KEYMANAGER_PKCS12_FILE_PATH="$RUN/keystore.pfx" \
  KEYMANAGER_PKCS12_PASSWORD="${KEYMANAGER_PKCS12_PASSWORD:-local-dev-only}" \
  KEYMANAGER_PKCS12_ALLOW_INSECURE_SOFTWARE_KEYSTORE=true \
  MOSIP_ESIGNET_AUTHN_PROVIDER=mock \
  MOSIP_ESIGNET_MOCK_DOMAIN_URL="http://$STUB_ADDR" \
  MOSIP_ESIGNET_DEVICE_SECRET_EXPIRY_SECONDS="$MOSIP_ESIGNET_DEVICE_SECRET_EXPIRY_SECONDS" \
  MOSIP_ESIGNET_CORS_ALLOWED_ORIGIN_REGEX='^http://localhost:3000$' \
  MOSIP_ESIGNET_OIDC_UI_HOSTNAME=localhost MOSIP_ESIGNET_OIDC_UI_PORT=3000 MOSIP_ESIGNET_OIDC_UI_SCHEME=http \
  MOSIP_ESIGNET_CAPTCHA_SITE_PROVIDER=hcaptcha \
  MOSIP_ESIGNET_CAPTCHA_SITE_KEY=10000000-ffff-ffff-ffff-000000000001 \
  LOG_LEVEL="${LOG_LEVEL:-info}" \
  nohup "$RUN/esignet" </dev/null >"$RUN/esignet.log" 2>&1 &
  echo $! >"$RUN/esignet.pid"
)
wait_for "http://localhost:$ESIGNET_PORT/health" esignet-service

echo "[4/4] oidc-ui (login / consent pages) on :3000"
if [ "${SKIP_UI:-}" = "" ]; then
  (cd "$ROOT/esignet/oidc-ui" && [ -d node_modules ] || npm ci --no-audit --no-fund >"$RUN/oidc-ui-install.log" 2>&1)
  # The UI's dev-mode connectivity check polls <api>/actuator/health, which eSignet Go does not serve
  # (it has /health, without CORS headers), so the page would show "No Internet Connection". For
  # this local run, poll a same-origin file instead (stop.sh restores env-config.js).
  ENV_JS="$ROOT/esignet/oidc-ui/public/env-config.js"
  grep -q "POLLING_URL" "$ENV_JS" || echo "window._env_.POLLING_URL = '/favicon.ico';" >>"$ENV_JS"
  (cd "$ROOT/esignet/oidc-ui" && VITE_API_URL="http://localhost:$ESIGNET_PORT" nohup npx vite --port 3000 --strictPort </dev/null \
    >"$RUN/oidc-ui.log" 2>&1 & echo $! >"$RUN/oidc-ui.pid")
  wait_for "http://localhost:3000/" oidc-ui
fi
echo "Ready. Discovery: $MOSIP_ESIGNET_HOST/.well-known/openid-configuration"
