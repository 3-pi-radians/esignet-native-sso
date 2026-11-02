#!/usr/bin/env bash
# Register the demo Super App and Child App as eSignet OIDC clients.
#
# Each app generates its private_key_jwt client key inside the Android Keystore on first launch and
# writes the PUBLIC key to its private files/client-jwk.json. This script reads those public keys
# from the connected device/emulator (debug builds only: `adb shell run-as`) and registers:
#
#   nsso-demo-super-app  authorization_code + token-exchange, allowed_authorization_scopes=[device_sso],
#                        device_sso_allowed_clients=[nsso-demo-child-app]
#   nsso-demo-child-app  authorization_code (re-consent) + token-exchange (Native SSO)
#
# Both use the same relying party (vendor), PAR, PKCE and DPoP-bound access tokens.
#
# Usage: demo/register-clients.sh                 # launch both apps once first
#        RESET=1 demo/register-clients.sh         # local stack only: re-create after an app reinstall
#        SUPER_JWK=a.json CHILD_JWK=b.json demo/register-clients.sh   # keys from files instead of adb
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${ESIGNET_URL:=http://localhost:8088}"
: "${ADMIN_TOKEN:=local-no-scope}"   # local stack: client-mgmt scope enforcement is off
SUPER_ID=nsso-demo-super-app
CHILD_ID=nsso-demo-child-app
RP_ID=nsso-demo-vendor

read_jwk() { # package
  adb shell run-as "$1" cat files/client-jwk.json 2>/dev/null || {
    echo "Could not read $1's public key. Install the debug APK and open the app once." >&2; exit 1; }
}
SUPER_KEY="$( [ -n "${SUPER_JWK:-}" ] && cat "$SUPER_JWK" || read_jwk io.mosip.nativesso.superapp )"
CHILD_KEY="$( [ -n "${CHILD_JWK:-}" ] && cat "$CHILD_JWK" || read_jwk io.mosip.nativesso.childapp )"

if [ -n "${RESET:-}" ]; then
  psql -h 127.0.0.1 -p "${PG_PORT:-5455}" -U postgres -d mosip_esignet -q \
    -c "DELETE FROM esignet.client_detail WHERE id IN ('$SUPER_ID','$CHILD_ID');"
  # eSignet caches clients; restart it so the deleted rows are not served from cache.
  "$ROOT/demo/local/stop.sh" >/dev/null && "$ROOT/demo/local/start.sh" >/dev/null
fi

register() { # client_id redirect_uri grant_types_json additional_config_json public_jwk
  local body
  body=$(cat <<EOF
{"requestTime":"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)","request":{
 "clientId":"$1","clientName":"$1","clientNameLangMap":{"eng":"$1"},"relyingPartyId":"$RP_ID",
 "logoUri":"https://mosip.io/images/logo.png","redirectUris":["$2"],
 "userClaims":["name","email","phone_number","gender","birthdate"],
 "authContextRefs":["mosip:idp:acr:generated-code"],"publicKey":$5,
 "grantTypes":$3,"clientAuthMethods":["private_key_jwt"],"additionalConfig":$4}}
EOF
)
  local resp
  resp=$(curl -sS -X POST "$ESIGNET_URL/client-mgmt/client" -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -d "$body")
  if echo "$resp" | grep -q '"errorCode"'; then
    echo "$1: $resp" >&2
    echo "(already registered with another key? re-run with RESET=1 against the local stack)" >&2
    exit 1
  fi
  echo "$1: registered"
}

COMMON='"require_pushed_authorization_requests":true,"dpop_bound_access_tokens":true,"require_pkce":true'
TE='["authorization_code","urn:ietf:params:oauth:grant-type:token-exchange"]'

register "$SUPER_ID" "io.mosip.nativesso.superapp://callback" "$TE" \
  "{$COMMON,\"allowed_authorization_scopes\":[\"device_sso\"],\"device_sso_allowed_clients\":[\"$CHILD_ID\"]}" "$SUPER_KEY"
register "$CHILD_ID" "io.mosip.nativesso.childapp://callback" "$TE" "{$COMMON}" "$CHILD_KEY"
