#!/usr/bin/env bash
# Recreate the full working tree: clone eSignet and ThunderID at the exact commits this work is
# based on and apply the Native SSO patches from patches/. Run from the repository root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ESIGNET_BASE=141a9d37      # mosip/esignet, branch develop-go
THUNDERID_BASE=51458d79979f # thunder-id/thunderid, branch 1.1.x (the commit esignet-service pins)

clone_and_patch() { # name, url, base commit
  local dir="$ROOT/$1"
  if [ ! -d "$dir/.git" ]; then
    git clone "$2" "$dir"
  fi
  git -C "$dir" checkout -q -B native-sso "$3"
  git -C "$dir" am -q "$ROOT"/patches/"$1"/*.patch
  echo "$1: native-sso branch at $(git -C "$dir" rev-parse --short HEAD)"
}

clone_and_patch thunderid https://github.com/thunder-id/thunderid.git "$THUNDERID_BASE"
clone_and_patch esignet https://github.com/mosip/esignet.git "$ESIGNET_BASE"
echo "Done. esignet-service resolves ThunderID from ../../thunderid/backend (see its go.mod)."
