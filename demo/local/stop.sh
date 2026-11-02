#!/usr/bin/env bash
# Stop the processes started by demo/local/start.sh. Data under demo/.run is kept; delete that
# directory for a clean slate.
set -uo pipefail
RUN="$(cd "$(dirname "$0")/.." && pwd)/.run"
for svc in oidc-ui esignet identity-stub; do
  if [ -f "$RUN/$svc.pid" ]; then
    kill "$(cat "$RUN/$svc.pid")" 2>/dev/null && echo "stopped $svc"
    rm -f "$RUN/$svc.pid"
  fi
done
git -C "$RUN/../../esignet" checkout -q -- oidc-ui/public/env-config.js 2>/dev/null
pkill -f "vite --port 3000" 2>/dev/null && echo "stopped vite"
[ -d "$RUN/pg" ] && pg_ctl -D "$RUN/pg" stop -m fast >/dev/null 2>&1 && echo "stopped postgres"
exit 0
