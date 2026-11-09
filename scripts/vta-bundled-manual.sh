#!/usr/bin/env bash
# A bundled gateway and sidecar you can poke at by hand: real containers from the
# shipped Compose example, left running, with the dashboard on https://localhost:8443
# and a normal passkey login (the first passkey you register becomes the admin).
#
#   GATEWAY_IMAGE=agent-gateway:stock-test VTA_IMAGE=vta-service:bundled-test \
#     ./scripts/vta-bundled-manual.sh up
#   ./scripts/vta-bundled-manual.sh login                  # how to log in and get a token
#   AG_TOKEN=... ./scripts/vta-bundled-manual.sh status    # connection state, from the API
#   AG_TOKEN=... ./scripts/vta-bundled-manual.sh sign      # issue a credential, show who signed it
#   ./scripts/vta-bundled-manual.sh logs                   # both containers' logs
#   ./scripts/vta-bundled-manual.sh down                   # remove containers, volumes and files
#
# Everything lives in tmp/vta-bundled-manual (override with DIR=). Needs port 8443
# free and `make config-debug` run once. Plain `docker compose` works in that
# folder too (it holds a .env); restart the gateway first, then `vta`.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${DIR:-${repo}/tmp/vta-bundled-manual}"
BASE="https://localhost:8443"
# shellcheck source=scripts/vta-bundled-lib.sh
source "${repo}/scripts/vta-bundled-lib.sh"

dc() { (cd "${DIR}" && docker compose -p vtabundledmanual "$@"); }
strip() { sed 's/\x1b\[[0-9;]*m//g'; }
api() {
  : "${AG_TOKEN:?set AG_TOKEN (run: $0 login)}"
  curl -sk -H "Authorization: Bearer ${AG_TOKEN}" "$@"
}

case "${1:-}" in
up)
  : "${GATEWAY_IMAGE:?set GATEWAY_IMAGE}" "${VTA_IMAGE:?set VTA_IMAGE}"
  docker image inspect "${GATEWAY_IMAGE}" "${VTA_IMAGE}" >/dev/null
  [[ -e "${DIR}/.env" ]] && { echo "already prepared in ${DIR}; run 'down' first" >&2; exit 1; }
  prepare_stack "${DIR}"
  python3 - "${DIR}/config/gateway.json" <<'PY'
import json, sys
p = sys.argv[1]
g = json.load(open(p))
g["webauthn"] = {"rp_id": "localhost", "external_origin": "https://localhost:8443"}
g["cors"] = sorted(set(g.get("cors", [])) | {"https://localhost:8443", "http://localhost:8080"})
# The gateway names its own DID after an https external address when it has one, and
# a trust agent resolves a localhost did:webvh over plain http only. With none, the
# DID is named after the plain-http listener (localhost:8080), which a trust agent
# in the gateway's network can fetch. The HTTPS listener and dashboard are unchanged.
for listener in g.get("listeners", []):
    listener["external_urls"] = [u for u in listener.get("external_urls", []) if not u.startswith("https://")]
json.dump(g, open(p, "w"), indent=2)
PY
  cat > "${DIR}/docker-compose.override.yml" <<YML
services:
  gateway:
    ports:
      - "8080:8080"
YML
  export_stack_env
  cat > "${DIR}/.env" <<ENV
GATEWAY_IMAGE=${GATEWAY_IMAGE}
VTA_IMAGE=${VTA_IMAGE}
TG_ENCRYPTION_KEY=${TG_ENCRYPTION_KEY}
AG_BACKUP_ENCRYPTION_KEY=${AG_BACKUP_ENCRYPTION_KEY}
AG_IDENTITY_HASH_PEPPER=${AG_IDENTITY_HASH_PEPPER}
ENV
  dc up -d
  echo "waiting for the bootstrap verdict..."
  for _ in $(seq 1 120); do
    l="$(dc logs gateway 2>&1 | strip)"
    [[ "${l}" == *"the bundled trust agent is connected"* ]] && { echo "connected"; break; }
    [[ "${l}" == *"the bundled trust agent is not connected"* ]] && { echo "NOT connected:"; echo "${l}" | grep -a "trust agent" | tail -3; break; }
    sleep 1
  done
  echo "dashboard: ${BASE}/dashboard (self-signed certificate; run '$0 login')"
  ;;
login)
  cat <<TXT
1. Open ${BASE}/dashboard and accept the certificate warning.
2. Register a passkey when asked (the first one becomes the administrator).
3. Open ${BASE}/trust-agent to see the connection state.
4. For the status and sign commands, take a token from the browser console:
     copy(sessionStorage.getItem('session_token'))
   then:  AG_TOKEN=<paste> $0 status
TXT
  ;;
status) api "${BASE}/api/v1/vta/status" | python3 -m json.tool ;;
sign)
  api -X POST "${BASE}/api/v1/identity/issue" -H 'Content-Type: application/json' \
    -d "{\"agent_identity\":{\"sub\":\"manual-check-$(date +%s)\"}}" | python3 -c '
import sys, json, base64
b = json.load(sys.stdin)
d = lambda s: json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
h, p = [d(x) for x in b["credential"].split(".")[:2]]
iss = p.get("issuer")
print("alg   :", h.get("alg"))
print("kid   :", h.get("kid"))
print("issuer:", iss.get("id") if isinstance(iss, dict) else iss)
print("subject:", p.get("credentialSubject", {}).get("id"))
print("is_new:", b.get("is_new"))'
  cat <<TXT
A pass: kid is gateway-jwt-N (the key the sidecar holds), the subject is a did:key minted
inside the sidecar, and '$0 logs' shows "payload signed key_id=gateway-jwt-N" in the vta
output and a token_signed audit record in the gateway output. The issuer is the did:key of
that signing key; it is not the sidecar's own DID (bootstrap.vta_did in 'status').
TXT
  ;;
logs)
  echo "== gateway"; dc logs gateway 2>&1 | strip | grep -a -i "trust agent\|vta\|bootstrap" | tail -20
  echo "== vta"; dc logs vta 2>&1 | strip | grep -a "enrolled\|payload signed\|key created\|listening" | cut -c1-200 | tail -20
  ;;
down) dc down -v 2>/dev/null || true; rm -rf "${DIR}"; echo "removed" ;;
*) sed -n 2,16p "$0"; exit 2 ;;
esac
