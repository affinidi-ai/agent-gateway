#!/usr/bin/env bash
# Live end-to-end check of the bundled sidecar as real containers, using the
# shipped Compose example in config/examples/vta-bundled/. Not part of CI: it
# needs Docker, two built images and a prepared local environment.
#
#   GATEWAY_IMAGE=agent-gateway:bundled-test VTA_IMAGE=vta-service:bundled-test \
#     ./scripts/vta-bundled-compose-e2e.sh
#
# Build the VTA image from verifiable-trust-infrastructure `gateway-integration`
# (`docker build -t vta-service:bundled-test .`) and the gateway image from this
# repository (`docker build -t agent-gateway:bundled-test .`). Run
# `make config-debug` once so `envs/local` and `envs/certs` exist.
#
# Uses its own temporary directory and compose project, and removes both on exit
# (KEEP=1 keeps them). Needs port 8443 free.
#
# Checks what the process-level script cannot: that the two containers really
# share one loopback, that the shared bootstrap volume is writable by both users,
# that the entrypoint runs inside the real VTA image with its secret mounted,
# and that nothing outside the pair can reach the trust agent.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
GATEWAY_IMAGE="${GATEWAY_IMAGE:?set GATEWAY_IMAGE}"
VTA_IMAGE="${VTA_IMAGE:?set VTA_IMAGE}"
WAIT_SECS="${WAIT_SECS:-120}"

for f in "${repo}/envs/local/config/config.toml" "${repo}/envs/certs/cert.pem"; do
  [[ -e "${f}" ]] || { echo "missing: ${f}" >&2; exit 2; }
done
docker image inspect "${GATEWAY_IMAGE}" "${VTA_IMAGE}" >/dev/null

work="$(mktemp -d)"
project="vtabundled$$"
cp -R "${repo}/config/examples/vta-bundled/." "${work}/"
mkdir -p "${work}/config" "${work}/certs" "${work}/secrets"

cleanup() {
  (cd "${work}" && docker compose -p "${project}" down -v >/dev/null 2>&1) || true
  [[ "${KEEP:-}" == "1" ]] && echo "kept ${work}" || rm -rf "${work}"
}
trap cleanup EXIT

cp -R "${repo}/envs/local/config/." "${work}/config/"
cp "${repo}/envs/certs/cert.pem" "${repo}/envs/certs/key.pem" "${work}/certs/"
python3 - "${work}" "${repo}" <<'PY'
import sys
work, repo = sys.argv[1:3]
p = work + "/config/config.toml"
s = open(p).read()
s = s.replace(repo + "/envs/local/certs", "/app/certs").replace(repo + "/envs/local", "/app")
s = s.replace("TRUST_GATEWAY_MASTER_KEY", "TG_ENCRYPTION_KEY")
s = s.replace("env://TRUST_GATEWAY_BACKUP_ENCRYPTION_KEY", "env://AG_BACKUP_ENCRYPTION_KEY")
s += open(work + "/config.bundled.toml").read()
open(p, "w").write(s)

# The local dev gateway.json carries legacy channel and proxy prefixes that
# collide with the dashboard's pages once the image's dashboard is present, and a
# dashboard path on the host. A deployment would not have either.
import json
gp = work + "/config/gateway.json"
g = json.loads(open(gp).read().replace(repo + "/www/default/build", "/app/www").replace(repo + "/envs/local", "/app"))
g["channels"] = []
g["mcp_proxies"] = []
open(gp, "w").write(json.dumps(g, indent=2))
PY
openssl rand -base64 32 > "${work}/secrets/vta_seed_passphrase"

export GATEWAY_IMAGE VTA_IMAGE
export TG_ENCRYPTION_KEY
TG_ENCRYPTION_KEY="$(openssl rand -base64 32)"
export AG_BACKUP_ENCRYPTION_KEY
AG_BACKUP_ENCRYPTION_KEY="$(cat "${repo}/envs/backup_encryption_key")"
export AG_IDENTITY_HASH_PEPPER
AG_IDENTITY_HASH_PEPPER="$(cat "${repo}/envs/identity_hash_pepper")"

dc() { (cd "${work}" && docker compose -p "${project}" "$@"); }
failures=0
check() { # check <description> <command...>
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "  ok    ${what}"; else echo "  FAIL  ${what}"; failures=$((failures + 1)); fi
}
strip() { sed 's/\x1b\[[0-9;]*m//g'; }
logs() { dc logs "$1" 2>&1 | strip; }
wait_connected() {
  for _ in $(seq 1 "${WAIT_SECS}"); do
    [[ "$(logs gateway)" == *"the bundled trust agent is connected"* ]] && return 0
    [[ "$(logs gateway)" == *"the bundled trust agent is not connected"* ]] && return 1
    sleep 1
  done
  return 1
}
bootstrap_file() { docker run --rm -v "${project}_bootstrap:/b:ro" busybox cat "/b/$1"; }

echo "== first start: two containers, no manual grant"
dc up -d >/dev/null 2>&1 || { dc up -d 2>&1 | tail -20; }
connected=0; wait_connected && connected=1
check "the gateway connected to its sidecar" test "${connected}" = 1
if [[ "${connected}" != 1 ]]; then
  echo "--- gateway log (tail)"; logs gateway | tail -15
  echo "--- vta log (tail)"; logs vta | tail -15
fi
check "the gateway wrote its did:key to the shared volume" bootstrap_file gateway-enrolment.env
check "the sidecar published its did:key to the shared volume" bootstrap_file vta-identity.env
check "the sidecar enrolled the gateway offline" test "$(logs vta | grep -c 'enrolled did:key')" -ge 1
first="$(bootstrap_file gateway-enrolment.env | sed -n 's/^GATEWAY_CONTROL_DID=//p')"

echo "== isolation: only the pair can reach the trust agent"
check "the sidecar answers on the shared loopback" dc exec -T vta wget -qO- http://127.0.0.1:8100/health
net="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$(dc ps -q gateway)" | head -n1)"
check "another container on the network cannot reach the trust agent" \
  bash -c "! docker run --rm --network '${net}' busybox wget -q -T 3 -O- http://gateway:8100/health"
check "the sidecar publishes no ports" test -z "$(dc ps vta --format '{{.Ports}}')"

echo "== restart keeps the same identity"
# The sidecar joins the gateway's network namespace, so it must be restarted after
# the gateway, never with it: `docker compose restart` fails the sidecar with
# "cannot join network of a non running container" and Docker's restart policy
# does not bring it back.
dc restart gateway >/dev/null 2>&1
sleep 3
dc restart vta >/dev/null 2>&1
sleep 5
connected=0; wait_connected && connected=1
check "the gateway reconnected" test "${connected}" = 1
check "the control DID is unchanged" test "$(bootstrap_file gateway-enrolment.env | sed -n 's/^GATEWAY_CONTROL_DID=//p')" = "${first}"
check "the sidecar did not re-enrol on restart" test "$(logs vta | grep -c 'enrolled did:key')" -le 1

echo
if [[ "${failures}" -eq 0 ]]; then echo "bundled compose e2e: all checks passed"; else echo "bundled compose e2e: ${failures} check(s) failed (rerun with KEEP=1 to keep the files)"; exit 1; fi
