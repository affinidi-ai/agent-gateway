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

# shellcheck source=scripts/vta-bundled-lib.sh
source "${repo}/scripts/vta-bundled-lib.sh"
docker image inspect "${GATEWAY_IMAGE}" "${VTA_IMAGE}" >/dev/null

work="$(mktemp -d)"
project="vtabundled$$"

cleanup() {
  docker rm -f "${project}-anchor" "${project}-vta2" >/dev/null 2>&1 || true
  (cd "${work}" && docker compose -p "${project}" down -v >/dev/null 2>&1) || true
  [[ "${KEEP:-}" == "1" ]] && echo "kept ${work}" || rm -rf "${work}"
}
trap cleanup EXIT

prepare_stack "${work}" || exit 2
export GATEWAY_IMAGE VTA_IMAGE
export_stack_env

dc() { (cd "${work}" && docker compose -p "${project}" "$@"); }
failures=0
check() { # check <description> <command...>
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "  ok    ${what}"; else echo "  FAIL  ${what}"; failures=$((failures + 1)); fi
}
strip() { sed 's/\x1b\[[0-9;]*m//g'; }
# Container logs survive a restart, so every check after one reads only what was
# logged since `mark`; otherwise an earlier "connected" line answers for the new run.
since=""
mark() { since="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ 2>/dev/null | sed 's/\.N*Z$/Z/')"; }
logs() {
  if [[ -n "${since}" ]]; then dc logs --since "${since}" "$1" 2>&1 | strip; else dc logs "$1" 2>&1 | strip; fi
}
wait_verdict() { # waits for the gateway's bootstrap verdict, connected or not
  for _ in $(seq 1 "${WAIT_SECS}"); do
    local l; l="$(logs gateway)"
    [[ "${l}" == *"the bundled trust agent is connected"* || "${l}" == *"the bundled trust agent is not connected"* ]] && return 0
    sleep 1
  done
  return 1
}
wait_connected() { wait_verdict && [[ "$(logs gateway)" == *"the bundled trust agent is connected"* ]]; }
verdict() { logs gateway | grep -o "state=[A-Za-z]*" | head -1; }
bootstrap_file() { docker run --rm -v "${project}_bootstrap:/b:ro" busybox cat "/b/$1"; }
# The VTA's own command line, offline, against the sidecar's data volume. The
# sidecar must be stopped: the store is single-writer.
vta_cli() {
  docker run --rm --entrypoint vta \
    -v "${project}_vta-data:/var/lib/vta" \
    -v "${work}/secrets/vta_seed_passphrase:/run/secrets/vta_seed_passphrase:ro" \
    "${VTA_IMAGE}" --config /var/lib/vta/config.toml "$@"
}
stop_pair() { dc stop vta >/dev/null 2>&1; dc stop gateway >/dev/null 2>&1; }
start_pair() { dc start gateway >/dev/null 2>&1; sleep 3; dc start vta >/dev/null 2>&1; }

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
mark
dc restart gateway >/dev/null 2>&1
sleep 3
dc restart vta >/dev/null 2>&1
sleep 5
connected=0; wait_connected && connected=1
check "the gateway reconnected" test "${connected}" = 1
check "the control DID is unchanged" test "$(bootstrap_file gateway-enrolment.env | sed -n 's/^GATEWAY_CONTROL_DID=//p')" = "${first}"
check "the sidecar did not re-enrol on restart" test "$(logs vta | grep -c 'enrolled did:key')" = 0

echo "== revoked: reported, and never re-enrolled"
stop_pair
vta_cli acl delete "${first}" --yes >/dev/null 2>&1
mark
start_pair
wait_verdict || true
check "the state is revoked" test "$(verdict)" = "state=Revoked"
check "the sidecar did not re-enrol the gateway" test "$(logs vta | grep -c 'enrolled did:key')" = 0

echo "== re-grant offline, restart"
stop_pair
vta_cli acl create --did "${first}" --role initiator --contexts gateway \
  --capabilities context-create,key-mint,sign-jws,sign-document >/dev/null 2>&1
mark
start_pair
connected=0; wait_connected && connected=1
check "the gateway connected again" test "${connected}" = 1

echo "== control-key rotation (gateway stopped, sidecar reachable)"
# The rotation runs with the gateway stopped and the sidecar up, so a throwaway
# pair stands in for the stack: one namespace holder, the sidecar inside it, and a
# one-off gateway that shares its loopback, with the same volumes and secrets.
stop_pair
docker run -d --name "${project}-anchor" busybox sleep 600 >/dev/null
docker run -d --name "${project}-vta2" --network "container:${project}-anchor" \
  --entrypoint /bin/sh \
  -v "${project}_vta-data:/var/lib/vta" -v "${project}_bootstrap:/bootstrap" \
  -v "${work}/vta-setup.base.toml:/etc/vta/setup.base.toml:ro" \
  -v "${work}/vta-entrypoint.sh:/etc/vta/vta-entrypoint.sh:ro" \
  -v "${work}/secrets/vta_seed_passphrase:/run/secrets/vta_seed_passphrase:ro" \
  "${VTA_IMAGE}" /etc/vta/vta-entrypoint.sh >/dev/null
up=0
for _ in $(seq 1 60); do
  docker exec "${project}-vta2" wget -qO- http://127.0.0.1:8100/health >/dev/null 2>&1 && { up=1; break; }
  sleep 1
done
check "the throwaway sidecar is listening" test "${up}" = 1
docker run --rm --network "container:${project}-anchor" \
  -v "${project}_gateway-storage:/app/_storage" -v "${project}_bootstrap:/bootstrap" \
  -v "${work}/config:/app/config:ro" -v "${work}/certs:/app/certs:ro" \
  -e TG_ENCRYPTION_KEY -e AG_BACKUP_ENCRYPTION_KEY -e AG_IDENTITY_HASH_PEPPER \
  "${GATEWAY_IMAGE}" --config /app/config/config.toml --vta-rotate-control-key --yes > "${work}/rotate.log" 2>&1 || true
check "the rotation reported success" grep -q "^Done" "${work}/rotate.log"
if ! grep -q "^Done" "${work}/rotate.log"; then echo "--- rotate log (tail)"; strip < "${work}/rotate.log" | tail -15; fi
second="$(bootstrap_file gateway-enrolment.env | sed -n 's/^GATEWAY_CONTROL_DID=//p')"
check "the control DID changed" test -n "${second}" -a "${second}" != "${first}"
printed="$(docker run --rm \
  -v "${project}_gateway-storage:/app/_storage" -v "${project}_bootstrap:/bootstrap" \
  -v "${work}/config:/app/config:ro" -v "${work}/certs:/app/certs:ro" \
  -e TG_ENCRYPTION_KEY -e AG_BACKUP_ENCRYPTION_KEY -e AG_IDENTITY_HASH_PEPPER \
  "${GATEWAY_IMAGE}" --config /app/config/config.toml --vta-print-control-did 2>/dev/null | strip | tail -n1)"
check "the printed control DID is the key now in use" test "${printed}" = "${second}"
docker rm -f "${project}-vta2" "${project}-anchor" >/dev/null 2>&1
mark
start_pair
connected=0; wait_connected && connected=1
check "the gateway reconnected under the new key" test "${connected}" = 1
dc stop vta >/dev/null 2>&1
acl="$(vta_cli acl list 2>&1 || true)"
check "the trust agent holds exactly one entry" test "$(printf '%s' "${acl}" | grep -c 'DID:  ')" = 1
check "that entry is the new key" grep -q "${second}" <<<"${acl}"

echo
if [[ "${failures}" -eq 0 ]]; then echo "bundled compose e2e: all checks passed"; else echo "bundled compose e2e: ${failures} check(s) failed (rerun with KEEP=1 to keep the files)"; exit 1; fi
