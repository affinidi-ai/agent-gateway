#!/usr/bin/env bash
# Live end-to-end check of the bundled trust agent sidecar, against the real
# `vta` and `agent-gateway` binaries, from zero. Not part of CI: it needs a
# built VTA and a prepared local environment.
#
#   VTA_BIN=../verifiable-trust-infrastructure/target/debug/vta \
#     ./scripts/vta-bundled-e2e.sh
#
# Build the VTA from verifiable-trust-infrastructure `gateway-integration` with
#   cargo build -p vta-service --features webvh --bin vta
# (not a workspace build), and the gateway with `cargo build`. Run
# `make config-debug` once so `envs/local` and `envs/certs` exist.
#
# Uses its own temporary directories and never touches `envs/local/_storage`.
# Needs the gateway's HTTP/HTTPS/outbound ports (8080, 8443, 9000) and 8100 free.
#
# Checks: first start connects with no manual step; a restart keeps the same
# identity; a revoked gateway is reported and not re-enrolled; a re-grant
# recovers; a control-key rotation moves the access entry and the gateway
# reconnects under the new key.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
VTA_BIN="${VTA_BIN:-${repo}/../verifiable-trust-infrastructure/target/debug/vta}"
GATEWAY_BIN="${GATEWAY_BIN:-${repo}/target/debug/agent-gateway}"
WAIT_SECS="${WAIT_SECS:-90}"

for f in "${VTA_BIN}" "${GATEWAY_BIN}" "${repo}/envs/local/config/config.toml" "${repo}/envs/certs/cert.pem"; do
  [[ -e "${f}" ]] || { echo "missing: ${f}" >&2; exit 2; }
done

work="$(mktemp -d)"
g="${work}/gw"
v="${work}/sidecar"
mkdir -p "${g}/_storage" "${g}/certs" "${v}/data" "${v}/boot" "${v}/secrets" "${v}/bin"
ln -s "${VTA_BIN}" "${v}/bin/vta"
printf 'bundled sidecar e2e seed passphrase' > "${v}/secrets/pass"

pids=()
cleanup() {
  for pid in "${pids[@]:-}"; do kill "${pid}" 2>/dev/null || true; done
  pkill -f "${v}/" 2>/dev/null || true
  [[ "${KEEP:-}" == "1" ]] && echo "kept ${work}" || rm -rf "${work}"
}
trap cleanup EXIT

cp -R "${repo}/envs/local/config" "${g}/config"
cp "${repo}/envs/certs/cert.pem" "${repo}/envs/certs/key.pem" "${g}/certs/"
python3 - "${g}" "${v}" "${repo}" <<'PY'
import sys
g, v, repo = sys.argv[1:4]
p = g + "/config/config.toml"
s = open(p).read().replace(repo + "/envs/local", g)
s += f'''
[vta]
enabled = true
mode = "embedded"
auto_bootstrap = true
base_url = "http://127.0.0.1:8100"
bootstrap_dir = "{v}/boot"
bootstrap_wait_secs = 40
'''
open(p, "w").write(s)
t = open(repo + "/config/examples/vta-bundled/vta-setup.base.toml").read()
for a, b in [("/var/lib/vta/config.toml", v + "/data/config.toml"), ("/var/lib/vta/data", v + "/data/store"),
             ("/var/lib/vta/seed.enc", v + "/data/seed.enc"), ("/run/secrets/vta_seed_passphrase", v + "/secrets/pass")]:
    t = t.replace(a, b)
open(v + "/setup.toml", "w").write(t)

# The local dev gateway.json carries a legacy `/payments` channel, which collides
# with the dashboard's Payments page. A deployment would not have it.
import json
gp = g + "/config/gateway.json"
gj = json.loads(open(gp).read().replace(repo + "/envs/local", g))
gj["channels"] = [ch for ch in gj.get("channels", []) if ch.get("prefix") != "/payments"]
open(gp, "w").write(json.dumps(gj, indent=2))
PY

export TRUST_GATEWAY_MASTER_KEY
TRUST_GATEWAY_MASTER_KEY="$(openssl rand -base64 32)"
export TRUST_GATEWAY_BACKUP_ENCRYPTION_KEY
TRUST_GATEWAY_BACKUP_ENCRYPTION_KEY="$(cat "${repo}/envs/backup_encryption_key")"
export AG_IDENTITY_HASH_PEPPER
AG_IDENTITY_HASH_PEPPER="$(cat "${repo}/envs/identity_hash_pepper")"
export RUST_LOG=info

failures=0
check() { # check <description> <command...>
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "  ok    ${what}"; else echo "  FAIL  ${what}"; failures=$((failures + 1)); fi
}
strip() { sed 's/\x1b\[[0-9;]*m//g'; }
note_did() { sed -n 's/^GATEWAY_CONTROL_DID=//p' "${v}/boot/gateway-enrolment.env"; }

start_sidecar() { # start_sidecar <log>
  (cd "${v}" && PATH="${v}/bin:${PATH}" BUNDLED_DATA="${v}/data" BUNDLED_BOOT="${v}/boot" BUNDLED_SETUP="${v}/setup.toml" \
    nohup sh "${repo}/config/examples/vta-bundled/vta-entrypoint.sh" > "$1" 2>&1 &)
  sleep 5
}
start_gateway() { # start_gateway <log> ; waits for a bootstrap verdict
  (cd "${g}" && nohup "${GATEWAY_BIN}" --config config/config.toml > "$1" 2>&1 &)
  for _ in $(seq 1 "${WAIT_SECS}"); do
    grep -aq "trust agent is connected\|trust agent is not connected" "$1" && return 0
    sleep 1
  done
  return 1
}
stop_all() { pkill -f "agent-gateway --config" 2>/dev/null || true; pkill -f "${v}/" 2>/dev/null || true; pkill -f "vta --config ${v}" 2>/dev/null || true; pkill -f vta-entrypoint 2>/dev/null || true; sleep 2; }
# Not `strip | grep -q`: grep exits at the first match, sed gets SIGPIPE, and
# pipefail then reports the pipeline as failed.
connected() { [[ "$(strip < "$1")" == *"the bundled trust agent is connected"* ]]; }
verdict() { strip < "$1" | grep -o "state=[A-Za-z]*" | head -1; }

echo "== first start, from zero (no manual grant)"
start_gateway "${work}/gw1.log" & gw=$!; sleep 6
start_sidecar "${work}/sc1.log"; wait "${gw}" || true
for _ in $(seq 1 "${WAIT_SECS}"); do connected "${work}/gw1.log" && break; sleep 1; done
check "the gateway connected" connected "${work}/gw1.log"
check "the gateway wrote its did:key for the sidecar" grep -q "^GATEWAY_CONTROL_DID=did:key:" "${v}/boot/gateway-enrolment.env"
check "the sidecar enrolled it offline" grep -aq "enrolled did:key:" "${work}/sc1.log"
check "the state record is encrypted at rest" test -f "${g}/_storage/vc_keys/vta_bundled_state.json.enc"
first="$(note_did)"

echo "== restart keeps the same identity"
stop_all; start_sidecar "${work}/sc2.log"; start_gateway "${work}/gw2.log" || true
check "the gateway reconnected" connected "${work}/gw2.log"
check "the control DID is unchanged" test "$(note_did)" = "${first}"
check "the sidecar did not re-enrol on restart" test "$(grep -ac 'enrolled did:key' "${work}/sc2.log")" = "0"

echo "== revoked: reported, and never re-enrolled"
stop_all
PATH="${v}/bin:${PATH}" vta --config "${v}/data/config.toml" acl delete "${first}" --yes >/dev/null 2>&1
start_sidecar "${work}/sc3.log"; start_gateway "${work}/gw3.log" || true
check "the state is revoked" test "$(verdict "${work}/gw3.log")" = "state=Revoked"
check "the entrypoint did not re-enrol the gateway" test "$(grep -ac 'enrolled did:key' "${work}/sc3.log")" = "0"

echo "== re-grant offline, restart"
stop_all
PATH="${v}/bin:${PATH}" vta --config "${v}/data/config.toml" acl create --did "${first}" --role initiator \
  --contexts gateway --capabilities context-create,key-mint,sign-jws,sign-document >/dev/null 2>&1
start_sidecar "${work}/sc4.log"; start_gateway "${work}/gw4.log" || true
check "the gateway connected again" connected "${work}/gw4.log"

echo "== control-key rotation (gateway stopped)"
stop_all; start_sidecar "${work}/sc5.log"
( cd "${g}" && "${GATEWAY_BIN}" --config config/config.toml --vta-rotate-control-key --yes ) > "${work}/rotate.log" 2>&1 || true
check "the rotation reported success" grep -q "^Done" "${work}/rotate.log"
second="$(note_did)"
check "the control DID changed" test -n "${second}" -a "${second}" != "${first}"
start_gateway "${work}/gw5.log" || true
check "the gateway reconnected under the new key" connected "${work}/gw5.log"
stop_all
acl="$(PATH="${v}/bin:${PATH}" vta --config "${v}/data/config.toml" acl list 2>&1 || true)"
check "the trust agent holds exactly one entry" test "$(printf '%s' "${acl}" | grep -c 'DID:  ')" = "1"
check "that entry is the new key" grep -q "${second}" <<<"${acl}"

echo
if [[ "${failures}" -eq 0 ]]; then echo "bundled sidecar e2e: all checks passed"; else echo "bundled sidecar e2e: ${failures} check(s) failed (rerun with KEEP=1 to keep the logs)"; exit 1; fi
