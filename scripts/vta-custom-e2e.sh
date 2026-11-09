#!/usr/bin/env bash
# Live end-to-end check that a surface can sign through a custom trust agent (a
# VTA an operator connects themselves) while the bundled sidecar stays the
# appliance default, using the real `vta` and `agent-gateway` binaries and the
# local A2A agent. Not part of CI.
#
#   VTA_BIN=../verifiable-trust-infrastructure/target/debug/vta \
#   A2A_AGENT_DIR=../a2a-local-agent \
#     ./scripts/vta-custom-e2e.sh
#
# Build the VTA from verifiable-trust-infrastructure `gateway-integration` with
#   cargo build -p vta-service --features webvh --bin vta
# and the gateway with `cargo build`. Run `make config-debug` once.
#
# Runs, from nothing: the gateway with its bundled sidecar (the default), a
# second, custom VTA that is paired through the management API, the A2A agent,
# and two surfaces that reach the agent. One surface uses the default; the other
# names the custom connection. A message through each shows who signed the
# identity credential the agent received.
#
# Uses its own temporary directories. Needs ports 8080, 8443, 9000, 8100, 3000
# and 9100 free. KEEP=1 keeps the directories and leaves the processes running.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
VTA_BIN="${VTA_BIN:-${repo}/../verifiable-trust-infrastructure/target/debug/vta}"
GATEWAY_BIN="${GATEWAY_BIN:-${repo}/target/debug/agent-gateway}"
A2A_AGENT_DIR="${A2A_AGENT_DIR:-${repo}/../a2a-local-agent}"
WAIT_SECS="${WAIT_SECS:-90}"
TEST_TOKEN="custom-e2e-token-32-plus-characters-long"
BASE="https://localhost:8443"

for f in "${VTA_BIN}" "${GATEWAY_BIN}" "${A2A_AGENT_DIR}/agent.py" "${repo}/envs/local/config/config.toml" "${repo}/envs/certs/cert.pem"; do
  [[ -e "${f}" ]] || { echo "missing: ${f}" >&2; exit 2; }
done

for port in 8080 8443 9000 8100 3000 9100 9101; do
  if nc -z 127.0.0.1 "${port}" 2>/dev/null; then echo "port ${port} is already in use" >&2; exit 2; fi
done

work="$(mktemp -d)"
g="${work}/gw"; v="${work}/sidecar"; c="${work}/custom"
mkdir -p "${g}/_storage" "${g}/certs" "${v}/data" "${v}/boot" "${v}/secrets" "${v}/bin" "${c}/data" "${c}/secrets" "${c}/bin"
ln -s "${VTA_BIN}" "${v}/bin/vta"
ln -s "${VTA_BIN}" "${c}/bin/vta"
printf 'bundled sidecar e2e seed passphrase' > "${v}/secrets/pass"
printf 'custom vta e2e seed passphrase' > "${c}/secrets/pass"

cleanup() {
  if [[ "${KEEP:-}" == "1" ]]; then echo "kept ${work} (processes still running)"; return; fi
  pkill -f "${work}/" 2>/dev/null || true
  pkill -f "agent-gateway --config config/config.toml" 2>/dev/null || true
  [[ -s "${work}/agent.pid" ]] && kill "$(cat "${work}/agent.pid")" 2>/dev/null || true
  rm -rf "${work}"
}
trap cleanup EXIT

cp -R "${repo}/envs/local/config" "${g}/config"
cp "${repo}/envs/certs/cert.pem" "${repo}/envs/certs/key.pem" "${g}/certs/"
python3 - "${g}" "${v}" "${c}" "${repo}" <<'PY'
import sys
g, v, c, repo = sys.argv[1:5]
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
base = open(repo + "/config/examples/vta-bundled/vta-setup.base.toml").read()
def setup(root, port, name, out):
    t = base
    for a, b in [("/var/lib/vta/config.toml", root + "/data/config.toml"), ("/var/lib/vta/data", root + "/data/store"),
                 ("/var/lib/vta/seed.enc", root + "/data/seed.enc"), ("/run/secrets/vta_seed_passphrase", root + "/secrets/pass"),
                 ("8100", str(port)), ("agent-gateway-bundled", name)]:
        t = t.replace(a, b)
    open(out, "w").write(t)
# The local dev gateway.json carries a legacy `/payments` channel, which collides
# with the dashboard's Payments page and stops the gateway starting. The other
# channel prefixes are kept: they are what mounts proxy routes on the listener.
import json
gp = g + "/config/gateway.json"
gj = json.loads(open(gp).read().replace(repo + "/envs/local", g))
gj["channels"] = [ch for ch in gj.get("channels", []) if ch.get("prefix") != "/payments"]
open(gp, "w").write(json.dumps(gj, indent=2))
setup(v, 8100, "agent-gateway-bundled", v + "/setup.toml")
setup(c, 3000, "custom-vta", c + "/setup.toml")
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
connected() { [[ "$(strip < "$1")" == *"the bundled trust agent is connected"* ]]; }

start_sidecar() {
  (cd "${v}" && PATH="${v}/bin:${PATH}" BUNDLED_DATA="${v}/data" BUNDLED_BOOT="${v}/boot" BUNDLED_SETUP="${v}/setup.toml" \
    nohup sh "${repo}/config/examples/vta-bundled/vta-entrypoint.sh" > "${work}/sidecar.log" 2>&1 &)
}
start_gateway() { # start_gateway <log>
  (cd "${g}" && AG_TEST_MODE=true AG_TEST_ALLOW_ROLE_OVERRIDE=true AG_TEST_TOKEN="${TEST_TOKEN}" nohup "${GATEWAY_BIN}" --config config/config.toml > "$1" 2>&1 &)
}
login() {
  token=""
  for _ in $(seq 1 30); do
    token="$(curl -sk -X POST "${BASE}/api/internal/test-support/auth/login" -H "X-Test-Token: ${TEST_TOKEN}" \
      -H 'Content-Type: application/json' -d '{"role":"administrator"}' 2>/dev/null \
      | python3 -c "import sys,json; print(json.load(sys.stdin)['session_token'])" 2>/dev/null || true)"
    [[ -n "${token}" ]] && return 0
    sleep 1
  done
  return 0
}
# The custom VTA is run by hand, like an operator's own: it needs private
# endpoints allowed so that it can resolve the gateway's did:webvh on localhost.
vta_custom() { VTA_ALLOW_PRIVATE_ENDPOINTS=1 PATH="${c}/bin:${PATH}" vta --config "${c}/data/config.toml" "$@"; }
start_custom() {
  (cd "${c}" && VTA_ALLOW_PRIVATE_ENDPOINTS=1 PATH="${c}/bin:${PATH}" nohup vta --config "${c}/data/config.toml" > "${work}/custom.log" 2>&1 &)
  for _ in $(seq 1 30); do curl -sf http://127.0.0.1:3000/health >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
stop_custom() { pkill -f "vta --config ${c}/data/config.toml" 2>/dev/null || true; sleep 2; }

token=""
api() { # api <method> <path> [json-body]
  local method="$1" path="$2"
  if [[ $# -ge 3 ]]; then
    curl -sk -X "${method}" "${BASE}${path}" -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' -d "$3"
  else
    curl -sk -X "${method}" "${BASE}${path}" -H "Authorization: Bearer ${token}"
  fi
}
jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }

echo "== the default: gateway with its bundled sidecar"
start_gateway "${work}/gateway.log"
sleep 6
start_sidecar
for _ in $(seq 1 "${WAIT_SECS}"); do connected "${work}/gateway.log" && break; sleep 1; done
check "the gateway connected to its bundled sidecar" connected "${work}/gateway.log"

login
check "the dashboard API accepts the test session" test -n "${token}"
bundled_vta_did="$(api GET /api/v1/vta/status | jget "d['bootstrap']['vta_did']")"

echo "== a custom VTA, set up from nothing"
(cd "${c}" && PATH="${c}/bin:${PATH}" vta setup --from "${c}/setup.toml") > "${work}/custom-setup.log" 2>&1
vta_custom contexts create --id custom --name "Custom" > "${work}/custom-ctx.log" 2>&1
custom_vta_did="$(sed -n 's/^vta_did[[:space:]]*=[[:space:]]*"\(did:[^"]*\)".*/\1/p' "${c}/data/config.toml" | head -n 1)"
check "the custom VTA has its own DID" test -n "${custom_vta_did}"
check "the custom VTA's DID differs from the bundled one" test "${custom_vta_did}" != "${bundled_vta_did}"

echo "== pair the custom VTA through the management API"
# `control_identity: did_key` because the default, a published did:webvh, needs the
# custom VTA to fetch the gateway's DID over plain http, and this local gateway's
# DID names its TLS port. Against a gateway that is reachable the default applies.
created="$(api POST /api/v1/vta/connections "{\"control_identity\":\"did_key\",\"name\":\"Custom VTA\",\"enabled\":true,\"transport\":\"https\",\"endpoint\":\"http://127.0.0.1:3000\",\"vta_did\":\"${custom_vta_did}\",\"default_context_id\":\"custom\"}")"
conn_id="$(printf '%s' "${created}" | jget "d['id']")"
check "the connection was created" test -n "${conn_id}"
pair="$(api POST "/api/v1/vta/connections/${conn_id}/pair")"
control_did="$(printf '%s' "${pair}" | jget "d['control_did']")"
check "pairing names the control DID to grant" test -n "${control_did}"
echo "     control DID: ${control_did}"
vta_custom acl create --did "${control_did}" --role initiator --contexts custom \
  --capabilities context-create,key-mint,sign-jws,sign-document > "${work}/custom-acl.log" 2>&1
check "the operator granted that DID on the custom VTA" grep -qi "created\|ok\|did" "${work}/custom-acl.log"
start_custom
check "the custom VTA answers on port 3000" curl -sf http://127.0.0.1:3000/health
verified="$(api POST "/api/v1/vta/connections/${conn_id}/verify")"
check "the connection verifies" test "$(printf '%s' "${verified}" | jget "d['pairing']['state']")" = "connected"
provisioned="$(api POST "/api/v1/vta/connections/${conn_id}/keys" '{}')"
custom_kid="$(printf '%s' "${provisioned}" | jget "d['keys']['active']['key_id']")"
check "a signing key was minted inside the custom VTA" test -n "${custom_kid}"
echo "     custom signing key: ${custom_kid}"

echo "== the agent and two surfaces"
(cd "${A2A_AGENT_DIR}"; LLM_BASE_URL="http://127.0.0.1:9" AGENT_PORT=9100 AGENT_HOST=127.0.0.1 nohup python3 agent.py > "${work}/agent.log" 2>&1 & echo $! > "${work}/agent.pid")
for _ in $(seq 1 20); do nc -z 127.0.0.1 9100 && break; sleep 1; done
check "the A2A agent answers" nc -z 127.0.0.1 9100

# The surfaces point at a recording shim that passes every request on to the real
# agent, so the agent still receives them and the body the gateway sent can be
# read back: the agent prints credentials in an older extension than the gateway
# now sends.
mkdir -p "${work}/capture"
cat > "${work}/shim.py" <<'PY'
import json, sys, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
OUT, AGENT = sys.argv[1], sys.argv[2]
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            ext = json.loads(body)["params"]["message"]["metadata"]["https://fabric.affinidi.io/extensions/agent-identity/v1"]
            name = ext["agentIdentity"]["sub"]
        except Exception:
            name = "unknown"
        open(f"{OUT}/{name}.json", "wb").write(body)
        req = urllib.request.Request(AGENT, data=body, headers={"Content-Type": "application/json"})
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            data, status = resp.read(), resp.status
        except Exception as e:
            data, status = json.dumps({"error": str(e)}).encode(), 502
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 9101), H).serve_forever()
PY
(nohup python3 "${work}/shim.py" "${work}/capture" http://127.0.0.1:9100 > "${work}/shim.log" 2>&1 &)
for _ in $(seq 1 10); do nc -z 127.0.0.1 9101 && break; sleep 1; done
check "the recording shim is up" nc -z 127.0.0.1 9101

# Verifies the Data Integrity proofs (eddsa-jcs-2022) of the credential inside the
# presentation the gateway injected, under its issuer, and of the presentation
# itself, under the agent that holds it.
cat > "${work}/verify.py" <<'PY'
import base64, hashlib, json, subprocess, sys
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BINDING = "https://fabric.affinidi.io/extensions/agent-identity-binding/v1"
def b58d(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + raw
def jcs(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
try:
    body = json.load(open(sys.argv[1]))
    presentation = json.loads(body["params"]["message"]["metadata"][BINDING]["verifiablePresentation"])
    credential = presentation["verifiableCredential"][0]
except Exception:
    print(json.dumps({"present": False})); sys.exit(0)
def check(doc_with_proof, key_did):
    proof = doc_with_proof["proof"]
    signature = b58d(proof["proofValue"][1:])
    unsecured = {k: v for k, v in doc_with_proof.items() if k != "proof"}
    config = {k: v for k, v in proof.items() if k != "proofValue"}
    digest = hashlib.sha256(jcs(config)).digest() + hashlib.sha256(jcs(unsecured)).digest()
    public = b58d(key_did.split(":")[-1][1:])[2:]
    script = ("const c=require('crypto');const [x,d,s]=process.argv.slice(1);"
              "const k=c.createPublicKey({key:{kty:'OKP',crv:'Ed25519',x},format:'jwk'});"
              "console.log(c.verify(null,Buffer.from(d,'hex'),k,Buffer.from(s,'hex')));")
    return subprocess.run(["node", "-e", script, base64.urlsafe_b64encode(public).decode().rstrip("="), digest.hex(), signature.hex()],
                          capture_output=True, text=True).stdout.strip() == "true"

issuer = credential["issuer"]
holder = presentation.get("holder")
print(json.dumps({"present": True, "issuer": issuer, "valid": check(credential, issuer),
                  "holder": holder, "holder_valid": check(presentation, holder)}))
PY

surface() { # surface <id> <route> [signing-json]
  local signing="${3:-}"
  python3 - "$1" "$2" "${signing}" <<'PY'
import json, sys
sid, route, signing = sys.argv[1:4]
s = {
  "surface_id": sid, "name": sid, "description": "e2e", "status": "active", "tags": [],
  "access_point": {"listen_address": "localhost:8080", "route": route, "protocol": "a2a", "public": True,
                   "publish_to_did_document": False, "terminate_trace_id": False},
  "identity_slots": {"inbound": {"type": "from_payload", "meta_field": "agentIdentity", "fields": ["agentIdentity.sub"],
                                 "json_schema": {"type": "object", "properties": {"agentIdentity": {"type": "object",
                                   "properties": {"sub": {"type": "string", "x-identity": True}, "name": {"type": "string"}}}}}}},
  "target": {"endpoint": "http://127.0.0.1:9101", "mcp_tool_policies_enabled": False, "mpp_auto_pay": False,
             "identity_injection": {"inject_vp": True}},
}
if signing:
    s["signing"] = json.loads(signing)
print(json.dumps(s))
PY
}
default_surface="$(surface e2e-default /agents/e2e-default)"
custom_surface="$(surface e2e-custom /agents/e2e-custom "{\"backend\":\"vta\",\"connection_id\":\"${conn_id}\",\"context_id\":\"custom\",\"key_id\":\"${custom_kid}\"}")"
r1="$(api POST /api/v1/surfaces "${default_surface}")"; echo "     default surface: $(printf '%s' "${r1}" | head -c 200)"
r2="$(api POST /api/v1/surfaces "${custom_surface}")"; echo "     custom surface:  $(printf '%s' "${r2}" | head -c 200)"

sleep 3

echo "== a message through each surface"
send() { (cd "${A2A_AGENT_DIR}" && python3 send.py --url "http://localhost:8080$1" --sub "$2" "hello" >/dev/null 2>&1 || true); }
# How many times each VTA was asked to do one kind of thing, from its own log.
calls() { strip < "${work}/$1.log" | grep -a -c "spec/$2" || true; }
field() { python3 -c "import sys,json; print(json.load(sys.stdin).get(sys.argv[1], ''))" "$1"; }
context_dids() { # context_dids <vta log> <context id>: every DID that VTA set on that context
  strip < "${work}/$1.log" | python3 -c '
import sys, json
for line in sys.stdin:
    try: f = json.loads(line).get("fields", {})
    except Exception: continue
    if f.get("message") == "context DID updated" and f.get("id") == sys.argv[1]:
        print(f.get("did"))' "$2"
}

sc0="$(calls sidecar keys/sign-document)"; cu0="$(calls custom keys/sign-document)"
send /agents/e2e-default e2e-default-user
sleep 2
sc1="$(calls sidecar keys/sign-document)"; cu1="$(calls custom keys/sign-document)"
send /agents/e2e-custom e2e-custom-user
sleep 2
sc2="$(calls sidecar keys/sign-document)"; cu2="$(calls custom keys/sign-document)"

contains() { [[ -n "$2" && "$1" == *"$2"* ]]; }
agent_log="$(strip < "${work}/agent.log")"
check "the agent received the default surface's message" contains "${agent_log}" "e2e-default-user"
check "the agent received the custom surface's message" contains "${agent_log}" "e2e-custom-user"
dv="$(python3 "${work}/verify.py" "${work}/capture/e2e-default-user.json")"
cv="$(python3 "${work}/verify.py" "${work}/capture/e2e-custom-user.json")"
echo "     default surface: ${dv}"
echo "     custom surface:  ${cv}"
check "the default surface's message carries an identity credential" test "$(printf '%s' "${dv}" | field present)" = "True"
check "the custom surface's message carries an identity credential" test "$(printf '%s' "${cv}" | field present)" = "True"
check "the default credential's signature verifies under its issuer" test "$(printf '%s' "${dv}" | field valid)" = "True"
check "the custom credential's signature verifies under its issuer" test "$(printf '%s' "${cv}" | field valid)" = "True"
check "the default presentation's signature verifies under the agent" test "$(printf '%s' "${dv}" | field holder_valid)" = "True"
check "the custom presentation's signature verifies under the agent" test "$(printf '%s' "${cv}" | field holder_valid)" = "True"
d_issuer="$(printf '%s' "${dv}" | field issuer)"; c_issuer="$(printf '%s' "${cv}" | field issuer)"
check "the two surfaces are issued by different identities" test -n "${d_issuer}" -a "${d_issuer}" != "${c_issuer}"
check "the default issuer is the bundled sidecar's gateway context" contains "$(context_dids sidecar gateway)" "${d_issuer}"
check "the custom issuer is the custom VTA's own context" contains "$(context_dids custom custom)" "${c_issuer}"
echo "     document signings  sidecar: ${sc0} -> ${sc1} (default message) -> ${sc2} (custom message)"
echo "                        custom:  ${cu0} -> ${cu1} (default message) -> ${cu2} (custom message)"
check "the default message was signed by the sidecar, not the custom VTA" test "${sc1}" -gt "${sc0}" -a "${cu1}" = "${cu0}"
check "the custom message was signed by the custom VTA" test "${cu2}" -gt "${cu1}"

echo
if [[ "${failures}" -eq 0 ]]; then echo "custom vta e2e: all checks passed"; else echo "custom vta e2e: ${failures} check(s) failed (rerun with KEEP=1 to keep the logs)"; exit 1; fi
