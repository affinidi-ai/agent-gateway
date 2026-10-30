#!/usr/bin/env bash
#
# Start the demo's supporting services on the host:
#   - two Ory Hydra containers (hydra-a, hydra-b), in-memory storage, JWT access tokens,
#     scopes in a list claim, plain http in Hydra's development mode; with OIDC_DEMO_IDP=auth0
#     (auth0.sh) only hydra-b, because the Auth0 tenant is the caller's authorization server;
#   - the mock A2A agent, with a login-only card, as a host python3 process.
# Callers on hydra-a: demo-caller (the required scope, the Access Point as audience), demo-noscope (no
# scope) and demo-otheraud (another audience); demo-caller also on hydra-b. The gateway is not started
# here; see gateway.sh. Generated keys, secrets and configs live in envs/oidc-demo-run/ (gitignored). Nothing is pulled: the pinned Hydra image must already exist.
#
# Usage: scripts/oidc-demo/up.sh [--no-hop2]
#   --no-hop2   the mock agent accepts the card fetch and calls without a token, for a gateway that has
#               no JWT bearer provider yet. The hop 2 checks are skipped in that mode.

set -euo pipefail
unset CDPATH
# shellcheck source=scripts/oidc-demo/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

HYDRA_IMAGE_ID="sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9"
HOP2="${OIDC_DEMO_HOP2:-on}"
for arg in "$@"; do
    case "${arg}" in
        --no-hop2) HOP2=off ;;
        -h|--help) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) fail "unknown option: ${arg}" ;;
    esac
done

require_tools docker curl jq openssl python3

actual_id="$(docker image inspect "${HYDRA_IMAGE}" --format '{{.Id}}' 2>/dev/null)" \
    || fail "${HYDRA_IMAGE} is not present locally; this harness never pulls images"
[[ "${actual_id}" == "${HYDRA_IMAGE_ID}" ]] \
    || fail "${HYDRA_IMAGE} is ${actual_id}, expected the pinned ${HYDRA_IMAGE_ID}"

mkdir -p "${STATE_DIR}/config" "${SECRETS_DIR}"
chmod 700 "${STATE_DIR}" "${SECRETS_DIR}"
chmod 755 "${STATE_DIR}/config"
printf '%s\n' "${HOP2}" >"${STATE_DIR}/hop2"

"${OIDC_DEMO_DIR}/down.sh" --services-only >/dev/null

HYDRA_SET="a b"
if auth0_mode; then HYDRA_SET="b"; fi

info "Generating local secrets and the hop 2 signing key"
for which in ${HYDRA_SET}; do
    new_secret "hydra-${which}.system"
    new_secret "${which}-demo-caller.secret"
done
if ! auth0_mode; then
    new_secret "a-${NOSCOPE_CLIENT}.secret"
    new_secret "a-${OTHERAUD_CLIENT}.secret"
fi
new_secret "b-${HOP2_CLIENT}.secret"
new_secret "test-token"
if [[ ! -s "${STATE_DIR}/gateway-hop2.key" ]]; then
    (umask 077; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${STATE_DIR}/gateway-hop2.key" 2>/dev/null)
    openssl pkey -in "${STATE_DIR}/gateway-hop2.key" -pubout -out "${STATE_DIR}/gateway-hop2.pub.pem" 2>/dev/null
fi

write_hydra_config() {
    local which="$1" public="$2"
    (umask 077; printf 'SECRETS_SYSTEM=%s\nDSN=memory\n' "$(cat "$(secret_file "hydra-${which}.system")")" >"${STATE_DIR}/hydra-${which}.env")
    cat >"${STATE_DIR}/config/hydra-${which}.yml" <<YAML
urls:
  self:
    issuer: http://127.0.0.1:${public}/
  login: http://127.0.0.1:3000/login
  consent: http://127.0.0.1:3000/consent
serve:
  public:
    port: 4444
    host: 0.0.0.0
  admin:
    port: 4445
    host: 0.0.0.0
strategies:
  access_token: jwt
  scope: exact
  jwt:
    scope_claim: list
oauth2:
  grant:
    jwt:
      jti_optional: false
      iat_optional: true
      max_ttl: 1h
YAML
    chmod 644 "${STATE_DIR}/config/hydra-${which}.yml"
}

start_hydra() {
    local which="$1" name="$2" public="$3" admin="$4"
    write_hydra_config "${which}" "${public}"
    docker run -d --name "${name}" \
        -p "127.0.0.1:${public}:4444" -p "127.0.0.1:${admin}:4445" \
        --env-file "${STATE_DIR}/hydra-${which}.env" \
        -v "${STATE_DIR}/config:/cfg:ro" \
        "${HYDRA_IMAGE}" serve all --dev -c "/cfg/hydra-${which}.yml" >/dev/null
    wait_http "http://127.0.0.1:${admin}/health/ready" "${name}" 120
}

if auth0_mode; then
    info "Auth0 mode: starting hydra-b (${HYDRA_B_ISSUER}) only; the caller's authorization server is the Auth0 tenant"
else
    info "Starting hydra-a (${HYDRA_A_ISSUER}) and hydra-b (${HYDRA_B_ISSUER})"
    start_hydra a "${HYDRA_A_NAME}" "${HYDRA_A_PUBLIC}" "${HYDRA_A_ADMIN}"
fi
start_hydra b "${HYDRA_B_NAME}" "${HYDRA_B_PUBLIC}" "${HYDRA_B_ADMIN}"

admin_post() {
    local which="$1" path="$2" code
    code="$(curl -sS --connect-timeout 5 --max-time 20 -o "${STATE_DIR}/last-admin-response" -w '%{http_code}' \
        -X POST -H 'Content-Type: application/json' --data-binary @- "$(hydra_admin_url "${which}")${path}")" \
        || fail "Hydra ${which} admin call ${path} failed"
    case "${code}" in
        200|201) ;;
        *) fail "Hydra ${which} admin call ${path} returned ${code}: $(jq -c '{error, error_description}' "${STATE_DIR}/last-admin-response" 2>/dev/null)" ;;
    esac
}

register_cc_client() {
    local which="$1" client="$2" scope="$3" audience="$4"
    jq -n --arg id "${client}" --rawfile secret "$(secret_file "${which}-${client}.secret")" \
        --arg scope "${scope}" --arg aud "${audience}" \
        '{client_id: $id, client_secret: ($secret | rtrimstr("\n")), grant_types: ["client_credentials"], scope: $scope,
          audience: [$aud], token_endpoint_auth_method: "client_secret_basic"}' \
        | admin_post "${which}" /admin/clients
}

info "Registering the demo clients on the Hydra instances"
for which in ${HYDRA_SET}; do
    register_cc_client "${which}" demo-caller "agent.read agent.write" "${AP_URL}"
done
if ! auth0_mode; then
    register_cc_client a "${NOSCOPE_CLIENT}" "" "${AP_URL}"
    register_cc_client a "${OTHERAUD_CLIENT}" "${REQUIRED_SCOPE}" "${OTHER_AUDIENCE}"
fi

info "Registering the hop 2 client and trusting the gateway signing key on hydra-b"
jq -n --arg id "${HOP2_CLIENT}" --rawfile secret "$(secret_file "b-${HOP2_CLIENT}.secret")" --arg scope "${HOP2_SCOPE}" \
    '{client_id: $id, client_secret: ($secret | rtrimstr("\n")), grant_types: ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
      scope: $scope, token_endpoint_auth_method: "client_secret_basic"}' \
    | admin_post b /admin/clients
expires_at="$(python3 -I -c 'import datetime as d; print((d.datetime.now(d.timezone.utc) + d.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
jwk="$(python3 -I "${OIDC_DEMO_DIR}/jwt_tools.py" jwk "${STATE_DIR}/gateway-hop2.pub.pem" gateway-hop2-key)"
jq -n --arg iss "${HOP2_ISSUER}" --arg sub "${HOP2_SUBJECT}" --arg scope "${HOP2_SCOPE}" --arg exp "${expires_at}" --argjson jwk "${jwk}" \
    '{issuer: $iss, subject: $sub, scope: [$scope], expires_at: $exp, jwk: $jwk}' \
    | admin_post b /admin/trust/grants/jwt-bearer/issuers

if curl -s -o /dev/null --connect-timeout 2 --max-time 4 "${AGENT_URL}/" 2>/dev/null; then
    fail "port ${AGENT_PORT} is already in use by another process; stop it or set OIDC_DEMO_AGENT_PORT"
fi
info "Starting the mock agent on ${AGENT_URL} (hop 2: ${HOP2})"
agent_args=(--port "${AGENT_PORT}" --public-url "${AGENT_URL}"
    --introspect-url "${HYDRA_B_ADMIN_URL}/admin/oauth2/introspect"
    --issuer "${HYDRA_B_ISSUER}" --scope "${HOP2_SCOPE}")
[[ "${HOP2}" == "on" ]] || agent_args+=(--open)
nohup python3 -I "${OIDC_DEMO_DIR}/mock_agent.py" "${agent_args[@]}" >"${STATE_DIR}/mock-agent.log" 2>&1 &
echo $! >"${STATE_DIR}/mock-agent.pid"
wait_http "${AGENT_URL}/_demo/log" "mock agent" 40

cat <<EOF

Demo services are up.
$(auth0_mode || printf '  hydra-a   %s   (admin %s)   caller authorization server\n' "${HYDRA_A_ISSUER}" "${HYDRA_A_ADMIN_URL}")
  hydra-b   ${HYDRA_B_ISSUER}   (admin ${HYDRA_B_ADMIN_URL})   second server; also the agent's own
  agent     ${AGENT_URL}
  gateway   ${GATEWAY_URL} (not started; scripts/oidc-demo/gateway.sh start --fresh starts it)
Next: make oidc-demo-seed (needs that gateway) or make oidc-demo-run (does everything).
EOF
