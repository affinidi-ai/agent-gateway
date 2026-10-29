#!/usr/bin/env bash
#
# Checks the demo's supporting pieces without a gateway: both Hydra instances (discovery, token
# flows, the JWT bearer grant), the protected mock agent, and a seeding dry run. Every check
# asserts and the script exits non-zero on the first failure. It starts the services itself when
# they are not running and stops them afterwards unless OIDC_DEMO_KEEP=1.

set -euo pipefail
unset CDPATH
# shellcheck source=scripts/oidc-demo/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_tools curl jq openssl python3
make_tmp

STARTED=false
cleanup() {
    rm -rf "${TMP_DIR}"
    if [[ "${STARTED}" == true && "${OIDC_DEMO_KEEP:-0}" != "1" ]]; then
        "${OIDC_DEMO_DIR}/down.sh" --services-only >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if ! curl -fsS -o /dev/null --connect-timeout 2 "${HYDRA_A_ADMIN_URL}/health/ready" 2>/dev/null \
    || ! curl -fsS -o /dev/null --connect-timeout 2 "${AGENT_URL}/_demo/log" 2>/dev/null; then
    STARTED=true
    "${OIDC_DEMO_DIR}/up.sh"
fi
HOP2="$(hop2_mode)"

# jwt_bearer_grant ASSERTION OUT [curl args...]: the JWT bearer grant on hydra-b as the hop 2 client;
# prints the HTTP status. The client secret and the assertion reach curl as a config on standard input.
jwt_bearer_grant() {
    local assertion="$1" out="$2"
    shift 2
    printf 'user = "%s:%s"\ndata-urlencode = "assertion=%s"\n' \
        "${HOP2_CLIENT}" "$(cat "$(secret_file "b-${HOP2_CLIENT}.secret")")" "${assertion}" \
        | curl -sS --connect-timeout 5 --max-time 20 -K - -o "${out}" -w '%{http_code}' \
            -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer "$@" "$(hydra_token_endpoint b)"
}

step "Hydra discovery: issuer string, RFC 8414 equals OIDC"
for which in a b; do
    base="http://127.0.0.1:$(hydra_public "${which}")"
    curl -fsS "${base}/.well-known/oauth-authorization-server" -o "${TMP_DIR}/rfc8414-${which}.json"
    curl -fsS "${base}/.well-known/openid-configuration" -o "${TMP_DIR}/oidc-${which}.json"
    assert_eq "hydra-${which} issuer" "$(hydra_issuer "${which}")" "$(jq -r .issuer "${TMP_DIR}/rfc8414-${which}.json")"
    assert_eq "hydra-${which} token endpoint" "$(hydra_token_endpoint "${which}")" "$(jq -r .token_endpoint "${TMP_DIR}/rfc8414-${which}.json")"
    assert_eq "hydra-${which} RFC 8414 document equals the OIDC document" \
        "$(jq -S . "${TMP_DIR}/oidc-${which}.json" | shasum -a 256 | cut -d' ' -f1)" \
        "$(jq -S . "${TMP_DIR}/rfc8414-${which}.json" | shasum -a 256 | cut -d' ' -f1)"
    curl -fsS "$(jq -r .jwks_uri "${TMP_DIR}/rfc8414-${which}.json")" -o "${TMP_DIR}/jwks-${which}.json"
    assert_json "hydra-${which} JWKS holds an RS256 signing key" '[.keys[] | select(.use == "sig" and .alg == "RS256")] | length > 0' "${TMP_DIR}/jwks-${which}.json"
done

step "Caller token flows on both Hydra instances (JWT access token, list scope claim, audience)"
for which in a b; do
    token="$(fetch_token "${which}" demo-caller "${AP_URL}" "${REQUIRED_SCOPE}")"
    jwt_claims "${token}" >"${TMP_DIR}/claims.json"
    printf '%s' "${token}" | python3 -I "${OIDC_DEMO_DIR}/jwt_tools.py" header - >"${TMP_DIR}/header.json"
    assert_json "hydra-${which} access token is a JWT signed with RS256" '.alg == "RS256" and .typ == "JWT"' "${TMP_DIR}/header.json"
    assert_eq "hydra-${which} token iss" "$(hydra_issuer "${which}")" "$(jq -r .iss "${TMP_DIR}/claims.json")"
    assert_json "hydra-${which} token aud holds the Access Point URL" ".aud | index(\"${AP_URL}\") != null" "${TMP_DIR}/claims.json"
    assert_json "hydra-${which} token scp is the list [${REQUIRED_SCOPE}]" ".scp == [\"${REQUIRED_SCOPE}\"]" "${TMP_DIR}/claims.json"
    assert_eq "hydra-${which} token client_id" "demo-caller" "$(jq -r .client_id "${TMP_DIR}/claims.json")"

    if fetch_token "${which}" demo-caller "https://evil.example/" "${REQUIRED_SCOPE}" >/dev/null 2>&1; then
        fail "hydra-${which} issued a token for an audience the client may not request"
    fi
    pass "hydra-${which} refuses an audience the client is not registered for"
done

step "Hop 2 on hydra-b: JWT bearer grant with the gateway signing key (what the gateway will send)"
assertion="$(python3 -I "${OIDC_DEMO_DIR}/jwt_tools.py" assertion "${STATE_DIR}/gateway-hop2.key" gateway-hop2-key \
    "${HOP2_ISSUER}" "${HOP2_SUBJECT}" "$(hydra_token_endpoint b)" "${HOP2_SCOPE}")"
code="$(jwt_bearer_grant "${assertion}" "${TMP_DIR}/hop2-token.json" -d "scope=${HOP2_SCOPE}")" \
    || fail "the JWT bearer grant request to hydra-b failed"
assert_eq "hydra-b grants the JWT bearer assertion" 200 "${code}"
hop2_token="$(jq -er .access_token "${TMP_DIR}/hop2-token.json")"
jwt_claims "${hop2_token}" >"${TMP_DIR}/claims.json"
assert_json "hop 2 token: issuer hydra-b, subject ${HOP2_SUBJECT}, scope [${HOP2_SCOPE}], client ${HOP2_CLIENT}" \
    ".iss == \"$(hydra_issuer b)\" and .sub == \"${HOP2_SUBJECT}\" and .scp == [\"${HOP2_SCOPE}\"] and .client_id == \"${HOP2_CLIENT}\"" "${TMP_DIR}/claims.json"
replayed="$(jwt_bearer_grant "${assertion}" /dev/null)" || fail "the replayed JWT bearer grant request to hydra-b failed"
assert_eq "a replayed assertion (same jti) is refused" 400 "${replayed}"

step "Mock agent: login-only card and calls"
curl -fsS -X POST "${AGENT_URL}/_demo/reset" -o /dev/null
code="$(curl -sS -o /dev/null -w '%{http_code}' "${AGENT_URL}/.well-known/agent-card.json")"
if [[ "${HOP2}" == "on" ]]; then
    assert_eq "card without a token" 401 "${code}"
    caller_token="$(fetch_token a demo-caller "${AP_URL}" "${REQUIRED_SCOPE}")"
    caller_header="$(bearer_header_file caller-header "${caller_token}")"
    hop2_header="$(bearer_header_file hop2-header "${hop2_token}")"
    code="$(curl -sS -o /dev/null -w '%{http_code}' -H "@${caller_header}" "${AGENT_URL}/.well-known/agent-card.json")"
    assert_eq "card with a caller token from hydra-a (wrong server and scope)" 401 "${code}"
    code="$(curl -sS -o "${TMP_DIR}/card.json" -w '%{http_code}' -H "@${hop2_header}" "${AGENT_URL}/.well-known/agent-card.json")"
    assert_eq "card with the hop 2 token" 200 "${code}"
    assert_json "card is the agent's" '.name == "OIDC Demo Mock Agent"' "${TMP_DIR}/card.json"
    code="$(curl -sS -o "${TMP_DIR}/rpc.json" -w '%{http_code}' -H "@${hop2_header}" -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","messageId":"m1","parts":[{"kind":"text","text":"hi"}]}}}' "${AGENT_URL}/")"
    assert_eq "message/send with the hop 2 token" 200 "${code}"
    assert_json "message/send returns the mock reply" '.result.parts[0].text == "mock agent reply" and .id == 1' "${TMP_DIR}/rpc.json"
    code="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":2,"method":"message/send"}' "${AGENT_URL}/")"
    assert_eq "message/send without a token" 401 "${code}"
    curl -fsS "${AGENT_URL}/_demo/log" -o "${TMP_DIR}/agent-log.json"
    assert_json "the agent log records the authenticated card fetch and call as ${HOP2_CLIENT}, and the refusals" \
        "([.[] | select(.authenticated)] | length == 2 and all(.client_id == \"${HOP2_CLIENT}\")) and ([.[] | select(.authenticated | not)] | length == 3)" "${TMP_DIR}/agent-log.json"
else
    assert_eq "card without a token (hop 2 off: the agent is open)" 200 "${code}"
fi

step "Seeding dry run: payloads are valid and hold no secret values"
"${OIDC_DEMO_DIR}/seed.sh" --dry-run >"${TMP_DIR}/seed-dry-run.txt"
grep -q 'oidc-demo' "${TMP_DIR}/seed-dry-run.txt" || fail "dry run printed no demo objects"
for name in hydra-a.system b-demo-caller.secret "b-${HOP2_CLIENT}.secret" test-token; do
    secret_path="$(secret_file "${name}")"
    [[ -s "${secret_path}" ]] || fail "${name} is missing; run up.sh first"
    if grep -qFf "${secret_path}" "${TMP_DIR}/seed-dry-run.txt"; then
        fail "the seed dry run printed the value of ${name}"
    fi
done
if grep -q 'BEGIN' "${TMP_DIR}/seed-dry-run.txt"; then fail "the seed dry run printed key material"; fi
pass "dry run printed no secret values or key material"

printf '\n%sSmoke checks passed.%s\n' "${C_GREEN}" "${C_OFF}"
