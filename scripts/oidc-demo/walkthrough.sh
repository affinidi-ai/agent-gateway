#!/usr/bin/env bash
#
# The scripted demo of the caller's side: a caller discovers, obtains a token for and calls an A2A agent
# that sits behind the gateway, with hydra-a as the caller's authorization server. Every step prints its
# curl transcript (access tokens are never printed), asserts what it expects and exits non-zero on the
# first failure. Run it against a gateway that gateway.sh started and seed.sh seeded; run.sh runs
# hop2.sh after it for the gateway to agent side.
#
#   1. the card names hydra-a and the required scope; the mock agent's own scheme and signatures are gone
#   2. the authorization server metadata issuer equals the issuer the card points at
#   3. the protected resource metadata matches the Access Point
#   4. a token for the good client, with the Access Point as audience
#   5. a call with that token returns 200
#   6. no token: 401 with a resource_metadata challenge
#   7. a token for another audience: 401
#   8. a token without the required scope: 403 insufficient_scope
#   9. removing the required scope keeps the gateway refusing a caller without a token
#  10. swapping the surface to hydra-b changes the card and the validation, without a restart
#  11. swapping it back to hydra-a restores both

set -euo pipefail
unset CDPATH
# shellcheck source=scripts/oidc-demo/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

! auth0_mode || fail "this walkthrough runs with Hydra as the caller's authorization server; Auth0 mode runs walkthrough-auth0.sh"
require_tools curl jq python3
make_tmp
trap 'rm -rf "${TMP_DIR}"' EXIT
CARD_URL="${AP_URL}/.well-known/agent-card.json"
RPC_BODY='{"jsonrpc":"2.0","id":7,"method":"message/send","params":{"message":{"role":"user","messageId":"demo-1","parts":[{"kind":"text","text":"hello"}]}}}'
ACTIVE="a"

curl -fsS -o /dev/null --connect-timeout 3 "${GATEWAY_URL}/api/v1/alive" || fail "no gateway at ${GATEWAY_URL}; run scripts/oidc-demo/gateway.sh start --fresh and scripts/oidc-demo/seed.sh first"
curl -fsS -o /dev/null --connect-timeout 3 "${AGENT_URL}/_demo/log" || fail "no mock agent at ${AGENT_URL}; run scripts/oidc-demo/up.sh first"
GATEWAY_PID_BEFORE="$("${OIDC_DEMO_DIR}/gateway.sh" status)"

# call_agent [TOKEN]: POSTs the JSON-RPC message to the Access Point, with a bearer token when given.
call_agent() {
    if [[ -n "${1:-}" ]]; then
        req POST "${AP_URL}" -H 'Content-Type: application/json' -H "Authorization: Bearer ${1}" -d "${RPC_BODY}"
    else
        req POST "${AP_URL}" -H 'Content-Type: application/json' -d "${RPC_BODY}"
    fi
}

# token_for CLIENT AUDIENCE [SCOPE]: obtains a token from the active Hydra and prints the request, not the token.
token_for() {
    local scope_arg=""
    [[ -z "${3:-}" ]] || scope_arg=" -d scope=$3"
    printf '%s$ curl -u %s:<redacted> -d grant_type=client_credentials -d audience=%s%s %s%s\n' \
        "${C_DIM}" "$1" "$2" "${scope_arg}" "$(hydra_token_endpoint "${ACTIVE}")" "${C_OFF}" >&2
    fetch_token "${ACTIVE}" "$1" "$2" "${3:-}" || fail "token request for $1 failed"
}

# use_strategy STRATEGY_ID: points the surface's caller authentication at a strategy through the management API.
use_strategy() {
    req PATCH "${GATEWAY_URL}/api/v1/surfaces/${SURFACE_ID}" -H 'Content-Type: application/merge-patch+json' -H "@${SESSION_HEADER_FILE}" \
        -d "$(jq -n --argjson m "$(caller_auth_method_json "$1")" '{access_point: {caller_authentication: {methods: [$m]}}}')"
    [[ "${RESP_CODE}" == "200" ]] || { show_body; fail "surface patch returned ${RESP_CODE}"; }
}

metadata_url_filter() {
    printf '[.. | objects | select(has("oauth2MetadataUrl")) | .oauth2MetadataUrl] == ["%s.well-known/oauth-authorization-server"]' "$1"
}

step "The card names hydra-a and the required scope; the agent's own scheme and signatures are gone"
req GET "${CARD_URL}"
[[ "${RESP_CODE}" == "200" ]] || { show_body; fail "card fetch returned ${RESP_CODE}"; }
show_body
assert_json "the card names hydra-a's metadata document" "$(metadata_url_filter "${HYDRA_A_ISSUER}")" "${RESP_BODY}"
assert_json "the card lists the required scope ${REQUIRED_SCOPE}" \
    "[.. | objects | select(has(\"oauth2MetadataUrl\")) | .. | objects | select(has(\"scopes\")) | .scopes | keys[]] | index(\"${REQUIRED_SCOPE}\") != null" "${RESP_BODY}"
assert_json "the agent's own scheme is gone" '[.. | objects | keys[]] | index("agent_own_oauth") == null' "${RESP_BODY}"
assert_json "the agent's own token URL is gone" '[.. | strings | select(contains("agent-as.internal.example"))] | length == 0' "${RESP_BODY}"
assert_json "the signatures are gone" '[.. | objects | keys[]] | index("signatures") == null' "${RESP_BODY}"
assert_json "the card points callers at the Access Point" ".url == \"${AP_URL}\" or ([.. | strings | select(. == \"${AP_URL}\")] | length > 0)" "${RESP_BODY}"

step "The authorization server metadata issuer equals the card's issuer"
METADATA_URL="$(jq -r '[.. | objects | select(has("oauth2MetadataUrl")) | .oauth2MetadataUrl] | .[0]' "${RESP_BODY}")"
req GET "${METADATA_URL}"
[[ "${RESP_CODE}" == "200" ]] || fail "authorization server metadata returned ${RESP_CODE}"
assert_eq "metadata issuer equals the configured issuer, trailing slash included" "${HYDRA_A_ISSUER}" "$(jq -r .issuer "${RESP_BODY}")"
assert_eq "the card's metadata URL is the issuer's RFC 8414 location" "${HYDRA_A_ISSUER}.well-known/oauth-authorization-server" "${METADATA_URL}"
assert_eq "token endpoint" "$(hydra_token_endpoint a)" "$(jq -r .token_endpoint "${RESP_BODY}")"

step "Protected resource metadata (RFC 9728) matches the Access Point"
req GET "${PRM_URL}"
[[ "${RESP_CODE}" == "200" ]] || { show_body; fail "protected resource metadata returned ${RESP_CODE}"; }
show_body
assert_eq "resource" "${AP_URL}" "$(jq -r .resource "${RESP_BODY}")"
assert_json "authorization_servers is exactly hydra-a's issuer" ".authorization_servers == [\"${HYDRA_A_ISSUER}\"]" "${RESP_BODY}"
assert_json "scopes_supported is exactly the required scope" ".scopes_supported == [\"${REQUIRED_SCOPE}\"]" "${RESP_BODY}"

step "A token for the good client, with the Access Point as audience"
GOOD_TOKEN="$(token_for demo-caller "${AP_URL}" "${REQUIRED_SCOPE}")"
jwt_claims "${GOOD_TOKEN}" >"${TMP_DIR}/claims.json"
assert_json "aud holds the Access Point" ".aud | index(\"${AP_URL}\") != null" "${TMP_DIR}/claims.json"
assert_eq "iss" "${HYDRA_A_ISSUER}" "$(jq -r .iss "${TMP_DIR}/claims.json")"
assert_json "scp" ".scp == [\"${REQUIRED_SCOPE}\"]" "${TMP_DIR}/claims.json"

step "A call with the token returns 200"
call_agent "${GOOD_TOKEN}"
show_body
assert_eq "status" 200 "${RESP_CODE}"
assert_json "the agent's reply came back through the gateway" '.result.parts[0].text == "mock agent reply"' "${RESP_BODY}"

step "No token: 401 with a resource_metadata challenge"
call_agent
show_body
assert_eq "status" 401 "${RESP_CODE}"
CHALLENGE="$(header_value www-authenticate)"
info "WWW-Authenticate: ${CHALLENGE}"
[[ "${CHALLENGE}" == Bearer* && "${CHALLENGE}" == *"resource_metadata=\"${PRM_URL}\""* ]] \
    || fail "the challenge does not point at the protected resource metadata"
pass "the challenge is a Bearer challenge pointing at ${PRM_URL}"
[[ "${CHALLENGE}" == *"scope=\"${REQUIRED_SCOPE}\""* ]] || fail "the challenge does not name the required scope"
pass "the challenge names the scope ${REQUIRED_SCOPE}"

step "A token for another audience: 401"
OTHER_TOKEN="$(token_for "${OTHERAUD_CLIENT}" "${OTHER_AUDIENCE}" "${REQUIRED_SCOPE}")"
call_agent "${OTHER_TOKEN}"
show_body
assert_eq "status" 401 "${RESP_CODE}"
[[ "$(header_value www-authenticate)" == Bearer*resource_metadata=* ]] || fail "the 401 has no resource_metadata challenge"
pass "the 401 carries a Bearer challenge with resource_metadata"

step "A token without the required scope: 403"
NOSCOPE_TOKEN="$(token_for "${NOSCOPE_CLIENT}" "${AP_URL}")"
call_agent "${NOSCOPE_TOKEN}"
show_body
assert_eq "status" 403 "${RESP_CODE}"
[[ "$(header_value www-authenticate)" == Bearer*insufficient_scope* ]] || fail "the 403 does not carry an insufficient_scope challenge"
pass "the 403 names insufficient_scope"

step "Removing the required scope keeps the gateway refusing a caller without a token"
gateway_session
req PATCH "${GATEWAY_URL}/api/v1/surfaces/${SURFACE_ID}" -H 'Content-Type: application/merge-patch+json' -H "@${SESSION_HEADER_FILE}" \
    -d "$(jq -n --arg sid "${STRATEGY_A_ID}" '{access_point: {caller_authentication: {methods: [{type: "jwt_bearer", jwt_verification_strategy_id: $sid, audiences: []}]}}}')"
[[ "${RESP_CODE}" == "200" ]] || { show_body; fail "surface patch returned ${RESP_CODE}"; }
call_agent
assert_eq "status" 401 "${RESP_CODE}"
CHALLENGE="$(header_value www-authenticate)"
[[ "${CHALLENGE}" == *"resource_metadata=\"${PRM_URL}\""* ]] || fail "the challenge does not point at the protected resource metadata"
[[ "${CHALLENGE}" != *"scope="* ]] || fail "the challenge still names a scope"
pass "the challenge points at ${PRM_URL} and names no scope"
req GET "${PRM_URL}"
assert_eq "metadata status" 200 "${RESP_CODE}"
assert_json "the protected resource metadata lists no scopes" '(.scopes_supported // []) == []' "${RESP_BODY}"
use_strategy "${STRATEGY_A_ID}"

step "Swapping the surface to hydra-b changes the card and the validation, without a restart"
use_strategy "${STRATEGY_B_ID}"
req GET "${CARD_URL}"
assert_eq "card status" 200 "${RESP_CODE}"
assert_json "the card now names hydra-b's metadata document" "$(metadata_url_filter "${HYDRA_B_ISSUER}")" "${RESP_BODY}"
req GET "${PRM_URL}"
assert_json "the protected resource metadata now names hydra-b" ".authorization_servers == [\"${HYDRA_B_ISSUER}\"]" "${RESP_BODY}"
call_agent "${GOOD_TOKEN}"
assert_eq "the hydra-a token is refused" 401 "${RESP_CODE}"
ACTIVE="b"
B_TOKEN="$(token_for demo-caller "${AP_URL}" "${REQUIRED_SCOPE}")"
call_agent "${B_TOKEN}"
assert_eq "a hydra-b token is accepted" 200 "${RESP_CODE}"
assert_eq "the gateway was not restarted" "${GATEWAY_PID_BEFORE}" "$("${OIDC_DEMO_DIR}/gateway.sh" status)"

step "Swapping back to hydra-a restores the card and the validation"
use_strategy "${STRATEGY_A_ID}"
ACTIVE="a"
req GET "${CARD_URL}"
assert_eq "card status" 200 "${RESP_CODE}"
assert_json "the card names hydra-a's metadata document again" "$(metadata_url_filter "${HYDRA_A_ISSUER}")" "${RESP_BODY}"
req GET "${PRM_URL}"
assert_json "the protected resource metadata names hydra-a again" ".authorization_servers == [\"${HYDRA_A_ISSUER}\"]" "${RESP_BODY}"
call_agent "${B_TOKEN}"
assert_eq "the hydra-b token is refused" 401 "${RESP_CODE}"
call_agent "${GOOD_TOKEN}"
assert_eq "the hydra-a token is accepted again" 200 "${RESP_CODE}"

printf '\n%sWalkthrough passed.%s\n' "${C_GREEN}" "${C_OFF}"
