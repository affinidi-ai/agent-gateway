#!/usr/bin/env bash
#
# The Auth0 walkthrough: a caller reaches the mock agent through the gateway with a token from a live
# Auth0 tenant (hop 1), while the gateway reaches the agent with a hydra-b token (hop 2). Run it
# against a gateway that gateway.sh started and seed.sh seeded with OIDC_DEMO_IDP=auth0; auth0.sh does
# all of that. The tenant's API identifier must equal the Access Point URL, which the gateway derives
# as the resource and requires in aud. Token requests are limited on a free tenant, so each Auth0 client
# asks for one token and every call reuses it. Output holds no token and no value from the values file
# when piped through auth0_redact, which auth0.sh does.
#
#   1. the card declares the Auth0 authorization server and the scope
#   2. the protected resource metadata names the Access Point, the Auth0 issuer and the scope
#   3. the A2A SDKs parse the served card (only when the SDKs of make oidc-sdk-check are installed)
#   4. no token: 401 with a challenge that points at the metadata
#   5. one token per Auth0 app, with the issuer, audience and scope the gateway expects
#   6. the scoped app's token: 200, the mock agent answers
#   7. the app without the scope: 403 with insufficient_scope
#   8. a token from another issuer (hydra-b): 401
#   9. swapping the surface to hydra-b and back works without a gateway restart
#  10. hop 2: the gateway sent its own hydra-b token to the agent

set -euo pipefail
unset CDPATH
# shellcheck source=scripts/oidc-demo/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_tools curl jq python3
auth0_mode || fail "this walkthrough needs OIDC_DEMO_IDP=auth0; run scripts/oidc-demo/auth0.sh"
auth0_load
make_tmp
trap 'rm -rf "${TMP_DIR}"' EXIT
CARD_URL="${AP_URL}/.well-known/agent-card.json"
CARD="${TMP_DIR}/card.json"
SDK_DIR="${OIDC_SDK_DIR:-${REPO_ROOT}/tmp/oidc-sdk}"
RPC_BODY='{"jsonrpc":"2.0","id":7,"method":"message/send","params":{"message":{"role":"user","messageId":"demo-1","parts":[{"kind":"text","text":"hello"}]}}}'
AUTH0_STRATEGY_ID="$(cat "${STATE_DIR}/auth0-strategy-id")"

curl -fsS -o /dev/null --connect-timeout 3 "${GATEWAY_URL}/api/v1/alive" || fail "no gateway at ${GATEWAY_URL}; run scripts/oidc-demo/auth0.sh"
curl -fsS -o /dev/null --connect-timeout 3 "${AGENT_URL}/_demo/log" || fail "no mock agent at ${AGENT_URL}; run scripts/oidc-demo/auth0.sh"
GATEWAY_PID_BEFORE="$("${OIDC_DEMO_DIR}/gateway.sh" status)"

call_agent() {
    if [[ -n "${1:-}" ]]; then
        req POST "${AP_URL}" -H 'Content-Type: application/json' -H "Authorization: Bearer ${1}" -d "${RPC_BODY}"
    else
        req POST "${AP_URL}" -H 'Content-Type: application/json' -d "${RPC_BODY}"
    fi
}

step "The card declares the Auth0 authorization server and the scope"
req GET "${CARD_URL}"
[[ "${RESP_CODE}" == "200" ]] || { show_body; fail "card fetch returned ${RESP_CODE}"; }
show_body
cp "${RESP_BODY}" "${CARD}"
assert_json "the card's interface is the Access Point URL" ".url == \"${AP_URL}\"" "${CARD}"
assert_json "the card declares only the gateway's scheme" '(.securitySchemes | keys) == ["agent_gateway"]' "${CARD}"
METADATA_URL="$(jq -r '.securitySchemes.agent_gateway.oauth2MetadataUrl' "${CARD}")"
case "${METADATA_URL}" in
    "${AUTH0_ISSUER}.well-known/"*) pass "the card's metadata URL is a well-known document of the Auth0 issuer" ;;
    *) fail "the card does not name the Auth0 issuer's metadata document" ;;
esac
assert_json "the scheme lists exactly the scope ${AUTH0_SCOPE}" \
    "(.securitySchemes.agent_gateway.flows.clientCredentials.scopes | keys) == [\"${AUTH0_SCOPE}\"]" "${CARD}"
assert_json "the card requires the gateway's scheme with ${AUTH0_SCOPE}" ".security == [{agent_gateway: [\"${AUTH0_SCOPE}\"]}]" "${CARD}"
assert_json "the agent's own scheme and signatures are gone" \
    "(has(\"signatures\") | not) and ([tostring | contains(\"agent_own_oauth\", \"agent-as.internal.example\", \"${HYDRA_B_ISSUER}\")] | any | not)" "${CARD}"
printf '%s$ curl %s%s\n' "${C_DIM}" "${METADATA_URL}" "${C_OFF}"
curl -fsS --connect-timeout 5 --max-time 20 -o "${TMP_DIR}/as-metadata.json" "${METADATA_URL}" || fail "the Auth0 metadata document did not answer"
assert_eq "its issuer equals the tenant issuer, trailing slash included" "${AUTH0_ISSUER}" "$(jq -r .issuer "${TMP_DIR}/as-metadata.json")"
assert_eq "the card's token URL is the tenant's token endpoint" "$(jq -r .token_endpoint "${TMP_DIR}/as-metadata.json")" \
    "$(jq -r '.securitySchemes.agent_gateway.flows.clientCredentials.tokenUrl' "${CARD}")"

step "Protected resource metadata names the Access Point, the Auth0 issuer and the scope"
req GET "${PRM_URL}"
[[ "${RESP_CODE}" == "200" ]] || { show_body; fail "protected resource metadata returned ${RESP_CODE}"; }
show_body
assert_eq "resource is the Access Point URL" "${AP_URL}" "$(jq -r .resource "${RESP_BODY}")"
assert_eq "the Auth0 API identifier is that resource" "${AP_URL}" "${AUTH0_API_IDENTIFIER}"
assert_json "authorization_servers is exactly the Auth0 issuer" ".authorization_servers == [\"${AUTH0_ISSUER}\"]" "${RESP_BODY}"
assert_json "scopes_supported is exactly ${AUTH0_SCOPE}" ".scopes_supported == [\"${AUTH0_SCOPE}\"]" "${RESP_BODY}"

if [[ -x "${SDK_DIR}/py1/bin/python" ]]; then
    step "The A2A SDKs parse the card the gateway serves"
    SSL_CERT_FILE="${GATEWAY_CA_FILE}" NODE_EXTRA_CA_CERTS="${GATEWAY_CA_FILE}" \
        "${OIDC_DEMO_DIR}/sdk-check/run.sh" --live "${CARD_URL}" || fail "an A2A SDK did not parse the served card"
else
    info "A2A SDK check skipped: no SDKs under ${SDK_DIR}; see make oidc-sdk-check."
fi

step "No token: 401 with a challenge that points at the metadata"
call_agent
show_body
assert_eq "status" 401 "${RESP_CODE}"
CHALLENGE="$(header_value www-authenticate)"
info "WWW-Authenticate: ${CHALLENGE}"
case "${CHALLENGE}" in
    Bearer*"resource_metadata=\"${PRM_URL}\""*) pass "the challenge is a Bearer challenge pointing at ${PRM_URL}" ;;
    *) fail "the challenge does not point at the protected resource metadata" ;;
esac
case "${CHALLENGE}" in
    *"scope=\"${AUTH0_SCOPE}\""*) pass "the challenge names the scope ${AUTH0_SCOPE}" ;;
    *) fail "the challenge does not name the scope ${AUTH0_SCOPE}" ;;
esac

step "One token per Auth0 app (the only Auth0 token requests of this run)"
printf '%s$ curl -X POST <tenant>/oauth/token (JSON body from stdin: client_id, client_secret, audience, grant_type)%s\n' "${C_DIM}" "${C_OFF}"
SCOPED_TOKEN="$(auth0_token m2m)" || fail "the Auth0 token request for the scoped app failed"
NOSCOPE_TOKEN="$(auth0_token noscope)" || fail "the Auth0 token request for the app without scope failed"
jwt_claims "${SCOPED_TOKEN}" >"${TMP_DIR}/scoped-claims.json"
jwt_claims "${NOSCOPE_TOKEN}" >"${TMP_DIR}/noscope-claims.json"
assert_eq "scoped token iss" "${AUTH0_ISSUER}" "$(jq -r .iss "${TMP_DIR}/scoped-claims.json")"
assert_json "scoped token aud holds the Access Point URL" "[.aud] | flatten | index(\"${AP_URL}\") != null" "${TMP_DIR}/scoped-claims.json"
assert_json "scoped token scope claim holds ${AUTH0_SCOPE}" ".scope | split(\" \") | index(\"${AUTH0_SCOPE}\") != null" "${TMP_DIR}/scoped-claims.json"
assert_json "no-scope token aud holds the Access Point URL" "[.aud] | flatten | index(\"${AP_URL}\") != null" "${TMP_DIR}/noscope-claims.json"
assert_json "no-scope token has no scope or scp claim" 'has("scope") == false and has("scp") == false' "${TMP_DIR}/noscope-claims.json"
info "claim names of the scoped token: $(jq -r 'keys | join(", ")' "${TMP_DIR}/scoped-claims.json")"

step "The scoped app's token: 200 through the gateway, the mock agent answers"
call_agent "${SCOPED_TOKEN}"
show_body
assert_eq "status" 200 "${RESP_CODE}"
assert_json "the agent's reply came back through the gateway" '.result.parts[0].text == "mock agent reply"' "${RESP_BODY}"

step "The app without the scope: 403 with insufficient_scope"
call_agent "${NOSCOPE_TOKEN}"
show_body
assert_eq "status" 403 "${RESP_CODE}"
case "$(header_value www-authenticate)" in
    Bearer*insufficient_scope*) pass "the 403 names insufficient_scope" ;;
    *) fail "the 403 does not carry an insufficient_scope challenge" ;;
esac

step "A token from another issuer (hydra-b): 401"
printf '%s$ curl -K - -d grant_type=client_credentials --data-urlencode audience=%s --data-urlencode scope=%s %s (client credentials from stdin)%s\n' \
    "${C_DIM}" "${AP_URL}" "${REQUIRED_SCOPE}" "$(hydra_token_endpoint b)" "${C_OFF}"
HYDRA_TOKEN="$(fetch_token b demo-caller "${AP_URL}" "${REQUIRED_SCOPE}")" || fail "hydra-b token request failed"
call_agent "${HYDRA_TOKEN}"
show_body
assert_eq "status" 401 "${RESP_CODE}"
case "$(header_value www-authenticate)" in
    Bearer*"resource_metadata=\"${PRM_URL}\""*invalid_token*) pass "the 401 carries an invalid_token challenge with resource_metadata" ;;
    *) fail "the 401 has no invalid_token challenge with resource_metadata" ;;
esac

step "Swapping the surface to a hydra-b strategy and back works without a restart"
gateway_session
patch_method() {
    req PATCH "${GATEWAY_URL}/api/v1/surfaces/${SURFACE_ID}" -H 'Content-Type: application/merge-patch+json' -H "@${SESSION_HEADER_FILE}" \
        -d "$(jq -n --argjson m "$1" '{access_point: {caller_authentication: {methods: [$m]}}}')"
    [[ "${RESP_CODE}" == "200" ]] || { show_body; fail "surface patch returned ${RESP_CODE}"; }
}
patch_method "$(caller_auth_method_json "${STRATEGY_B_ID}")"
req GET "${PRM_URL}"
assert_json "the protected resource metadata now names hydra-b" ".authorization_servers == [\"${HYDRA_B_ISSUER}\"]" "${RESP_BODY}"
call_agent "${SCOPED_TOKEN}"
assert_eq "the Auth0 token is refused while hydra-b is active" 401 "${RESP_CODE}"
call_agent "${HYDRA_TOKEN}"
assert_eq "the hydra-b token is accepted while hydra-b is active" 200 "${RESP_CODE}"
patch_method "$(auth0_auth_method_json "${AUTH0_STRATEGY_ID}")"
req GET "${PRM_URL}"
assert_json "the protected resource metadata names the Auth0 issuer again" ".authorization_servers == [\"${AUTH0_ISSUER}\"]" "${RESP_BODY}"
call_agent "${SCOPED_TOKEN}"
assert_eq "the same Auth0 token is accepted again" 200 "${RESP_CODE}"
call_agent "${HYDRA_TOKEN}"
assert_eq "the hydra-b token is refused again" 401 "${RESP_CODE}"
assert_eq "the gateway was not restarted" "${GATEWAY_PID_BEFORE}" "$("${OIDC_DEMO_DIR}/gateway.sh" status)"

if [[ "$(hop2_mode)" == "on" ]]; then
    step "Hop 2: the gateway sent its own hydra-b token on the card fetch and on the call"
    curl -fsS -X POST "${AGENT_URL}/_demo/reset" -o /dev/null
    req GET "${CARD_URL}"
    assert_eq "card status" 200 "${RESP_CODE}"
    call_agent "${SCOPED_TOKEN}"
    assert_eq "call status" 200 "${RESP_CODE}"
    req GET "${AGENT_URL}/_demo/log"
    show_body
    assert_json "the agent saw an authenticated card fetch and an authenticated call, both as ${HOP2_CLIENT}" \
        "length >= 2 and all(.authenticated and .client_id == \"${HOP2_CLIENT}\") and ([.[] | select(.method == \"GET\")] | length >= 1) and ([.[] | select(.method == \"POST\")] | length >= 1)" "${RESP_BODY}"
    assert_json "the caller's Auth0 token never reached the agent (no refused request in the log)" 'all(.status == 200)' "${RESP_BODY}"
else
    info "Hop 2 step skipped: the harness was started with hop 2 off."
fi

printf '\n%sAuth0 walkthrough passed.%s\n' "${C_GREEN}" "${C_OFF}"
