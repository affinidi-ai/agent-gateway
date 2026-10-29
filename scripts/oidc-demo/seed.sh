#!/usr/bin/env bash
#
# Seed a running demo gateway through the management API, with no human sign-in: the session
# comes from the test-mode login endpoint (AG_TEST_MODE=true, a debug build; see gateway.sh).
#
# Objects created, in order:
#   secrets            hop 2 signing key, client id and client secret (read from envs/oidc-demo-run/)
#   strategies         not created here: gateway.sh start writes one per Hydra instance into storage
#                      (the save-time URL checks refuse loopback), and this script checks they exist
#   policy             denies callers whose authentication failed
#   credential provider  oauth2_jwt_bearer pointing at hydra-b (skipped with hop 2 off)
#   surface            A2A Access Point at /mock-agent: jwt_bearer from hydra-a, required scope,
#                      target = the mock agent, Target Authentication through the provider
#
# With OIDC_DEMO_IDP=auth0 (see auth0.sh) the caller's authorization server is the Auth0 tenant: the
# strategy is created through the API with discovery, as the dashboard's Discover from issuer does, and
# the surface requires the Access Point URL (the tenant's API identifier) as audience and the scope agent:invoke.
#
# Usage: scripts/oidc-demo/seed.sh [--dry-run]
#   --dry-run   print the payloads with secret values redacted; no network and no gateway needed
#
# Fields added by the OIDC work (discover_metadata, required_scopes, the credential_provider
# Target Authentication method, the oauth2_jwt_bearer provider type) are sent as they are
# specified; a gateway build without them rejects or ignores them.

set -euo pipefail
unset CDPATH
# shellcheck source=scripts/oidc-demo/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DRY_RUN=false
for arg in "$@"; do
    case "${arg}" in
        --dry-run) DRY_RUN=true ;;
        -h|--help) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) fail "unknown option: ${arg}" ;;
    esac
done

require_tools curl jq
if auth0_mode && [[ "${DRY_RUN}" != true ]]; then auth0_load; fi
HOP2="$(hop2_mode)"
PROVIDER_SLUG="oidc-demo-hop2"
PROVIDER_RECORD_ID=""
KEY_SECRET_ID="OIDC_DEMO_HOP2_SIGNING_KEY"
CLIENT_ID_SECRET_ID="OIDC_DEMO_HOP2_CLIENT_ID"
CLIENT_SECRET_SECRET_ID="OIDC_DEMO_HOP2_CLIENT_SECRET"

# secret_payload ID NAME: the secrets API payload, with the value read from standard input.
secret_payload() {
    jq -Rs --arg id "$1" --arg name "$2" \
        '{secret_id: $id, name: $name, description: "OIDC demo hop 2", value: rtrimstr("\n")}'
}

policy_payload() {
    jq -n --arg id "${POLICY_ID}" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{
        id: $id, name: $id, description: "Deny callers whose authentication failed",
        policy_type: "agent_surface", enabled: true, created_at: $now,
        policy: "package surface.policy\n\ndefault allow := false\n\nallow if not deny\n\ndeny if input.source_auth.method == \"failed\"\n"}'
}

provider_payload() {
    jq -n --arg slug "${PROVIDER_SLUG}" --arg te "$(hydra_token_endpoint b)" --arg scope "${HOP2_SCOPE}" \
        --arg iss "${HOP2_ISSUER}" --arg sub "${HOP2_SUBJECT}" --arg key "${KEY_SECRET_ID}" \
        --arg cid "${CLIENT_ID_SECRET_ID}" --arg csec "${CLIENT_SECRET_SECRET_ID}" '{
        name: "OIDC demo hop 2", provider_id: $slug, provider_type: "oauth2_jwt_bearer",
        token_endpoint: $te, default_scopes: [$scope],
        client_id_secret_ref: $cid, client_secret_secret_ref: $csec,
        jwt_bearer: {assertion_issuer: $iss, assertion_subject: $sub, signing_key_secret_ref: $key,
                     signing_algorithm: "RS256", key_id: "gateway-hop2-key"}}'
}

# surface_payload STRATEGY_ID [METHOD_JSON]: the surface, with caller_auth_method_json STRATEGY_ID unless
# METHOD_JSON is given.
surface_payload() {
    local strategy_id="$1" target_auth="null"
    if [[ "${HOP2}" == "on" ]]; then
        target_auth="$(jq -n --arg slug "${PROVIDER_RECORD_ID:-<provider record id>}" '{method: {credential_provider: {credential_provider_id: $slug}}, fallback: "reject"}')"
    fi
    local method="${2:-}"
    [[ -n "${method}" ]] || method="$(caller_auth_method_json "${strategy_id}")"
    jq -n --arg id "${SURFACE_ID}" --arg listen "${ACCESS_POINT_ORIGIN}" --arg route "${SURFACE_ROUTE}" --arg agent "${AGENT_URL}" \
        --arg policy "${POLICY_ID}" --argjson method "${method}" --argjson auth "${target_auth}" '{
        surface_id: $id, name: "oidc-demo", description: "OIDC demo surface in front of the mock agent", status: "active",
        access_point: {listen_address: $listen, route: $route, protocol: "a2a", publish_to_did_document: false,
                       caller_authentication: {methods: [$method]},
                       inbound_policy: {policy_definition_id: $policy}},
        target: ({endpoint: $agent, policy: null, response_policy: null, mcp_tool_policies_enabled: false,
                  identity_injection: {inject_vp: false}, mpp_auto_pay: false}
                 + (if $auth == null then {} else {auth: $auth} end))}'
}

if [[ "${DRY_RUN}" == true ]]; then
    show() { printf '%s %s\n' "$1" "$2"; jq . ; }
    info "Dry run: nothing is sent. Secret values are redacted. Hop 2: ${HOP2}"
    if [[ "${HOP2}" == "on" ]]; then
        for pair in "${KEY_SECRET_ID}|OIDC demo hop 2 signing key" "${CLIENT_ID_SECRET_ID}|OIDC demo hop 2 client id" "${CLIENT_SECRET_SECRET_ID}|OIDC demo hop 2 client secret"; do
            printf '<redacted>' | secret_payload "${pair%%|*}" "${pair#*|}" | show POST /api/v1/secrets/new
        done
    fi
    info "Strategies come from gateway.sh start, which writes these storage records:"
    strategy_record_json a | jq .
    strategy_record_json b | jq .
    policy_payload | show POST /api/v1/policy-definitions
    if [[ "${HOP2}" == "on" ]]; then provider_payload | show POST /api/v1/credential-providers; fi
    surface_payload "${STRATEGY_A_ID}" | show POST /api/v1/surfaces
    exit 0
fi

make_tmp
trap 'rm -rf "${TMP_DIR}"' EXIT
gateway_session

api() {
    local method="$1" path="$2"
    shift 2
    curl -sS --connect-timeout 5 --max-time 30 -X "${method}" -H "@${SESSION_HEADER_FILE}" \
        -H 'Content-Type: application/json' -o "${TMP_DIR}/api-body" -w '%{http_code}' "$@" "${GATEWAY_URL}${path}"
}

api_ok() {
    local what="$1" method="$2" path="$3" code
    shift 3
    code="$(api "${method}" "${path}" "$@")" || fail "${what}: request failed"
    case "${code}" in
        200|201|204) ;;
        *) fail "${what}: HTTP ${code}: $(head -c 300 "${TMP_DIR}/api-body")" ;;
    esac
}

delete_named() {
    local path="$1" name_filter="$2" id ids
    api GET "${path}" >/dev/null || return 0
    ids="$(jq -r "(if type == \"array\" then . else (.items // .strategies // .surfaces // .providers // .secrets // .policies // []) end)
        | .[] | select(${name_filter}) | (.id // .surface_id // .secret_id)" "${TMP_DIR}/api-body" 2>/dev/null || true)"
    for id in ${ids}; do
        api DELETE "${path}/${id}" >/dev/null || true
    done
}

info "Removing objects from an earlier seed"
delete_named /api/v1/surfaces '.name == "oidc-demo"'
delete_named /api/v1/credential-providers '.provider_id == "oidc-demo-hop2"'
delete_named /api/v1/policy-definitions '.id == "oidc-demo-deny-failed-callers"'
for secret_id in "${KEY_SECRET_ID}" "${CLIENT_ID_SECRET_ID}" "${CLIENT_SECRET_SECRET_ID}"; do
    delete_named /api/v1/secrets ".secret_id == \"${secret_id}\""
done

if [[ "${HOP2}" == "on" ]]; then
    info "Creating the hop 2 secrets (values are never printed)"
    secret_payload "${KEY_SECRET_ID}" "OIDC demo hop 2 signing key" <"${STATE_DIR}/gateway-hop2.key" \
        | api_ok "signing key secret" POST /api/v1/secrets/new --data-binary @-
    printf '%s' "${HOP2_CLIENT}" | secret_payload "${CLIENT_ID_SECRET_ID}" "OIDC demo hop 2 client id" \
        | api_ok "client id secret" POST /api/v1/secrets/new --data-binary @-
    secret_payload "${CLIENT_SECRET_SECRET_ID}" "OIDC demo hop 2 client secret" <"$(secret_file "b-${HOP2_CLIENT}.secret")" \
        | api_ok "client secret secret" POST /api/v1/secrets/new --data-binary @-
fi

STRATEGY_IDS=("${STRATEGY_A_ID}" "${STRATEGY_B_ID}")
if auth0_mode; then STRATEGY_IDS=("${STRATEGY_B_ID}"); fi
info "Checking the verification strategies written by gateway.sh start"
for id in "${STRATEGY_IDS[@]}"; do
    code="$(api GET "/api/v1/jwt-verification-strategies/${id}")" || fail "strategy ${id}: request failed"
    [[ "${code}" == "200" ]] || fail "strategy ${id} is missing (HTTP ${code}); start the gateway with scripts/oidc-demo/gateway.sh start --fresh"
done
if ! auth0_mode; then
    api GET "/api/v1/jwt-verification-strategies/${STRATEGY_A_ID}" >/dev/null
    assert_eq "strategy a expected issuer" "${HYDRA_A_ISSUER}" "$(jq -r .expected_issuer "${TMP_DIR}/api-body")"
fi

info "Creating the deny policy"
policy_payload | api_ok "policy" POST /api/v1/policy-definitions --data-binary @-

if [[ "${HOP2}" == "on" ]]; then
    info "Creating the JWT bearer credential provider"
    provider_payload | api_ok "credential provider" POST /api/v1/credential-providers --data-binary @-
    PROVIDER_RECORD_ID="$(jq -er '.id' "${TMP_DIR}/api-body")" || fail "the credential provider response has no id"
fi

SURFACE_STRATEGY="${STRATEGY_A_ID}"
SURFACE_METHOD=""
if auth0_mode; then
    delete_named /api/v1/jwt-verification-strategies ".name == \"${AUTH0_STRATEGY_NAME}\""
    info "Discovering the Auth0 tenant's authorization server metadata"
    jq -n --arg iss "${AUTH0_ISSUER}" '{issuer: $iss}' | api_ok "discover" POST /api/v1/jwt-verification-strategies/discover --data-binary @-
    assert_eq "discovered issuer equals the tenant issuer, trailing slash included" "${AUTH0_ISSUER}" "$(jq -r .issuer "${TMP_DIR}/api-body")"
    jwks_uri="$(jq -er .jwks_uri "${TMP_DIR}/api-body")" || fail "discovery returned no jwks_uri"
    info "Creating the Auth0 verification strategy with discovery"
    jq -n --arg name "${AUTH0_STRATEGY_NAME}" --arg iss "${AUTH0_ISSUER}" --arg jwks "${jwks_uri}" \
        '{name: $name, expected_issuer: $iss, jwks_source: {type: "remote", jwks_uri: $jwks}, discover_metadata: true}' \
        | api_ok "auth0 strategy" POST /api/v1/jwt-verification-strategies --data-binary @-
    SURFACE_STRATEGY="$(jq -er '.id' "${TMP_DIR}/api-body")" || fail "the strategy response has no id"
    assert_eq "the strategy pins the tenant issuer" "${AUTH0_ISSUER}" "$(jq -r '.authorization_server.issuer' "${TMP_DIR}/api-body")"
    (umask 077; printf '%s\n' "${SURFACE_STRATEGY}" >"${STATE_DIR}/auth0-strategy-id")
    SURFACE_METHOD="$(auth0_auth_method_json "${SURFACE_STRATEGY}")"
fi

info "Creating the surface"
surface_payload "${SURFACE_STRATEGY}" ${SURFACE_METHOD:+"${SURFACE_METHOD}"} | api_ok "surface" POST /api/v1/surfaces --data-binary @-

pass "gateway seeded: surface ${SURFACE_ID} at ${AP_URL}"
