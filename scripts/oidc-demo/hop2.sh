#!/usr/bin/env bash
#
# The hop 2 checks, for a stack that is up and seeded (up.sh, gateway.sh start --fresh, seed.sh).
# The gateway gets its own token from hydra-b with the JWT bearer grant and sends it to the mock
# agent, which accepts nothing else.
#
#   1. Card fetch through the gateway succeeds although the agent's card endpoint needs a token.
#   2. A call through the gateway reaches the agent with a token the agent validated.
#   3. The gateway obtained that token from hydra-b with the JWT bearer grant.
#   4. A second call does not reach hydra-b's token endpoint again.
#   5. After the trust grant is revoked and the gateway restarted (empty token cache), the call
#      fails with the generic gateway error and no key or token detail in the body.
#   6. The gateway log of each run carries no key, assertion, token or token endpoint error text.
#
# The script restarts the gateway first (empty token cache) and revokes the trust grant at the
# end, so run up.sh, gateway.sh start --fresh and seed.sh again before repeating it.
# Tokens are never printed. Exit status is non-zero on the first failed assertion.

set -euo pipefail
unset CDPATH
# shellcheck source=scripts/oidc-demo/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_tools curl jq docker python3
make_tmp
trap 'rm -rf "${TMP_DIR}"' EXIT

RPC_BODY='{"jsonrpc":"2.0","id":7,"method":"message/send","params":{"message":{"role":"user","messageId":"hop2-1","parts":[{"kind":"text","text":"hello"}]}}}'

token_requests() {
    docker logs "${HYDRA_B_NAME}" 2>&1 | grep 'completed handling request' | grep -c 'path:/oauth2/token' || true
}

AGENT_LOG="${TMP_DIR}/agent-log.json"
agent_log() { curl -sS "${AGENT_URL}/_demo/log" -o "${AGENT_LOG}" || fail "could not read the mock agent log"; }

caller_token() { fetch_token a demo-caller "${AP_URL}" "${REQUIRED_SCOPE}"; }

gateway_log_is_clean() {
    [[ -f "${GATEWAY_LOG_FILE}" ]] || fail "no gateway log at ${GATEWAY_LOG_FILE}"
    if grep -qE 'eyJ[A-Za-z0-9_-]{8,}\.|PRIVATE KEY|ory_at_|The provided authorization grant' "${GATEWAY_LOG_FILE}"; then
        fail "the gateway log ($1) carries a key, an assertion, a token or the token endpoint's error text"
    fi
    pass "the gateway log ($1) carries no key, assertion, token or token endpoint error text"
}

call_gateway() {
    local token
    token="$(caller_token)" || fail "no caller token from hydra-a"
    req POST "${AP_URL}" -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' --data "${RPC_BODY}"
}

grants="${TMP_DIR}/grants"
curl -sS "${HYDRA_B_ADMIN_URL}/admin/trust/grants/jwt-bearer/issuers" -o "${grants}"
jq -e --arg iss "${HOP2_ISSUER}" 'any(.[]; .issuer == $iss)' "${grants}" >/dev/null \
    || fail "hydra-b has no trust grant for ${HOP2_ISSUER}; this script revokes it, so run up.sh again before repeating"
"${OIDC_DEMO_DIR}/gateway.sh" start >/dev/null
curl -sS -X POST "${AGENT_URL}/_demo/reset" >/dev/null
BASE="$(token_requests)"
info "hydra-b token requests so far: ${BASE}"

step "Agent card fetch through the gateway (the agent's card needs a hydra-b token)"
req GET "${AP_URL}/.well-known/agent-card.json" -H 'Accept: application/json'
assert_eq "card status" 200 "${RESP_CODE}"
assert_json "card is the agent's" '.name == "OIDC Demo Mock Agent"' "${RESP_BODY}"
agent_log
assert_json "agent saw an authenticated card fetch as ${HOP2_CLIENT}" \
    '[.[] | select(.method == "GET" and .authenticated == true and .client_id == "'"${HOP2_CLIENT}"'")] | length >= 1' "${AGENT_LOG}"

step "Call through the gateway reaches the agent with a valid hydra-b token"
call_gateway
assert_eq "call status" 200 "${RESP_CODE}"
assert_json "agent replied" '.result.parts[0].text == "mock agent reply"' "${RESP_BODY}"
agent_log
assert_json "agent validated the call token as ${HOP2_CLIENT}" \
    '[.[] | select(.method == "POST" and .authenticated == true and .client_id == "'"${HOP2_CLIENT}"'")] | length == 1' "${AGENT_LOG}"
assert_json "agent saw no rejected request" '[.[] | select(.status != 200)] | length == 0' "${AGENT_LOG}"

step "The gateway obtained its token from hydra-b with the JWT bearer grant"
AFTER_FIRST="$(token_requests)"
info "hydra-b token requests after card fetch and first call: $((AFTER_FIRST - BASE))"
[[ "$((AFTER_FIRST - BASE))" -ge 1 ]] || fail "hydra-b saw no token request"
pass "hydra-b served $((AFTER_FIRST - BASE)) token request(s) for the gateway"

step "A second call reuses the cached token"
call_gateway
assert_eq "second call status" 200 "${RESP_CODE}"
assert_eq "hydra-b token requests unchanged" "${AFTER_FIRST}" "$(token_requests)"
gateway_log_is_clean "granted"

step "Negative: revoke the trust grant, restart the gateway (empty cache), call again"
grant_id="$(jq -er --arg iss "${HOP2_ISSUER}" '[.[] | select(.issuer == $iss)][0].id' "${grants}")" || fail "no trust grant for ${HOP2_ISSUER}"
code="$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "${HYDRA_B_ADMIN_URL}/admin/trust/grants/jwt-bearer/issuers/${grant_id}")"
assert_eq "trust grant revoked (HTTP)" 204 "${code}"
"${OIDC_DEMO_DIR}/gateway.sh" start >/dev/null
call_gateway
assert_eq "call status after revoke" 502 "${RESP_CODE}"
show_body
if grep -qiE 'bearer|eyJ|PRIVATE|assertion|invalid_grant|hydra|client_secret|14454' "${RESP_BODY}"; then
    fail "the 502 body carries key, token or authorization server detail"
fi
pass "502 body has no key, token or authorization server detail"
grep -q 'Target authentication failed' "${GATEWAY_LOG_FILE}" || fail "the gateway log does not record the Target authentication failure"
gateway_log_is_clean "refused"
agent_log
assert_json "agent saw no authenticated call after the revoke (the two earlier calls only)" '[.[] | select(.method == "POST" and .authenticated == true)] | length == 2' "${AGENT_LOG}"

pass "hop 2 verified"
