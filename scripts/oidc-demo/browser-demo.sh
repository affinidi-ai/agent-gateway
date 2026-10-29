#!/usr/bin/env bash
#
# Leave the OIDC demo running in the background so the Agent card tab can be shown in a browser.
#
#   browser-demo.sh start       build what is stale, start Hydra, the mock agent and the native gateway,
#                               seed the demo surface and its credential provider, write the dashboard
#                               login to a file, print the URLs and return
#   browser-demo.sh stop        stop the gateway, the mock agent and the containers
#   browser-demo.sh status      what is running, and whether the mock agent refuses the gateway
#   browser-demo.sh login       issue a fresh dashboard session and rewrite the login file
#   browser-demo.sh break-card  the mock agent refuses the gateway's token: the card fetch fails with 401
#                               and the gateway serves no card
#   browser-demo.sh fix-card    the mock agent checks tokens again
#
# break-card and fix-card only call the mock agent's /_demo/refuse control. They never restart the gateway:
# open the Agent card tab and press Refresh afterwards. The login file is tmp/local-oidc-demo/dashboard-login.txt
# (mode 600). It holds a console snippet that signs the browser in as the demo operator; it is never printed.

set -euo pipefail
unset CDPATH
# shellcheck source=scripts/oidc-demo/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

LOGIN_FILE="${GATEWAY_ENV_DIR}/dashboard-login.txt"
DASHBOARD_URL="${GATEWAY_URL}/surfaces/${SURFACE_ID}"
SERVED_CARD_URL="${AP_URL}/.well-known/agent-card.json"
SOURCE_CARD_URL="${AGENT_URL}/.well-known/agent-card.json"

agent_up() { curl -fsS -o /dev/null --connect-timeout 2 --max-time 4 "${AGENT_URL}/_demo/log" 2>/dev/null; }
gateway_up() { curl -fsS -o /dev/null --connect-timeout 2 --max-time 4 "${GATEWAY_URL}/api/v1/alive" 2>/dev/null; }

demo_containers() {
    docker ps --filter "name=${NAME_PREFIX}-" --format '{{.Names}}' 2>/dev/null || true
}

stale() {
    local src_dir="$1" out_dir="$2" newest
    [[ -f "${out_dir}/index.html" ]] || return 0
    newest="$(find "${src_dir}" -type f -not -path '*/node_modules/*' -newer "${out_dir}/index.html" -print -quit)"
    [[ -n "${newest}" ]]
}

ensure_dashboard_build() {
    cd "${REPO_ROOT}/www/default" || fail "cannot enter ${REPO_ROOT}/www/default"
    [[ -d node_modules ]] || fail "www/default/node_modules is missing; install the dashboard dependencies first"
    if stale src build; then
        info "The dashboard bundle is stale, rebuilding it"
        GENERATE_SOURCEMAP=false npm run build >/dev/null
    else
        info "The dashboard bundle is up to date"
    fi
    grep -rqF "agent-card-tab" build/static/js || fail "the dashboard build has no Agent card tab; check the www/default sources"
    cd "${REPO_ROOT}" || fail "cannot enter ${REPO_ROOT}"
}

# write_login_file: signs in through the test-mode endpoint and stores a console snippet that sets the
# dashboard session. The token goes from curl into a mode 600 file and is never printed.
write_login_file() {
    local response_file
    make_tmp
    response_file="${TMP_DIR}/login-response"
    (umask 077; printf 'header = "X-Test-Token: %s"\n' "$(cat "$(secret_file test-token)")" \
        | curl -sS --connect-timeout 5 --max-time 20 -K - -X POST -H 'Content-Type: application/json' \
            -d '{"username": "oidc-demo", "role": "administrator"}' \
            "${GATEWAY_URL}/api/internal/test-support/auth/login" >"${response_file}") \
        || fail "test-mode login failed; is the gateway running with AG_TEST_MODE=true?"
    jq -e '.session_token' "${response_file}" >/dev/null || fail "the login response has no session token"
    (
        umask 077
        {
            printf 'Dashboard: %s\n' "${DASHBOARD_URL}"
            printf 'Signed in as oidc-demo (administrator). The session lasts %s seconds;\n' "$(jq -r '.expires_in_seconds // "an unknown number of"' "${response_file}")"
            printf 'make oidc-demo-browser ARGS=login issues a new one.\n\n'
            printf 'Open %s/dashboard, open the browser console and paste this one line:\n\n' "${GATEWAY_URL}"
            jq -r --arg url "${DASHBOARD_URL}" --arg q "'" \
                '"sessionStorage.setItem(" + $q + "session_token" + $q + ", " + $q + .session_token + $q + "); location.href = " + $q + $url + $q + ";"' "${response_file}"
        } >"${LOGIN_FILE}"
    )
    chmod 600 "${LOGIN_FILE}"
    rm -rf "${TMP_DIR}"
    TMP_DIR=""
}

print_summary() {
    cat <<SUMMARY

The Agent card demo is running in the background.
  Dashboard         ${DASHBOARD_URL}
  Dashboard login   ${LOGIN_FILE} (mode 600; paste its last line into the browser console)
  Served card       ${SERVED_CARD_URL}
                    curl --cacert ${GATEWAY_CA_FILE} ${SERVED_CARD_URL}
  Agent's own card  ${SOURCE_CARD_URL} (needs the gateway's token; the gateway fetches it for you)
  Break / fix       make oidc-demo-browser ARGS=break-card | fix-card, then Refresh in the tab
  Stop              make oidc-demo-browser ARGS=stop
SUMMARY
}

cmd_start() {
    require_tools docker curl jq openssl python3 node npm cargo lsof
    if gateway_up || agent_up || [[ -n "$(demo_containers)" ]]; then
        fail "the demo is already running; stop it first (make oidc-demo-browser ARGS=stop)"
    fi
    ensure_dashboard_build
    "${OIDC_DEMO_DIR}/up.sh"
    "${OIDC_DEMO_DIR}/gateway.sh" start --fresh
    "${OIDC_DEMO_DIR}/seed.sh"
    write_login_file
    print_summary
}

cmd_stop() {
    "${OIDC_DEMO_DIR}/down.sh"
    rm -f "${LOGIN_FILE}"
    local left
    left="$(demo_containers)"
    [[ -z "${left}" ]] || fail "containers still running: ${left}"
}

cmd_status() {
    local agent="stopped" gateway="stopped" refusing="n/a" containers
    if agent_up; then
        agent="running at ${AGENT_URL}"
        refusing="$(curl -fsS --connect-timeout 2 --max-time 4 "${AGENT_URL}/_demo/state" 2>/dev/null \
            | jq -r 'if .refuse then "yes (the card fetch fails with 401)" else "no" end' 2>/dev/null || echo unknown)"
    fi
    if gateway_up; then gateway="running at ${GATEWAY_URL} ($("${OIDC_DEMO_DIR}/gateway.sh" status))"; fi
    containers="$(demo_containers | tr '\n' ' ')"
    printf 'gateway      %s\nmock agent   %s\nagent refuses the gateway token: %s\ncontainers   %s\n' \
        "${gateway}" "${agent}" "${refusing}" "${containers:-none}"
    if [[ -f "${LOGIN_FILE}" ]]; then printf 'login file   %s\n' "${LOGIN_FILE}"; fi
    printf 'dashboard    %s\n' "${DASHBOARD_URL}"
}

set_refuse() {
    local want="$1" answer
    agent_up || fail "the mock agent is not running at ${AGENT_URL}; start the demo first"
    answer="$(curl -fsS --connect-timeout 5 --max-time 10 -X POST -H 'Content-Type: application/json' \
        -d "{\"refuse\": ${want}}" "${AGENT_URL}/_demo/refuse" | jq -r '.refuse')" || fail "the mock agent did not answer"
    [[ "${answer}" == "${want}" ]] || fail "the mock agent answered refuse=${answer}, expected ${want}"
}

cmd_login() {
    gateway_up || fail "the gateway is not running at ${GATEWAY_URL}; start the demo first"
    write_login_file
    info "Login file rewritten: ${LOGIN_FILE}"
}

case "${1:-}" in
    start) cmd_start ;;
    stop) cmd_stop ;;
    status) cmd_status ;;
    login) cmd_login ;;
    break-card)
        set_refuse true
        info "The mock agent now refuses the gateway's token. Press Refresh in the Agent card tab: the card fetch fails with 401 and no card is served." ;;
    fix-card)
        set_refuse false
        info "The mock agent checks tokens again. Press Refresh in the Agent card tab." ;;
    *) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
