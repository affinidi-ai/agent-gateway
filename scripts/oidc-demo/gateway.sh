#!/usr/bin/env bash
#
# Start or stop the demo gateway. The gateway always runs natively (a debug cargo build); the
# test-mode login the seed script uses exists only in debug builds.
#
#   gateway.sh start [--fresh] [--no-strategies]   prepare the gateway env, start the gateway in the background
#   gateway.sh stop              stop it
#   gateway.sh status            print running or stopped
#
# --fresh wipes the gateway env first (tmp/local-oidc-demo, or OIDC_DEMO_GATEWAY_ENV_REL, which must resolve to a directory below tmp/), so the gateway starts with no
# stored configuration. --no-strategies leaves the two verification strategies out, for a run that creates them in the dashboard.
# Start also registers the surface route /mock-agent in gateway.json (routes are read at startup), makes
# the inbound HTTPS listener's external URL https://localhost:<https port> so the Access Point URL is https, and
# writes the two verification strategies (one per Hydra instance, authorization server
# metadata pinned) straight into the gateway's storage: the management API's save-time URL checks
# refuse the loopback JWKS and discovery URLs the local Hydra instances use. With OIDC_DEMO_IDP=auth0 only
# the hydra-b strategy is written; seed.sh creates the Auth0 one through the API.
#
# OIDC_DEMO_CACHE_REFRESH_SECS=<n> sets cache_refresh_interval_secs, so strategy files written into the gateway's
# storage while it runs are picked up within n seconds (the live UI tests seed a loopback Hydra this way).
#
# Demo-only seam: the gateway reads AG_TEST_MODE=true together with AG_BDD_OAUTH_ENDPOINT_ALLOWLIST
# (exact URLs) to accept the loopback http token endpoint of the local Hydra instances, and
# AG_BDD_EGRESS_ALLOWLIST (origins) to accept the loopback http mock agent as a Target that may
# receive a credential provider's token. Production
# URL rules refuse loopback hosts and non-https token endpoints, so this run proves the protocol
# flows, not production egress. Discovery and JWKS fetches need no seam: their egress policy admits
# loopback and http. See docs/development/OIDC_DEMO.md.

set -euo pipefail
unset CDPATH
# shellcheck source=scripts/oidc-demo/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

no_strategies=false
PID_FILE="${GATEWAY_ENV_DIR}/gateway.pid"
LOG_FILE="${GATEWAY_LOG_FILE}"
GATEWAY_BIN="${REPO_ROOT}/target/debug/agent-gateway"

gateway_running() {
    [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null \
        && ps -p "$(cat "${PID_FILE}")" -o command= | grep -q agent-gateway
}

stop_gateway() {
    if gateway_running; then
        local pid
        pid="$(cat "${PID_FILE}")"
        kill "${pid}" 2>/dev/null || true
        local i
        for ((i = 0; i < 20; i++)); do
            kill -0 "${pid}" 2>/dev/null || break
            sleep 0.25
        done
    fi
    rm -f "${PID_FILE}"
}

# The development certificate, pepper and backup key that make config-certs prepares. That target
# also adds the certificate to the macOS system trust store with sudo, which this harness never
# does, so the same files are generated here without that step.
ensure_local_keys() {
    local envs="${REPO_ROOT}/envs"
    mkdir -p "${envs}"
    local file
    for file in identity_hash_pepper backup_encryption_key; do
        if [[ ! -s "${envs}/${file}" ]]; then
            (umask 077; openssl rand -hex 32 >"${envs}/${file}")
        fi
    done
    if [[ ! -f "${envs}/certs/cert.pem" ]]; then
        (
            cd "${envs}" || exit 1
            mkdir -p config/certs
            "${REPO_ROOT}/scripts/certs/generate-cert.sh" >/dev/null
            rm -Rf certs && mv config/certs . && rm -Rf config
        )
    fi
}

wipe_gateway_env() {
    local tmp_root target
    tmp_root="$(cd "${REPO_ROOT}/tmp" && pwd -P)" || fail "cannot resolve ${REPO_ROOT}/tmp"
    target="$(cd "${GATEWAY_ENV_DIR}" && pwd -P)" || fail "cannot resolve ${GATEWAY_ENV_DIR}"
    case "${target}" in
        "${tmp_root}"/?*) rm -rf "${target}" ;;
        *) fail "refusing to wipe ${GATEWAY_ENV_DIR}: it is not below ${REPO_ROOT}/tmp" ;;
    esac
}

start_gateway() {
    local fresh=false arg
    for arg in "$@"; do
        case "${arg}" in
            --fresh) fresh=true ;;
            --no-strategies) no_strategies=true ;;
            *) fail "unknown option: ${arg}" ;;
        esac
    done
    require_tools curl openssl cargo
    cd "${REPO_ROOT}" || fail "cannot enter ${REPO_ROOT}"
    stop_gateway
    [[ "${fresh}" == true && -d "${GATEWAY_ENV_DIR}" ]] && wipe_gateway_env
    [[ -s "${STATE_DIR}/secrets/test-token" ]] || { new_secret test-token; }
    ensure_local_keys
    cargo build --bin agent-gateway
    ./scripts/_prepare.sh debug "${GATEWAY_ENV_REL}" --auto-accept >/dev/null
    # shellcheck disable=SC1091
    source "${GATEWAY_ENV_DIR}/instance.env"
    [[ "${HTTP_PORT}" == "${GATEWAY_HTTP_PORT}" ]] \
        || fail "the prepared gateway port is ${HTTP_PORT}, the harness expects ${GATEWAY_HTTP_PORT}; set OIDC_DEMO_GATEWAY_PORT"
    [[ "${HTTPS_PORT}" == "${GATEWAY_HTTPS_PORT}" ]] \
        || fail "the prepared gateway HTTPS port is ${HTTPS_PORT}, the harness expects ${GATEWAY_HTTPS_PORT}; set OIDC_DEMO_GATEWAY_HTTPS_PORT"
    local port
    for port in "${GATEWAY_HTTP_PORT}" "${GATEWAY_HTTPS_PORT}"; do
        if lsof -ti "tcp:${port}" -sTCP:LISTEN >/dev/null 2>&1; then
            fail "port ${port} is already in use"
        fi
    done

    if [[ -n "${OIDC_DEMO_CACHE_REFRESH_SECS:-}" ]]; then
        sed -i.bak "s/^cache_refresh_interval_secs = .*/cache_refresh_interval_secs = ${OIDC_DEMO_CACHE_REFRESH_SECS}/" "${GATEWAY_ENV_DIR}/config/config.toml"
        rm -f "${GATEWAY_ENV_DIR}/config/config.toml.bak"
    fi

    local gateway_json="${GATEWAY_ENV_DIR}/config/gateway.json"
    jq --arg route "${SURFACE_ROUTE}" 'if any(.channels[]; .prefix == $route) then . else .channels += [{id: "oidc-demo", name: "oidc-demo", prefix: $route}] end' \
        "${gateway_json}" >"${gateway_json}.tmp" && mv "${gateway_json}.tmp" "${gateway_json}"
    jq --arg origin "${ACCESS_POINT_ORIGIN}" '.listeners |= map(if .listener_type == "inbound" and .protocol == "https" then .external_urls = [$origin] else . end)' \
        "${gateway_json}" >"${gateway_json}.tmp" && mv "${gateway_json}.tmp" "${gateway_json}"

    local strategies="${GATEWAY_ENV_DIR}/_storage/jwt_verification_strategies" which id
    mkdir -p "${strategies}"
    for which in a b; do
        [[ "${no_strategies}" == false ]] || break
        [[ "${which}" == "b" ]] || ! auth0_mode || continue
        if [[ "${which}" == "a" ]]; then id="${STRATEGY_A_ID}"; else id="${STRATEGY_B_ID}"; fi
        strategy_record_json "${which}" >"${strategies}/${id}.json"
    done

    local allowlist
    allowlist="$(hydra_token_endpoint a),$(hydra_token_endpoint b)"
    if auth0_mode; then allowlist="$(hydra_token_endpoint b)"; fi
    local egress_allowlist="${AGENT_URL},${HYDRA_A_ISSUER%/},${HYDRA_B_ISSUER%/}"
    (
        cd "${GATEWAY_ENV_DIR}" || exit 1
        AG_TEST_MODE=true \
        AG_TEST_TOKEN="$(cat "$(secret_file test-token)")" \
        AG_TEST_ALLOW_ROLE_OVERRIDE=true \
        AG_BDD_OAUTH_ENDPOINT_ALLOWLIST="${allowlist}" \
        AG_BDD_EGRESS_ALLOWLIST="${egress_allowlist}" \
        AG_BACKUP_ENCRYPTION_KEY="$(cat "${REPO_ROOT}/envs/backup_encryption_key")" \
        AG_IDENTITY_HASH_PEPPER="$(cat "${REPO_ROOT}/envs/identity_hash_pepper")" \
        RUST_LOG="${RUST_LOG:-info}" \
        nohup "${GATEWAY_BIN}" --config config/config.toml >"${LOG_FILE}" 2>&1 &
        echo $! >"${PID_FILE}"
    )
    wait_http "${GATEWAY_URL}/api/v1/alive" "the gateway (log: ${LOG_FILE})" 120
    info "Gateway running at ${GATEWAY_URL} (pid $(cat "${PID_FILE}"), log ${LOG_FILE})"
}

case "${1:-}" in
    start) shift; start_gateway "$@" ;;
    stop) stop_gateway ;;
    status) if gateway_running; then echo "running (pid $(cat "${PID_FILE}"))"; else echo stopped; fi ;;
    *) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
