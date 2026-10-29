#!/usr/bin/env bash
#
# Live end-to-end UI tests for the OIDC/OAuth trust plane: a headless Chromium drives the real
# dashboard of a native gateway in test mode, in front of two Ory Hydra containers and the mock
# A2A agent. Nothing on the identity side is mocked.
#
# What it does:
#   1. builds the debug gateway (cargo, incremental) and the dashboard bundle only when stale;
#   2. picks free ports, starts hydra-a, hydra-b and the mock agent with the demo harness, and a
#      gateway with no stored configuration in tmp/oidc-ui-e2e;
#   3. runs ui-tests/playwright.oidc-live.config.ts, then fails the run if the results hold a
#      private key, a token or one of the run's secrets (report_secret_scan.py);
#   4. stops everything again, also when the run fails or is interrupted, and deletes the
#      run's keys, secrets and gateway storage, keeping only the results.
#
# Usage: scripts/oidc-demo/run-ui-e2e.sh [playwright arguments, for example a spec file or --grep]
# Environment:
#   OIDC_E2E_RESULT_DIR   where the Playwright report and artefacts go (default tmp/oidc-ui-e2e/results)
#   OIDC_E2E_SKIP_BUILD   1 skips the staleness checks and builds
#   OIDC_E2E_KEEP         1 leaves the stack up after the run, for debugging by hand
# The script prints no secret value. Secrets are typed into the dashboard through an evaluate call,
# so the Playwright report does not record them; traces, screenshots and videos are off.

set -euo pipefail
unset CDPATH
# shellcheck source=scripts/oidc-demo/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_tools docker curl jq openssl python3 node npm lsof

E2E_ROOT="${REPO_ROOT}/tmp/oidc-ui-e2e"

free_port() {
    python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

port_free() { ! lsof -ti "tcp:$1" -sTCP:LISTEN >/dev/null 2>&1; }

pick_gateway_offset() {
    local n
    for ((n = 500; n < 900; n++)); do
        if port_free $((8080 + n)) && port_free $((8443 + n)) && port_free $((9000 + n)) && port_free $((3002 + n)); then
            echo "${n}"
            return 0
        fi
    done
    fail "no free gateway port set found"
}

cleanup() {
    local code=$?
    set +e
    if [[ "${OIDC_E2E_KEEP:-0}" == "1" ]]; then
        echo "OIDC_E2E_KEEP=1: leaving the stack up. Stop it with: (source tmp/oidc-ui-e2e/stack.env && scripts/oidc-demo/down.sh)" >&2
        exit "${code}"
    fi
    "${OIDC_DEMO_DIR}/down.sh" >/dev/null 2>&1
    local left
    left="$(docker ps -a --filter "name=${OIDC_DEMO_NAME_PREFIX}-" --format '{{.Names}}' 2>/dev/null)"
    [[ -z "${left}" ]] || { docker rm -f ${left} >/dev/null 2>&1; echo "removed leftover containers: ${left}" >&2; }
    [[ -d "${E2E_ROOT}" ]] && find "${E2E_ROOT}" -mindepth 1 -maxdepth 1 ! -name results -exec rm -rf {} +
    exit "${code}"
}

stale() {
    local src_dir="$1" out_dir="$2" newest
    [[ -f "${out_dir}/index.html" ]] || return 0
    newest="$(find "${src_dir}" -type f -not -path '*/node_modules/*' -newer "${out_dir}/index.html" -print -quit)"
    [[ -n "${newest}" ]]
}

cd "${REPO_ROOT}"

if [[ "${OIDC_E2E_SKIP_BUILD:-0}" != "1" ]]; then
    info "Building the debug gateway (incremental)"
    cargo build --bin agent-gateway
    if stale www/default/src www/default/build; then
        info "Dashboard bundle is stale, rebuilding"
        (cd www/default && GENERATE_SOURCEMAP=false npm run build >/dev/null)
    else
        info "Dashboard bundle is up to date"
    fi
fi
[[ -d www/default/build ]] || fail "www/default/build is missing; run without OIDC_E2E_SKIP_BUILD"
[[ -d ui-tests/node_modules ]] || (cd ui-tests && npm ci --silent)

OFFSET="$(pick_gateway_offset)"
export OIDC_DEMO_NAME_PREFIX="oidc-ui-e2e-$$"
export OIDC_DEMO_STATE_DIR="${E2E_ROOT}/state"
export OIDC_DEMO_GATEWAY_ENV_REL="tmp/oidc-ui-e2e/local-${OFFSET}"
export OIDC_DEMO_GATEWAY_PORT=$((8080 + OFFSET))
export OIDC_DEMO_GATEWAY_HTTPS_PORT=$((8443 + OFFSET))
export OIDC_DEMO_HYDRA_A_PORT="$(free_port)"
export OIDC_DEMO_HYDRA_A_ADMIN_PORT="$(free_port)"
export OIDC_DEMO_HYDRA_B_PORT="$(free_port)"
export OIDC_DEMO_HYDRA_B_ADMIN_PORT="$(free_port)"
export OIDC_DEMO_AGENT_PORT="$(free_port)"
export OIDC_DEMO_CACHE_REFRESH_SECS=1
trap cleanup EXIT INT TERM

rm -rf "${E2E_ROOT:?}"
mkdir -p "${E2E_ROOT}"
# lib.sh was sourced before the overrides above; load the derived values again.
# shellcheck source=scripts/oidc-demo/lib.sh
source "${OIDC_DEMO_DIR}/lib.sh"

"${OIDC_DEMO_DIR}/up.sh"
"${OIDC_DEMO_DIR}/gateway.sh" start --fresh --no-strategies

RESULT_DIR="${OIDC_E2E_RESULT_DIR:-${E2E_ROOT}/results}"
mkdir -p "${RESULT_DIR}"

export AG_BASE_URL="${GATEWAY_URL}"
AG_TEST_TOKEN="$(cat "$(secret_file test-token)")"
export AG_TEST_TOKEN
export AG_TEST_MODE=true
export AG_TEST_ALLOW_ROLE_OVERRIDE=true
export AG_RESULT_DIR="${RESULT_DIR}"
export OIDC_E2E_HYDRA_A_ISSUER="${HYDRA_A_ISSUER}"
export OIDC_E2E_HYDRA_A_ADMIN="${HYDRA_A_ADMIN_URL}"
export OIDC_E2E_HYDRA_B_ISSUER="${HYDRA_B_ISSUER}"
export OIDC_E2E_HYDRA_B_ADMIN="${HYDRA_B_ADMIN_URL}"
export OIDC_E2E_HYDRA_B_CONTAINER="${HYDRA_B_NAME}"
export OIDC_E2E_AGENT_URL="${AGENT_URL}"
export OIDC_E2E_ACCESS_POINT_ORIGIN="${ACCESS_POINT_ORIGIN}"
export OIDC_E2E_GATEWAY_CA_FILE="${GATEWAY_CA_FILE}"
export OIDC_E2E_SURFACE_ROUTE="${SURFACE_ROUTE}"
export OIDC_E2E_GATEWAY_ENV_DIR="${GATEWAY_ENV_DIR}"
export OIDC_E2E_WORLD_FILE="${STATE_DIR}/world.json"

(
    umask 077
    env | grep -E '^(AG_BASE_URL|AG_TEST_TOKEN|AG_RESULT_DIR|OIDC_E2E_|OIDC_DEMO_)' | grep -v '^OIDC_E2E_KEEP=' | sed 's/^/export /' >"${E2E_ROOT}/stack.env"
)

cd ui-tests
mkdir -p test_results/.auth
code=0
npx playwright test --config playwright.oidc-live.config.ts "$@" || code=$?
python3 -I "${OIDC_DEMO_DIR}/report_secret_scan.py" "${RESULT_DIR}" "${OIDC_E2E_WORLD_FILE}" "${STATE_DIR}/secrets" || code=1
echo "HTML report: ${RESULT_DIR}/html (npx playwright show-report ${RESULT_DIR}/html)"
exit "${code}"
