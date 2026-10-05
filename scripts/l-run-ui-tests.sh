#!/bin/bash
#
# Run the Playwright UI test suite against a freshly started local gateway.
#
# Steps:
#   1. Prepare the debug env (calls scripts/_prepare.sh, which also
#      self-heals the dashboard static path to ${WWW_DIR}/build). The default
#      env tmp/local-ui-tests is wiped first and kept after the run for
#      debugging, gateway.log included; its ports are HTTP 8711, HTTPS 9074,
#      OUTBOUND 9631.
#   2. Ensure the debug gateway binary is built.
#   3. Ensure the React dashboard bundle is built and up-to-date. The
#      Playwright global-setup also checks freshness, but rebuilding here
#      keeps a single rebuild path and avoids a noisy nested make call.
#   4. Free the env's ports if a previous run is still bound to them.
#   5. Start the gateway with AG_TEST_MODE=true, wait until /dashboard
#      answers, run the suite, and kill the gateway on exit (success or
#      failure).
#
# Env overrides:
#   AG_BASE_URL    default http://localhost:<HTTP_PORT>
#   AG_TEST_TOKEN  default ui-test-token-32-plus-characters
#   AG_HTTP_PORT   default the env's HTTP_PORT
#   AG_SKIP_BUILD  if "true", skip cargo and UI builds (assume current)
#   AG_ENV_DIR     use this env dir and its ports instead; never wiped

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

TEST_TOKEN="${AG_TEST_TOKEN:-ui-test-token-32-plus-characters}"
GATEWAY_BIN="${REPO_ROOT}/target/debug/agent-gateway"
GATEWAY_LOG="/tmp/ag-ui-tests.log"
if [[ -n "${AG_ENV_DIR:-}" ]]; then
    ENV_DIR="${AG_ENV_DIR}"
else
    ENV_DIR="tmp/local-ui-tests"
    GATEWAY_LOG="${REPO_ROOT}/${ENV_DIR}/gateway.log"
    rm -rf "${REPO_ROOT:?}/${ENV_DIR}"
fi
BACKUP_KEY_FILE="${AG_BACKUP_KEY_FILE:-${REPO_ROOT}/envs/backup_encryption_key}"
PEPPER_FILE="${AG_IDENTITY_PEPPER_FILE:-${REPO_ROOT}/envs/identity_hash_pepper}"
AG_BACKUP_ENCRYPTION_KEY="${AG_BACKUP_ENCRYPTION_KEY:-}"
AG_IDENTITY_HASH_PEPPER="${AG_IDENTITY_HASH_PEPPER:-}"

if [[ -z "${AG_BACKUP_ENCRYPTION_KEY}" && -f "${BACKUP_KEY_FILE}" ]]; then
    AG_BACKUP_ENCRYPTION_KEY="$(< "${BACKUP_KEY_FILE}")"
fi

if [[ -z "${AG_IDENTITY_HASH_PEPPER}" && -f "${PEPPER_FILE}" ]]; then
    AG_IDENTITY_HASH_PEPPER="$(< "${PEPPER_FILE}")"
fi

if [[ -z "${AG_BACKUP_ENCRYPTION_KEY}" ]]; then
    echo "❌ Backup encryption key not found; run 'make config-certs' first"
    exit 1
fi

GATEWAY_PID=""
cleanup() {
    if [[ -n "${GATEWAY_PID}" ]] && kill -0 "${GATEWAY_PID}" 2>/dev/null; then
        echo "🧹 Stopping gateway (pid ${GATEWAY_PID})..."
        kill "${GATEWAY_PID}" 2>/dev/null || true
        wait "${GATEWAY_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# 1. Config
if [[ ! -f "${ENV_DIR}/config/config.toml" || ! -f "${ENV_DIR}/config/gateway.json" ]]; then
    echo "📦 First-time env setup..."
    if [[ "${AG_SKIP_BUILD:-false}" != "true" ]]; then
        cargo build --bin agent-gateway
    fi
fi
if ! prepare_output="$(./scripts/_prepare.sh debug "${ENV_DIR}" --auto-accept)"; then
    echo "❌ scripts/_prepare.sh failed for ${ENV_DIR}:"
    echo "${prepare_output}"
    exit 1
fi

# Source the ports assigned by _prepare.sh
source "${ENV_DIR}/instance.env"
HTTP_PORT="${AG_HTTP_PORT:-${HTTP_PORT}}"
BASE_URL="${AG_BASE_URL:-http://localhost:${HTTP_PORT}}"

# 2. Gateway binary
if [[ "${AG_SKIP_BUILD:-false}" != "true" && ! -x "${GATEWAY_BIN}" ]]; then
    echo "🔨 Building debug gateway..."
    cargo build --bin agent-gateway
fi

# 3. UI bundle (Playwright global-setup also checks; this keeps logs tidy)
if [[ "${AG_SKIP_BUILD:-false}" != "true" ]]; then
    src_mtime=$(find ${WWW_DIR:-www/default}/src -type f -not -path '*/node_modules/*' -exec stat -f %m {} + 2>/dev/null | sort -nr | head -1 || echo 0)
    build_mtime=$(find ${WWW_DIR:-www/default}/build -type f -exec stat -f %m {} + 2>/dev/null | sort -nr | head -1 || echo 0)
    if [[ -z "${build_mtime}" || "${src_mtime}" -gt "${build_mtime:-0}" ]]; then
        echo "🛠️  UI bundle stale, running make www-rebuild..."
        make www-rebuild >/dev/null
    fi
fi

# 4. Free test ports from a previous crashed run
for p in "${HTTP_PORT}" "${HTTPS_PORT}" "${OUTBOUND_PORT}"; do
    if existing=$(lsof -ti:"${p}" 2>/dev/null); then
        if [[ -n "${existing}" ]]; then
            echo "⚠️  Port ${p} in use by pid(s) ${existing} — killing..."
            echo "${existing}" | xargs kill -9 2>/dev/null || true
        fi
    fi
done
sleep 0.5

# 5. Start gateway, wait for readiness
echo "🚀 Starting gateway in test mode (logs: ${GATEWAY_LOG})..."
(
    cd "${ENV_DIR}"
    AG_TEST_MODE=true \
    AG_TEST_TOKEN="${TEST_TOKEN}" \
    AG_TEST_ALLOW_ROLE_OVERRIDE=true \
    AG_BACKUP_ENCRYPTION_KEY="${AG_BACKUP_ENCRYPTION_KEY}" \
    AG_IDENTITY_HASH_PEPPER="${AG_IDENTITY_HASH_PEPPER}" \
    RUST_LOG="${RUST_LOG:-warn}" \
    "${GATEWAY_BIN}" --config config/config.toml \
        > "${GATEWAY_LOG}" 2>&1 &
    echo $! > /tmp/ag-ui-tests.pid
)
GATEWAY_PID=$(cat /tmp/ag-ui-tests.pid)

ready=0
for _ in $(seq 1 30); do
    if curl -fsS -o /dev/null "${BASE_URL}/dashboard" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.5
done
if [[ "${ready}" -ne 1 ]]; then
    echo "❌ Gateway did not become ready on ${BASE_URL}. Last log lines:"
    tail -30 "${GATEWAY_LOG}" || true
    exit 1
fi
echo "✅ Gateway ready"

# 6. Run Playwright
cd ui-tests
[[ -d node_modules ]] || npm install --silent
npx playwright install chromium --with-deps >/dev/null 2>&1 || true
rm -rf test_results/.auth test_results/latest

# Pin a single result directory for the whole run so workers don't each
# create their own timestamped folder.
AG_RESULT_DIR="./test_results/result_$(date +%Y%m%d_%H%M%S)"
export AG_RESULT_DIR

test_exit=0
AG_BASE_URL="${BASE_URL}" \
AG_ENV_DIR="${ENV_DIR}" \
AG_TEST_MODE=true \
AG_TEST_TOKEN="${TEST_TOKEN}" \
AG_TEST_ALLOW_ROLE_OVERRIDE=true \
AG_SKIP_UI_BUILD=true \
npm run test:ui || test_exit=$?

if [[ "${test_exit}" -ne 0 ]] && [[ "${CI:-false}" != "true" ]]; then
    npx playwright show-report "${AG_RESULT_DIR}/html" >/dev/null 2>&1 &
    disown $!
    echo "📊 UI test report: http://localhost:9323 (background, run 'make ui-test-report' to reopen)"
fi

exit "${test_exit}"
