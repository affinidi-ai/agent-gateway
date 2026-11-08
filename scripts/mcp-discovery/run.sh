#!/usr/bin/env bash
#
# MCP authorization server discovery against a real authorization server:
# Ory Hydra in Docker, a login and consent app, an MCP server, and the gateway
# with an MCP surface that publishes protected resource metadata naming Hydra.
# Runs the automated client check, and with --keep leaves everything running
# for a check with MCP Inspector. See scripts/mcp-discovery/README.md.
#
# Exit codes: 0 pass, 1 failure, 2 invalid options or precondition not met,
# 130 SIGINT, 143 SIGTERM.

set -euo pipefail
unset CDPATH

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
WORK="${REPO}/target/mcp-discovery"
LOGS="${WORK}/logs"
BIN_NAME="$(sed -n 's/^name = "\(.*\)"/\1/p' "${REPO}/Cargo.toml" | head -1)"
BINARY="${REPO}/target/debug/${BIN_NAME}"

HYDRA_IMAGE="oryd/hydra:v26.2.0"
HYDRA_CONTAINER="agent-gateway-mcp-discovery-hydra"
HYDRA_PUBLIC_PORT="${MCP_DISCOVERY_HYDRA_PUBLIC_PORT:-4444}"
HYDRA_ADMIN_PORT="${MCP_DISCOVERY_HYDRA_ADMIN_PORT:-4445}"
PORT_BASE="${MCP_DISCOVERY_PORT_BASE:-18643}"
GATEWAY_PORT=$((PORT_BASE))
LOGIN_PORT=$((PORT_BASE + 1))
MCP_PORT=$((PORT_BASE + 2))
CALLBACK_PORT=$((PORT_BASE + 3))
INSPECTOR_ORIGIN="${MCP_DISCOVERY_INSPECTOR_ORIGIN:-http://localhost:6274}"
CLIENT_ID="mcp-discovery-demo"
ISSUER="https://localhost:${HYDRA_PUBLIC_PORT}"
HYDRA_ADMIN="https://localhost:${HYDRA_ADMIN_PORT}"
RESOURCE="https://localhost:${GATEWAY_PORT}/demo/mcp"
CHECK_REDIRECT="http://127.0.0.1:${CALLBACK_PORT}/callback"

SKIP_BUILD=false
KEEP=false
STARTED_PIDS=()
HYDRA_STARTED=false

usage() {
    cat <<EOF
Usage: scripts/mcp-discovery/run.sh [options]

  --skip-build   Use the existing ${BINARY#"${REPO}"/}
  --keep         Leave everything running after the check, for MCP Inspector;
                 stop it with Ctrl-C
  -h, --help     Show this help

Needs Docker, Node.js 22 or later, and mkcert with its local CA installed
(mkcert -install), so the gateway, Node and the browser trust the certificate.

Environment:
  MCP_DISCOVERY_PORT_BASE         First of the four local ports (default 18643)
  MCP_DISCOVERY_HYDRA_PUBLIC_PORT Hydra public port (default 4444)
  MCP_DISCOVERY_HYDRA_ADMIN_PORT  Hydra admin port (default 4445)
  MCP_DISCOVERY_INSPECTOR_ORIGIN  Browser origin of MCP Inspector (default http://localhost:6274)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true ;;
        --keep) KEEP=true ;;
        -h | --help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

fail() {
    echo "FAIL  $2" >&2
    exit "$1"
}

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

wait_for() {
    local name="$1" url="$2" waited=0
    until curl -fsS -o /dev/null --max-time 2 "${url}" 2>/dev/null; do
        waited=$((waited + 1))
        [[ ${waited} -lt 60 ]] || fail 1 "${name} did not start (logs: ${LOGS#"${REPO}"/})"
        sleep 1
    done
}

start_process() {
    local log="$1"
    shift
    "$@" > "${log}" 2>&1 &
    STARTED_PIDS+=("$!")
}

cleanup() {
    local pid
    for pid in "${STARTED_PIDS[@]+"${STARTED_PIDS[@]}"}"; do
        kill "${pid}" 2>/dev/null || true
    done
    if [[ "${HYDRA_STARTED}" == true ]]; then
        docker logs "${HYDRA_CONTAINER}" > "${LOGS}/hydra.log" 2>&1 || true
        docker rm -f "${HYDRA_CONTAINER}" > /dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Preflight.
command -v docker > /dev/null || fail 2 "docker is required"
docker info > /dev/null 2>&1 || fail 2 "the Docker daemon is not running"
command -v node > /dev/null || fail 2 "Node.js 22 or later is required"
[[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 22 ]] || fail 2 "Node.js 22 or later is required"
command -v mkcert > /dev/null || fail 2 "mkcert is required (https://github.com/FiloSottile/mkcert)"
CA_ROOT="$(mkcert -CAROOT)"
[[ -f "${CA_ROOT}/rootCA.pem" ]] || fail 2 "run 'mkcert -install' first, so the local CA is trusted"
for port in "${HYDRA_PUBLIC_PORT}" "${HYDRA_ADMIN_PORT}" "${GATEWAY_PORT}" "${LOGIN_PORT}" "${MCP_PORT}"; do
    if port_open "${port}"; then
        fail 2 "port ${port} is in use"
    fi
done
export NODE_EXTRA_CA_CERTS="${CA_ROOT}/rootCA.pem"
export CURL_CA_BUNDLE="${CA_ROOT}/rootCA.pem"

rm -rf "${WORK}"
mkdir -p "${LOGS}" "${WORK}/certs"

# The official MCP client SDK, pinned by package-lock.json; no install scripts run.
(cd "${HERE}" && npm ci --ignore-scripts --no-audit --no-fund) > "${LOGS}/npm.log" 2>&1 ||
    fail 1 "npm ci failed (log: ${LOGS#"${REPO}"/}/npm.log)"

if [[ "${SKIP_BUILD}" == false ]]; then
    echo "Building the gateway..."
    (cd "${REPO}" && cargo build --bin "${BIN_NAME}") > "${LOGS}/build.log" 2>&1 ||
        fail 1 "gateway build failed (log: ${LOGS#"${REPO}"/}/build.log)"
fi
[[ -x "${BINARY}" ]] || fail 2 "no gateway binary at ${BINARY#"${REPO}"/}; run without --skip-build"

mkcert -cert-file "${WORK}/certs/cert.pem" -key-file "${WORK}/certs/key.pem" localhost 127.0.0.1 > /dev/null 2>&1 ||
    fail 1 "mkcert could not issue the localhost certificate"
# Hydra runs as a non-root user and reads the key through a read-only mount.
chmod 644 "${WORK}/certs/key.pem"

# Ory Hydra with JWT access tokens, TLS, and the login and consent app.
docker rm -f "${HYDRA_CONTAINER}" > /dev/null 2>&1 || true
docker run -d --name "${HYDRA_CONTAINER}" \
    -p "127.0.0.1:${HYDRA_PUBLIC_PORT}:4444" -p "127.0.0.1:${HYDRA_ADMIN_PORT}:4445" \
    -v "${WORK}/certs:/certs:ro" \
    -e DSN=memory \
    -e URLS_SELF_ISSUER="${ISSUER}" \
    -e URLS_LOGIN="http://localhost:${LOGIN_PORT}/login" \
    -e URLS_CONSENT="http://localhost:${LOGIN_PORT}/consent" \
    -e STRATEGIES_ACCESS_TOKEN=jwt \
    -e SECRETS_SYSTEM="$(openssl rand -hex 32)" \
    -e SERVE_TLS_ENABLED=true -e SERVE_TLS_CERT_PATH=/certs/cert.pem -e SERVE_TLS_KEY_PATH=/certs/key.pem \
    -e SERVE_PUBLIC_CORS_ENABLED=true \
    -e SERVE_PUBLIC_CORS_ALLOWED_ORIGINS="${INSPECTOR_ORIGIN}" \
    "${HYDRA_IMAGE}" serve all > /dev/null || fail 1 "could not start ${HYDRA_IMAGE}"
HYDRA_STARTED=true
wait_for "Hydra" "${ISSUER}/health/ready"
echo "PASS  Hydra started (${ISSUER})"

# A public client for MCP Inspector and for the check, allowed to receive
# tokens for the demo resource.
curl -fsS -o /dev/null -X POST "${HYDRA_ADMIN}/admin/clients" -H 'content-type: application/json' -d "{
  \"client_id\": \"${CLIENT_ID}\",
  \"client_name\": \"MCP discovery demo\",
  \"grant_types\": [\"authorization_code\"],
  \"response_types\": [\"code\"],
  \"token_endpoint_auth_method\": \"none\",
  \"scope\": \"tools\",
  \"audience\": [\"${RESOURCE}\"],
  \"redirect_uris\": [\"${CHECK_REDIRECT}\", \"${INSPECTOR_ORIGIN}/oauth/callback\", \"${INSPECTOR_ORIGIN}/oauth/callback/debug\"]
}" || fail 1 "could not register the Hydra client"
echo "PASS  Hydra client '${CLIENT_ID}' registered"

start_process "${LOGS}/login-consent.log" node "${HERE}/login-consent.mjs" --port "${LOGIN_PORT}" --hydra-admin "${HYDRA_ADMIN}"
start_process "${LOGS}/mcp-server.log" node "${HERE}/mcp-server.mjs" --port "${MCP_PORT}"
wait_for "the login and consent app" "http://127.0.0.1:${LOGIN_PORT}/health"
wait_for "the MCP server" "http://127.0.0.1:${MCP_PORT}/health"

node "${HERE}/env.mjs" --dir "${WORK}/env" --binary "${BINARY}" --gateway-port "${GATEWAY_PORT}" \
    --mcp-url "http://127.0.0.1:${MCP_PORT}/mcp" --issuer "${ISSUER}" --jwks-uri "${ISSUER}/.well-known/jwks.json" \
    --cert "${WORK}/certs/cert.pem" --key "${WORK}/certs/key.pem" --inspector-origin "${INSPECTOR_ORIGIN}" \
    > "${LOGS}/env.log" 2>&1 || fail 1 "could not write the gateway env (log: ${LOGS#"${REPO}"/}/env.log)"
(
    cd "${WORK}/env/config"
    export "$(cat "${WORK}/env/backup-key-var")=$(openssl rand -hex 32)"
    export RUST_LOG="${RUST_LOG:-info}"
    exec "${BINARY}" --config config.toml
) > "${LOGS}/gateway.log" 2>&1 &
STARTED_PIDS+=("$!")
wait_for "the gateway" "https://localhost:${GATEWAY_PORT}/.well-known/oauth-protected-resource/demo/mcp"
echo "PASS  gateway started (${RESOURCE})"
echo

STATUS=0
node "${HERE}/check.mjs" --resource "${RESOURCE}" --client-id "${CLIENT_ID}" --redirect-uri "${CHECK_REDIRECT}" \
    --gateway-log "${LOGS}/gateway.log" || STATUS=$?
echo
node "${HERE}/sdk-check.mjs" --resource "${RESOURCE}" --client-id "${CLIENT_ID}" --redirect-uri "${CHECK_REDIRECT}" ||
    STATUS=$?

if [[ "${KEEP}" == true ]]; then
    cat <<EOF

Everything is still running. Check with MCP Inspector in another terminal:

  NODE_EXTRA_CA_CERTS="${CA_ROOT}/rootCA.pem" npx @modelcontextprotocol/inspector@2.12.0

  Transport: Streamable HTTP    URL: ${RESOURCE}
  Authentication > OAuth client ID: ${CLIENT_ID}    Scope: tools

Sign in at the login page as demo-user (admitted) or any other name (refused
by the surface policy). Logs: ${LOGS#"${REPO}"/}. Press Ctrl-C to stop.
EOF
    wait
fi
exit "${STATUS}"
