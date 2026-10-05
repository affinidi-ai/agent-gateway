#!/bin/bash

# Run the gateway in debug mode with a frontend dev server.
# Usage:
#   ./scripts/l-run-debug.sh [instance_suffix]
# instance_suffix: named instance suffix (e.g. 1, my-tests) → uses envs/local-<suffix>
# Defaults to www/default if WWW_DIR is not set.

# set -x
set -e

source "$(dirname "$0")/_env.sh"
source "$(dirname "$0")/_run-common.sh"

www_dir="${WWW_DIR:-www/default}"
resolve_target_dir "${1:-}"
: "${target_dir:?resolve_target_dir must set target_dir}"

repo_dir=$(pwd)
ln -sf "${repo_dir}/${www_dir}/build" "${target_dir}/www" 2>/dev/null || true

export RUST_LOG="${RUST_LOG:-debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

source_ports
: "${https_port:?source_ports must set https_port}"
: "${ui_port:?source_ports must set ui_port}"

echo "🔧 Running in DEBUG mode (${www_dir})"
echo "Backend:  debug binary → https://localhost:${https_port}"
echo "Frontend: dev server with hot reload → http://localhost:${ui_port}"
echo "Proxy:    /api/** → ${VITE_BACKEND_URL}"
echo ""

cd "${target_dir}"
"${repo_dir}/target/debug/agent-gateway" --config config/config.toml &
BACKEND_PID=$!

cleanup() {
    printf "\n🛑 Shutting down...\n"
    kill "${WATCHER_PID}" 2>/dev/null || true
    kill -9 "${NPM_PID}" 2>/dev/null || true
    while IFS= read -r child_pid; do
        [[ -n "${child_pid}" ]] && kill -9 "${child_pid}" 2>/dev/null || true
    done < <(pgrep -P "${NPM_PID}" 2>/dev/null || true)
    lsof -ti :"${ui_port}" | xargs kill -9 2>/dev/null || true
    kill "${BACKEND_PID}" 2>/dev/null || true
    wait "${BACKEND_PID}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

start_frontend "${BACKEND_PID}"

(while kill -0 "${BACKEND_PID}" 2>/dev/null; do sleep 1; done; printf "\n🔄 Backend exited — shutting down frontend...\n"; kill "$$" 2>/dev/null) &
WATCHER_PID=$!

wait "${NPM_PID}"
