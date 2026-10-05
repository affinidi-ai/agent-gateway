#!/bin/bash

# Run the gateway in watch mode.
# cargo watch rebuilds and restarts the backend on Rust source changes.
# The npm dev server already has hot-reload for frontend changes.
# Usage:
#   ./scripts/l-run-watch.sh [instance_suffix]
# instance_suffix: named instance suffix (e.g. 1, my-tests) → uses envs/local-<suffix>
# Defaults to www/default if WWW_DIR is not set.

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

echo "🔧 Running in WATCH mode (${www_dir})"
echo "Backend:  cargo watch → https://localhost:${https_port}"
echo "Frontend: dev server with hot reload → http://localhost:${ui_port}"
echo "Proxy:    /api/** → ${VITE_BACKEND_URL}"
echo ""

PID_FILE="${target_dir}/.backend.pid"

cleanup() {
    printf "\n🛑 Shutting down...\n"
    kill "${CARGO_WATCH_PID}" 2>/dev/null || true
    kill "${WATCHER_PID}" 2>/dev/null || true
    kill -9 "${NPM_PID}" 2>/dev/null || true
    while IFS= read -r child_pid; do
        [[ -n "${child_pid}" ]] && kill -9 "${child_pid}" 2>/dev/null || true
    done < <(pgrep -P "${NPM_PID}" 2>/dev/null || true)
    lsof -ti :"${ui_port}" | xargs kill -9 2>/dev/null || true
    if [[ -f "${PID_FILE}" ]]; then
        kill "$(cat "${PID_FILE}")" 2>/dev/null || true
        rm -f "${PID_FILE}"
    fi
}
trap cleanup EXIT INT TERM

cd "${repo_dir}"
export PID_FILE target_dir repo_dir
cargo watch -w src -s 'cargo build --bin agent-gateway 2>&1 || exit 1
  echo "Restarting backend..."
  if [ -f "$PID_FILE" ]; then kill "$(cat "$PID_FILE")" 2>/dev/null || true; sleep 0.5; fi
  cd "$target_dir" && "$repo_dir/target/debug/agent-gateway" --config config/config.toml &
  echo $! > "$PID_FILE"
  echo "Backend restarted"' &
CARGO_WATCH_PID=$!

# Start binary immediately if it exists from a previous build; otherwise cargo-watch
# will build and start it on its first cycle.
if [[ -f "${repo_dir}/target/debug/agent-gateway" ]]; then
  cd "${target_dir}"
  "${repo_dir}/target/debug/agent-gateway" --config config/config.toml &
  echo "$!" > "${PID_FILE}"
fi

start_frontend "${CARGO_WATCH_PID}"

(while kill -0 "${CARGO_WATCH_PID}" 2>/dev/null; do sleep 1; done; printf "\n🔄 cargo watch exited — shutting down...\n"; kill "$$" 2>/dev/null) &
WATCHER_PID=$!

wait "${NPM_PID}"
