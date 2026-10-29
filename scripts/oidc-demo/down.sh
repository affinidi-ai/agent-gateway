#!/usr/bin/env bash
#
# Stop what up.sh and gateway.sh started: the two Hydra containers, the mock agent and, unless
# --services-only is given, the gateway. The generated keys and secrets in envs/oidc-demo-run/ are
# kept; delete that directory to start from scratch.

set -euo pipefail
unset CDPATH
# shellcheck source=scripts/oidc-demo/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SERVICES_ONLY=false
[[ "${1:-}" != "--services-only" ]] || SERVICES_ONLY=true

if [[ "${SERVICES_ONLY}" != true ]]; then
    "${OIDC_DEMO_DIR}/gateway.sh" stop
fi

if command -v docker >/dev/null 2>&1; then
    docker rm -f "${HYDRA_A_NAME}" "${HYDRA_B_NAME}" >/dev/null 2>&1 || true
fi

pid_file="${STATE_DIR}/mock-agent.pid"
if [[ -f "${pid_file}" ]]; then
    pid="$(cat "${pid_file}")"
    if kill -0 "${pid}" 2>/dev/null && ps -p "${pid}" -o command= | grep -q mock_agent.py; then
        kill "${pid}" 2>/dev/null || true
    fi
    rm -f "${pid_file}"
fi
[[ "${SERVICES_ONLY}" == true ]] || echo "Demo services stopped."
