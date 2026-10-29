#!/usr/bin/env bash
#
# The whole demo in one command: start Hydra and the mock agent, start a native gateway, seed it
# and run the hop 2 checks. Everything is stopped afterwards unless OIDC_DEMO_KEEP=1, which leaves
# the stack running so the steps can be repeated by hand.
#
# Usage: scripts/oidc-demo/run.sh [--no-hop2]
#   --no-hop2   skip the JWT bearer provider: the mock agent needs no token and the hop 2 step is skipped

set -euo pipefail
unset CDPATH
# shellcheck source=scripts/oidc-demo/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

cleanup() {
    if [[ "${OIDC_DEMO_KEEP:-0}" == "1" ]]; then
        info "OIDC_DEMO_KEEP=1: leaving the stack running. Stop it with make oidc-demo-down."
    else
        "${OIDC_DEMO_DIR}/down.sh" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

"${OIDC_DEMO_DIR}/up.sh" "$@"
"${OIDC_DEMO_DIR}/gateway.sh" start --fresh
"${OIDC_DEMO_DIR}/seed.sh"
if [[ "$(hop2_mode)" == "on" ]]; then
    "${OIDC_DEMO_DIR}/hop2.sh"
else
    info "Hop 2 checks skipped: the harness was started with hop 2 off."
fi
