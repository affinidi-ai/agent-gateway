#!/usr/bin/env bash
#
# The demo with a live Auth0 tenant as the caller's authorization server: hydra-b and the mock agent
# for the gateway to agent hop, a native debug gateway, a seed through the management API and the
# Auth0 walkthrough. Everything is stopped afterwards unless OIDC_DEMO_KEEP=1. Output passes through a
# filter that masks every value of the Auth0 values file and every token, and down.sh masks the gateway's
# log files once the gateway has stopped; auth0_scan.py then checks gateway.log for secret material.
# With OIDC_DEMO_KEEP=1 the log files stay unmasked until make oidc-demo-down.
#
# Needs envs/oidc-demo/auth0.env (OIDC_DEMO_AUTH0_ENV names another file), whose API identifier must
# equal the Access Point URL; see docs/development/OIDC_DEMO.md.
# Token requests to a free tenant are counted: the walkthrough makes two per run.
#
# Usage: scripts/oidc-demo/auth0.sh

set -euo pipefail
unset CDPATH
export OIDC_DEMO_IDP=auth0
# shellcheck source=scripts/oidc-demo/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

auth0_load

cleanup() {
    local status=$?
    if [[ "${OIDC_DEMO_KEEP:-0}" == "1" ]]; then
        info "OIDC_DEMO_KEEP=1: leaving the stack running. Stop it with make oidc-demo-down."
        return
    fi
    "${OIDC_DEMO_DIR}/down.sh" >/dev/null 2>&1 || true
    if [[ -f "${GATEWAY_LOG_FILE}" ]]; then
        python3 -I "${OIDC_DEMO_DIR}/auth0_scan.py" "${AUTH0_ENV_FILE}" "${GATEWAY_LOG_FILE}" || status=1
    fi
    exit "${status}"
}
trap cleanup EXIT

{
    "${OIDC_DEMO_DIR}/up.sh"
    "${OIDC_DEMO_DIR}/gateway.sh" start --fresh
    "${OIDC_DEMO_DIR}/seed.sh"
    "${OIDC_DEMO_DIR}/walkthrough-auth0.sh"
} 2>&1 | auth0_redact
