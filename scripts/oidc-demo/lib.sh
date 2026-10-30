# shellcheck shell=bash
# shellcheck disable=SC2034
# Shared settings and helpers for the OIDC demo harness. Sourced by the other scripts.
#
# Everything here runs on the host with bash 3.2+, curl, jq, openssl and python3
# (standard library). The only container image is the pinned Ory Hydra image.

OIDC_DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${OIDC_DEMO_DIR}/../.." && pwd)"

HYDRA_IMAGE="${OIDC_DEMO_HYDRA_IMAGE:-oryd/hydra:v26.2.0}"
NAME_PREFIX="${OIDC_DEMO_NAME_PREFIX:-oidc-demo}"
HYDRA_A_NAME="${NAME_PREFIX}-hydra-a"
HYDRA_B_NAME="${NAME_PREFIX}-hydra-b"
HYDRA_A_PUBLIC="${OIDC_DEMO_HYDRA_A_PORT:-14444}"
HYDRA_A_ADMIN="${OIDC_DEMO_HYDRA_A_ADMIN_PORT:-14445}"
HYDRA_B_PUBLIC="${OIDC_DEMO_HYDRA_B_PORT:-14454}"
HYDRA_B_ADMIN="${OIDC_DEMO_HYDRA_B_ADMIN_PORT:-14455}"
AGENT_PORT="${OIDC_DEMO_AGENT_PORT:-19201}"

HYDRA_A_ISSUER="http://127.0.0.1:${HYDRA_A_PUBLIC}/"
HYDRA_B_ISSUER="http://127.0.0.1:${HYDRA_B_PUBLIC}/"
HYDRA_A_ADMIN_URL="http://127.0.0.1:${HYDRA_A_ADMIN}"
HYDRA_B_ADMIN_URL="http://127.0.0.1:${HYDRA_B_ADMIN}"
AGENT_URL="http://127.0.0.1:${AGENT_PORT}"

STATE_DIR="${OIDC_DEMO_STATE_DIR:-${REPO_ROOT}/envs/oidc-demo-run}"
SECRETS_DIR="${STATE_DIR}/secrets"
GATEWAY_ENV_REL="${OIDC_DEMO_GATEWAY_ENV_REL:-tmp/local-oidc-demo}"
GATEWAY_ENV_DIR="${REPO_ROOT}/${GATEWAY_ENV_REL}"
GATEWAY_LOG_FILE="${GATEWAY_ENV_DIR}/gateway.log"

# Same formula as scripts/_prepare.sh (assign_ports) for the env named local-oidc-demo.
_gateway_offset() {
    local hash
    hash="$(printf '%s' "oidc-demo" | cksum | awk '{print $1}')"
    echo $((100 + hash % 900))
}
GATEWAY_HTTP_PORT="${OIDC_DEMO_GATEWAY_PORT:-$((8080 + $(_gateway_offset)))}"
GATEWAY_URL="http://localhost:${GATEWAY_HTTP_PORT}"
# The Access Point lives on the gateway's HTTPS listener: it publishes authorization server
# discovery only at a canonical https URL. Clients trust the listener's development
# certificate through --cacert.
GATEWAY_HTTPS_PORT="${OIDC_DEMO_GATEWAY_HTTPS_PORT:-$((8443 + $(_gateway_offset)))}"
ACCESS_POINT_ORIGIN="https://localhost:${GATEWAY_HTTPS_PORT}"
GATEWAY_CA_FILE="${GATEWAY_ENV_DIR}/certs/cert.pem"
SURFACE_ROUTE="/mock-agent"
AP_URL="${ACCESS_POINT_ORIGIN}${SURFACE_ROUTE}"
PRM_URL="${ACCESS_POINT_ORIGIN}/.well-known/oauth-protected-resource${SURFACE_ROUTE}"
OTHER_AUDIENCE="https://other.example/resource"
NOSCOPE_CLIENT="demo-noscope"
OTHERAUD_CLIENT="demo-otheraud"

REQUIRED_SCOPE="agent.read"
HOP2_SCOPE="agent.invoke"
HOP2_CLIENT="gateway-hop2"
HOP2_ISSUER="agent-gateway-demo"
HOP2_SUBJECT="agent-gateway"

SURFACE_ID="oidc-demo-surface"
STRATEGY_A_ID="oidc-demo-hydra-a"
STRATEGY_B_ID="oidc-demo-hydra-b"
POLICY_ID="oidc-demo-deny-failed-callers"

hop2_mode() {
    if [[ -f "${STATE_DIR}/hop2" ]]; then cat "${STATE_DIR}/hop2"; else echo "${OIDC_DEMO_HOP2:-on}"; fi
}

if [[ -t 1 ]]; then
    C_BOLD=$'\033[1m'; C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
    C_BOLD=""; C_GREEN=""; C_RED=""; C_DIM=""; C_OFF=""
fi

fail() {
    printf '%sFAIL%s %s\n' "${C_RED}" "${C_OFF}" "$*" >&2
    exit 1
}

info() { printf '%s\n' "$*"; }

STEP_NO=0
step() {
    STEP_NO=$((STEP_NO + 1))
    printf '\n%s== %s. %s%s\n' "${C_BOLD}" "${STEP_NO}" "$*" "${C_OFF}"
}

pass() { printf '%sPASS%s %s\n' "${C_GREEN}" "${C_OFF}" "$*"; }

require_tools() {
    local tool
    for tool in "$@"; do
        command -v "${tool}" >/dev/null 2>&1 || fail "${tool} is required"
    done
}

assert_eq() {
    local what="$1" want="$2" got="$3"
    [[ "${want}" == "${got}" ]] || fail "${what}: expected '${want}', got '${got}'"
    pass "${what}: ${got}"
}

assert_json() {
    local what="$1" filter="$2" file="$3"
    jq -e "${filter}" "${file}" >/dev/null 2>&1 || {
        printf 'filter: %s\n' "${filter}" >&2
        jq -c . "${file}" >&2 2>/dev/null || cat "${file}" >&2
        fail "${what}"
    }
    pass "${what}"
}

TMP_DIR=""
make_tmp() {
    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/oidc-demo.XXXXXX")"
    chmod 700 "${TMP_DIR}"
}

# bearer_header_file NAME TOKEN: writes "Authorization: Bearer TOKEN" to the mode 600 file TMP_DIR/NAME,
# for curl -H @file, and prints its path. Needs make_tmp first.
bearer_header_file() {
    [[ -n "${TMP_DIR}" ]] || fail "bearer_header_file needs make_tmp first"
    local path="${TMP_DIR}/$1"
    (umask 077; printf 'Authorization: Bearer %s\n' "$2" >"${path}")
    printf '%s' "${path}"
}

RESP_CODE=""
RESP_BODY=""
RESP_HEADERS=""

# req METHOD URL [curl args...]: runs curl, sets RESP_CODE, RESP_BODY and RESP_HEADERS (files).
# An Authorization header never reaches a command line: it is written to a mode 600 file under TMP_DIR and
# curl reads it with -H @file. The printed transcript masks its value.
req() {
    local method="$1" url="$2"
    shift 2
    [[ -n "${TMP_DIR}" ]] || make_tmp
    RESP_BODY="${TMP_DIR}/body"
    RESP_HEADERS="${TMP_DIR}/headers"
    local printed="" arg n=0 header_file
    local -a args=()
    for arg in "$@"; do
        case "${arg}" in
            Authorization:*)
                n=$((n + 1))
                header_file="${TMP_DIR}/request-header-${n}"
                (umask 077; printf '%s\n' "${arg}" >"${header_file}")
                args+=("@${header_file}")
                printed="${printed% -H} -H 'Authorization: Bearer <redacted>'"
                ;;
            *)
                args+=("${arg}")
                printed="${printed} ${arg}"
                ;;
        esac
    done
    printf '%s$ curl -X %s %s%s%s\n' "${C_DIM}" "${method}" "${url}" "${printed}" "${C_OFF}"
    RESP_CODE="$(curl -sS --connect-timeout 5 --max-time 30 -X "${method}" -o "${RESP_BODY}" -D "${RESP_HEADERS}" -w '%{http_code}' --cacert "${GATEWAY_CA_FILE}" ${args[@]+"${args[@]}"} "${url}")" \
        || fail "curl failed for ${method} ${url}"
    printf '%s< HTTP %s%s\n' "${C_DIM}" "${RESP_CODE}" "${C_OFF}"
}

# header_value NAME: the first value of response header NAME (any case) of the last req call.
header_value() {
    local name="$1"
    tr -d '\r' <"${RESP_HEADERS}" | awk -F': ' -v n="$(printf '%s' "${name}" | tr '[:upper:]' '[:lower:]')" \
        'tolower($1) == n { sub(/^[^:]*: /, ""); print; exit }'
}

show_body() {
    if jq -e . "${RESP_BODY}" >/dev/null 2>&1; then jq -c . "${RESP_BODY}" | cut -c1-400; else head -c 400 "${RESP_BODY}"; echo; fi
}

wait_http() {
    local url="$1" label="$2" tries="${3:-60}" i
    for ((i = 0; i < tries; i++)); do
        if curl -fsS -o /dev/null --connect-timeout 2 --max-time 4 "${url}" 2>/dev/null; then return 0; fi
        sleep 0.5
    done
    fail "${label} did not become ready at ${url}"
}

# secret_file NAME: path of a generated secret under the state directory.
secret_file() { printf '%s/%s' "${SECRETS_DIR}" "$1"; }

# new_secret NAME: writes a random 32-hex-character secret (mode 600) unless it exists.
new_secret() {
    local path
    path="$(secret_file "$1")"
    if [[ ! -s "${path}" ]]; then
        (umask 077; mkdir -p "${SECRETS_DIR}"; openssl rand -hex 16 >"${path}")
    fi
}

hydra_public() { if [[ "$1" == "a" ]]; then echo "${HYDRA_A_PUBLIC}"; else echo "${HYDRA_B_PUBLIC}"; fi; }
hydra_admin_url() { if [[ "$1" == "a" ]]; then echo "${HYDRA_A_ADMIN_URL}"; else echo "${HYDRA_B_ADMIN_URL}"; fi; }
hydra_issuer() { if [[ "$1" == "a" ]]; then echo "${HYDRA_A_ISSUER}"; else echo "${HYDRA_B_ISSUER}"; fi; }
hydra_token_endpoint() { echo "$(hydra_issuer "$1")oauth2/token"; }

# fetch_token WHICH CLIENT [AUDIENCE] [SCOPE]: client_credentials grant; prints only the access token.
# The client secret reaches curl as a config on standard input, never in a command line.
fetch_token() {
    local which="$1" client="$2" audience="${3:-}" scope="${4:-}" out
    local -a args=(-sS --connect-timeout 5 --max-time 20 -K - -d grant_type=client_credentials)
    [[ -z "${audience}" ]] || args+=(--data-urlencode "audience=${audience}")
    [[ -z "${scope}" ]] || args+=(--data-urlencode "scope=${scope}")
    out="$(printf 'user = "%s:%s"\n' "${client}" "$(cat "$(secret_file "${which}-${client}.secret")")" \
        | curl "${args[@]}" "$(hydra_token_endpoint "${which}")")" || return 1
    printf '%s' "${out}" | jq -er '.access_token'
}

# jwt_claims TOKEN: the payload claims as JSON. The token reaches the helper on standard input.
jwt_claims() { printf '%s' "$1" | python3 -I "${OIDC_DEMO_DIR}/jwt_tools.py" decode -; }

# caller_auth_method_json STRATEGY_ID: the Access Point's jwt_bearer method for this demo.
caller_auth_method_json() {
    jq -n --arg sid "$1" --arg scope "${REQUIRED_SCOPE}" \
        '{type: "jwt_bearer", jwt_verification_strategy_id: $sid, audiences: [], required_scopes: [$scope]}'
}

# caller_protected_resource_json: the Access Point's authorization server discovery for this demo: its resource
# is the Access Point URL; the authorization server and scopes come from the strategy and required_scopes.
caller_protected_resource_json() { jq -n --arg ap "${AP_URL}" '{resource: $ap}'; }

# gateway_session: logs in through the test-mode endpoint and sets SESSION_TOKEN and SESSION_HEADER_FILE (a
# mode 600 file under TMP_DIR holding the Authorization header, for curl -H @file). Needs make_tmp first.
gateway_session() {
    local token body
    [[ -n "${TMP_DIR}" ]] || fail "gateway_session needs make_tmp first"
    token="$(cat "$(secret_file test-token)")"
    body="$(jq -n '{username: "oidc-demo", role: "administrator"}')"
    SESSION_TOKEN="$(printf 'header = "X-Test-Token: %s"\n' "${token}" \
        | curl -sS --connect-timeout 5 --max-time 20 -K - -X POST -H 'Content-Type: application/json' \
            -d "${body}" "${GATEWAY_URL}/api/internal/test-support/auth/login" | jq -er '.session_token')" \
        || fail "test-mode login failed; is the gateway running with AG_TEST_MODE=true (scripts/oidc-demo/gateway.sh start)?"
    SESSION_HEADER_FILE="$(bearer_header_file session-header "${SESSION_TOKEN}")"
}

# strategy_record_json WHICH: the stored JWT verification strategy for a Hydra instance, with the
# authorization server metadata already pinned. Written straight to storage by gateway.sh because
# the save-time URL checks refuse loopback jwks and discovery URLs, which is where the demo's Hydra
# instances live.
strategy_record_json() {
    local which="$1" id name issuer now
    if [[ "${which}" == "a" ]]; then id="${STRATEGY_A_ID}"; else id="${STRATEGY_B_ID}"; fi
    name="oidc-demo hydra-${which}"
    issuer="$(hydra_issuer "${which}")"
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    jq -n --arg id "${id}" --arg name "${name}" --arg iss "${issuer}" --arg now "${now}" '{
        id: $id, name: $name, expected_issuer: $iss,
        jwks_source: {type: "remote", jwks_uri: ($iss + ".well-known/jwks.json")},
        authorization_server: {issuer: $iss,
                               metadata_url: ($iss + ".well-known/oauth-authorization-server"),
                               token_endpoint: ($iss + "oauth2/token"),
                               jwks_uri: ($iss + ".well-known/jwks.json")},
        created_at: $now, updated_at: $now}'
}

# Auth0 mode (OIDC_DEMO_IDP=auth0): the caller's authorization server is a live Auth0 tenant.
# The tenant values come from a gitignored file that only auth0_tool.py and auth0_scan.py read; see OIDC_DEMO.md.
AUTH0_ENV_FILE="${OIDC_DEMO_AUTH0_ENV:-${REPO_ROOT}/envs/oidc-demo/auth0.env}"
AUTH0_SCOPE="agent:invoke"
AUTH0_STRATEGY_NAME="oidc-demo auth0"
AUTH0_REQUIRED_SCOPE="${AUTH0_SCOPE}"

auth0_mode() { [[ "${OIDC_DEMO_IDP:-}" == "auth0" ]]; }

auth0_tool() { python3 -I "${OIDC_DEMO_DIR}/auth0_tool.py" "$@"; }

# auth0_load: checks the values file and sets AUTH0_DOMAIN, AUTH0_API_IDENTIFIER and AUTH0_ISSUER. The Access
# Point accepts only tokens whose audience is its own URL, so the tenant's API identifier must equal AP_URL.
auth0_load() {
    [[ -f "${AUTH0_ENV_FILE}" ]] || fail "Auth0 mode needs the values file ${AUTH0_ENV_FILE}; see docs/development/OIDC_DEMO.md"
    auth0_tool check "${AUTH0_ENV_FILE}" >/dev/null 2>&1 || fail "the Auth0 values file is incomplete: $(auth0_tool check "${AUTH0_ENV_FILE}" 2>&1 | tr '\n' ' ')"
    AUTH0_DOMAIN="$(auth0_tool get "${AUTH0_ENV_FILE}" AUTH0_DOMAIN)"
    AUTH0_API_IDENTIFIER="$(auth0_tool get "${AUTH0_ENV_FILE}" AUTH0_API_IDENTIFIER)"
    AUTH0_ISSUER="https://${AUTH0_DOMAIN}/"
    [[ "${AUTH0_API_IDENTIFIER}" == "${AP_URL}" ]] \
        || fail "the Auth0 API identifier must equal the Access Point URL ${AP_URL}; see docs/development/OIDC_DEMO.md"
}

# auth0_redact: masks every value of the Auth0 values file on a stream.
auth0_redact() { auth0_tool redact "${AUTH0_ENV_FILE}"; }

# auth0_mask_logs: masks every value of the Auth0 values file in the gateway's log files (gateway.log and
# everything under _storage/logs). The gateway logs the verified issuer and subject of each accepted token,
# which name the tenant and the app. Run it once the gateway has stopped; down.sh does.
auth0_mask_logs() {
    [[ -f "${AUTH0_ENV_FILE}" ]] || return 0
    local log
    while IFS= read -r log; do
        auth0_redact <"${log}" >"${log}.masked" && cat "${log}.masked" >"${log}"
        rm -f "${log}.masked"
    done < <(find "${GATEWAY_LOG_FILE}" "${GATEWAY_ENV_DIR}/_storage/logs" -type f -name '*.log*' 2>/dev/null)
}

# auth0_token CLIENT: client_credentials grant against the tenant (CLIENT is m2m or noscope); prints only the
# access token. The request body, secret included, reaches curl on standard input, never in a command line.
auth0_token() {
    [[ -n "${TMP_DIR}" ]] || { printf 'auth0_token needs make_tmp first\n' >&2; return 1; }
    local out="${TMP_DIR}/auth0-token-$1.json" code
    code="$(auth0_tool token-body "${AUTH0_ENV_FILE}" "$1" \
        | curl -sS --connect-timeout 5 --max-time 20 -X POST -H 'Content-Type: application/json' --data-binary @- \
            -o "${out}" -w '%{http_code}' "${AUTH0_ISSUER}oauth/token")" || return 1
    [[ "${code}" == "200" ]] || { printf 'Auth0 token request for %s returned HTTP %s\n' "$1" "${code}" >&2; return 1; }
    jq -er '.access_token' "${out}"
}

# auth0_auth_method_json STRATEGY_ID: the Access Point's jwt_bearer method for Auth0. The Access Point URL, which
# auth0_load checked is the API identifier Auth0 puts in aud, is the discovery resource.
auth0_auth_method_json() {
    jq -n --arg sid "$1" --arg scope "${AUTH0_REQUIRED_SCOPE}" \
        '{type: "jwt_bearer", jwt_verification_strategy_id: $sid, audiences: [], required_scopes: [$scope]}'
}
