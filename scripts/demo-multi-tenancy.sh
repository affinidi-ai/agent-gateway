#!/bin/bash

set -euo pipefail

BASE_URL="${AG_BASE_URL:-https://localhost:8443}"
TENANT_A="${AG_DEMO_TENANT_A:-tenant-a}"
TENANT_B="${AG_DEMO_TENANT_B:-tenant-b}"
PROVISION_PATS=false
KEEP_RESOURCES=false
INSECURE=true

usage() {
    cat <<'EOF'
Usage: scripts/demo-multi-tenancy.sh [options]

Runs an executable management multi-tenancy demonstration against a running
Agent Gateway. By default, the script securely prompts for two existing PATs.

Options:
  --base-url URL      Gateway URL (default: https://localhost:8443)
    --provision-pats    Create one-day demo PATs using an administrator session
  --keep              Keep API resources and auto-created PATs after the demo
  --no-insecure       Verify the gateway TLS certificate instead of using -k
  -h, --help          Show this help

Environment:
  PAT_A, PAT_B                    Existing tenant PATs; prompted when omitted
  AG_ADMIN_SESSION_TOKEN        Administrator session for --provision-pats
  AG_BASE_URL                   Alternative to --base-url
  AG_DEMO_TENANT_A              Tenant A identifier (default: tenant-a)
  AG_DEMO_TENANT_B              Tenant B identifier (default: tenant-b)

Dashboard setup for existing PATs:
    1. Open Secrets > Access Tokens and choose New Access Token.
    2. In the full-page editor, add scopes from the Available permissions pills.
    3. Expand Advanced resource scoping and enter the header and pattern below.
    4. Create the token and copy its one-time secret before choosing Done.

Existing PAT contract:
  Header name:      x-demo-tenant
  Header patterns: exact tenant-a / tenant-b values
  Resource pattern:
    TENANT:${x-demo-tenant}:(?:secrets:demo-.*|sts-clients:.*)
  Tenant A scopes: secrets.view/edit/delete and sts_clients.view/edit/delete
  Tenant B scopes: secrets.view/edit/delete
EOF
}

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --base-url)
            [[ $# -ge 2 ]] || fail "--base-url requires a value"
            BASE_URL="${2%/}"
            shift 2
            ;;
        --provision-pats)
            PROVISION_PATS=true
            shift
            ;;
        --keep)
            KEEP_RESOURCES=true
            shift
            ;;
        --no-insecure)
            INSECURE=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

for command_name in curl jq mktemp; do
    command -v "${command_name}" >/dev/null 2>&1 || fail "${command_name} is required"
done

[[ "${TENANT_A}" =~ ^[A-Za-z0-9_-]+$ ]] || fail "tenant A must use only letters, digits, underscore, or dash"
[[ "${TENANT_B}" =~ ^[A-Za-z0-9_-]+$ ]] || fail "tenant B must use only letters, digits, underscore, or dash"
[[ "${TENANT_A}" != "${TENANT_B}" ]] || fail "tenant A and tenant B must differ"

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ag-multitenancy-demo.XXXXXX")"
chmod 700 "${TEMP_DIR}"

CURL_ARGS=(-sS --connect-timeout 5 --max-time 30)
if [[ "${INSECURE}" == "true" ]]; then
    CURL_ARGS+=(-k)
fi

PAT_A="${PAT_A:-}"
PAT_B="${PAT_B:-}"
ADMIN_SESSION_TOKEN="${AG_ADMIN_SESSION_TOKEN:-}"
PAT_A_ID=""
PAT_B_ID=""
A_RECORD_ID=""
B_RECORD_ID=""
STS_RECORD_ID=""
RUN_ID="$(date +%s)-$$"
A_SECRET_ID="demo-${RUN_ID}-a"
B_SECRET_ID="demo-${RUN_ID}-b"
OUTSIDE_SECRET_ID="outside-${RUN_ID}"
STS_CLIENT_ID="demo-sts-${RUN_ID}"

write_headers() {
    local path="$1"
    local token="$2"
    local tenant="${3:-}"

    umask 077
    printf 'Authorization: Bearer %s\n' "${token}" > "${path}"
    if [[ -n "${tenant}" ]]; then
        printf 'x-demo-tenant: %s\n' "${tenant}" >> "${path}"
    fi
}

request() {
    local method="$1"
    local path="$2"
    local headers_file="$3"
    local payload_file="$4"
    local output_file="$5"
    local args=("${CURL_ARGS[@]}" -X "${method}" -o "${output_file}" -w '%{http_code}' -H "@${headers_file}")

    if [[ -n "${payload_file}" ]]; then
        args+=(-H 'Content-Type: application/json' --data-binary "@${payload_file}")
    fi

    curl "${args[@]}" "${BASE_URL}${path}"
}

show_safe_body() {
    local body_file="$1"
    if [[ ! -s "${body_file}" ]]; then
        printf '<empty response>\n' >&2
    elif jq -e . "${body_file}" >/dev/null 2>&1; then
        jq 'del(.token, .value, .token_hash, .client_secret)' "${body_file}" >&2
    else
        printf '<non-JSON response omitted>\n' >&2
    fi
}

expect_status() {
    local label="$1"
    local expected="$2"
    local actual="$3"
    local body_file="$4"

    if [[ "${actual}" != "${expected}" ]]; then
        printf 'FAIL: %s expected HTTP %s, got %s\n' "${label}" "${expected}" "${actual}" >&2
        show_safe_body "${body_file}"
        exit 1
    fi
    printf 'PASS: %-48s HTTP %s\n' "${label}" "${actual}"
}

cleanup_request() {
    local method="$1"
    local path="$2"
    local headers_file="$3"
    local output_file="${TEMP_DIR}/cleanup-response.json"
    local status

    status="$(request "${method}" "${path}" "${headers_file}" "" "${output_file}" 2>/dev/null || true)"
    if [[ "${status}" != "204" && "${status}" != "404" && "${status}" != "401" ]]; then
        printf 'WARN: cleanup %s %s returned HTTP %s\n' "${method}" "${path}" "${status:-unavailable}" >&2
    fi
}

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    set +e

    if [[ "${KEEP_RESOURCES}" == "false" ]]; then
        [[ -z "${STS_RECORD_ID}" || ! -f "${TEMP_DIR}/pat-a.headers" ]] || cleanup_request DELETE "/api/v1/sts/clients/${STS_RECORD_ID}" "${TEMP_DIR}/pat-a.headers"
        [[ -z "${A_RECORD_ID}" || ! -f "${TEMP_DIR}/pat-a.headers" ]] || cleanup_request DELETE "/api/v1/secrets/${A_RECORD_ID}" "${TEMP_DIR}/pat-a.headers"
        [[ -z "${B_RECORD_ID}" || ! -f "${TEMP_DIR}/pat-b.headers" ]] || cleanup_request DELETE "/api/v1/secrets/${B_RECORD_ID}" "${TEMP_DIR}/pat-b.headers"
        [[ -z "${PAT_A_ID}" || ! -f "${TEMP_DIR}/admin.headers" ]] || cleanup_request DELETE "/api/v1/access-tokens/${PAT_A_ID}" "${TEMP_DIR}/admin.headers"
        [[ -z "${PAT_B_ID}" || ! -f "${TEMP_DIR}/admin.headers" ]] || cleanup_request DELETE "/api/v1/access-tokens/${PAT_B_ID}" "${TEMP_DIR}/admin.headers"
    elif [[ -n "${A_RECORD_ID}" || -n "${B_RECORD_ID}" ]]; then
        printf '\nResources retained (--keep):\n'
        [[ -z "${A_RECORD_ID}" ]] || printf '  Tenant A Secret: %s\n' "${A_RECORD_ID}"
        [[ -z "${B_RECORD_ID}" ]] || printf '  Tenant B Secret: %s\n' "${B_RECORD_ID}"
        [[ -z "${STS_RECORD_ID}" ]] || printf '  Tenant A STS client: %s\n' "${STS_RECORD_ID}"
        [[ -z "${PAT_A_ID}" ]] || printf '  Tenant A PAT record: %s\n' "${PAT_A_ID}"
        [[ -z "${PAT_B_ID}" ]] || printf '  Tenant B PAT record: %s\n' "${PAT_B_ID}"
    fi

    rm -rf "${TEMP_DIR}"
    exit "${exit_code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

prompt_secret() {
    local label="$1"
    local destination="$2"
    local value=""

    [[ -t 0 ]] || fail "${label} is required through an environment variable when stdin is not interactive"
    IFS= read -r -s -p "${label}: " value
    printf '\n'
    [[ -n "${value}" ]] || fail "${label} cannot be empty"
    printf -v "${destination}" '%s' "${value}"
}

provision_pat() {
    local tenant="$1"
    local include_sts="$2"
    local output_file="$3"
    local payload_file="${TEMP_DIR}/pat-${tenant}.payload.json"
    local status
    local scopes

    if [[ "${include_sts}" == "true" ]]; then
        scopes='["secrets.view","secrets.edit","secrets.delete","sts_clients.view","sts_clients.edit","sts_clients.delete"]'
    else
        scopes='["secrets.view","secrets.edit","secrets.delete"]'
    fi

    jq -n \
        --arg name "Multi-tenancy demo ${tenant}" \
        --arg description "Temporary PAT created by the multi-tenancy demo" \
        --arg resource_pattern 'TENANT:${x-demo-tenant}:(?:secrets:demo-.*|sts-clients:.*)' \
        --arg header_pattern "${tenant}" \
        --argjson scopes "${scopes}" \
        '{name:$name,description:$description,scopes:$scopes,resource_pattern:$resource_pattern,required_headers:[{name:"x-demo-tenant",pattern:$header_pattern}],expires_at:(now + 86400 | todateiso8601)}' \
        > "${payload_file}"

    status="$(request POST /api/v1/access-tokens "${TEMP_DIR}/admin.headers" "${payload_file}" "${output_file}")"
    expect_status "provision PAT for ${tenant}" 201 "${status}" "${output_file}"
}

printf 'Management multi-tenancy demo\n'
printf 'Gateway: %s\n' "${BASE_URL}"
printf 'Tenants: %s and %s\n\n' "${TENANT_A}" "${TENANT_B}"

if ! curl "${CURL_ARGS[@]}" -o /dev/null "${BASE_URL}/"; then
    fail "Agent Gateway is not reachable at ${BASE_URL}; start it with 'make run-debug'"
fi

if [[ "${PROVISION_PATS}" == "true" ]]; then
    if [[ -z "${ADMIN_SESSION_TOKEN}" ]]; then
        prompt_secret "Administrator session token" ADMIN_SESSION_TOKEN
    fi
    write_headers "${TEMP_DIR}/admin.headers" "${ADMIN_SESSION_TOKEN}"

    provision_pat "${TENANT_A}" true "${TEMP_DIR}/pat-a.json"
    PAT_A_ID="$(jq -er '.id | strings | select(length > 0)' "${TEMP_DIR}/pat-a.json")"
    PAT_A="$(jq -er '.token | strings | select(length > 0)' "${TEMP_DIR}/pat-a.json")"

    provision_pat "${TENANT_B}" false "${TEMP_DIR}/pat-b.json"
    PAT_B_ID="$(jq -er '.id | strings | select(length > 0)' "${TEMP_DIR}/pat-b.json")"
    PAT_B="$(jq -er '.token | strings | select(length > 0)' "${TEMP_DIR}/pat-b.json")"
else
    [[ -n "${PAT_A}" ]] || prompt_secret "Tenant A PAT" PAT_A
    [[ -n "${PAT_B}" ]] || prompt_secret "Tenant B PAT" PAT_B
fi

write_headers "${TEMP_DIR}/pat-a.headers" "${PAT_A}" "${TENANT_A}"
write_headers "${TEMP_DIR}/pat-b.headers" "${PAT_B}" "${TENANT_B}"
write_headers "${TEMP_DIR}/pat-a-no-tenant.headers" "${PAT_A}"
write_headers "${TEMP_DIR}/pat-a-wrong-tenant.headers" "${PAT_A}" "${TENANT_B}"

printf '\n1. Create one Secret per tenant\n'
printf '   Why: creation must stamp ownership from the validated PAT tenant, not from caller JSON.\n'

jq -n --arg name "Tenant A demo" --arg secret_id "${A_SECRET_ID}" \
    '{name:$name,secret_id:$secret_id,value:"demo-value-a",tags:["multitenancy-demo"]}' \
    > "${TEMP_DIR}/secret-a.payload.json"
status="$(request POST /api/v1/secrets/new "${TEMP_DIR}/pat-a.headers" "${TEMP_DIR}/secret-a.payload.json" "${TEMP_DIR}/secret-a.json")"
expect_status "create Tenant A Secret" 201 "${status}" "${TEMP_DIR}/secret-a.json"
A_RECORD_ID="$(jq -er '.id | strings | select(length > 0)' "${TEMP_DIR}/secret-a.json")"
[[ "$(jq -r '.tenant_id' "${TEMP_DIR}/secret-a.json")" == "${TENANT_A}" ]] || fail "Tenant A ownership was not stamped"

jq -n --arg name "Tenant B demo" --arg secret_id "${B_SECRET_ID}" \
    '{name:$name,secret_id:$secret_id,value:"demo-value-b",tags:["multitenancy-demo"]}' \
    > "${TEMP_DIR}/secret-b.payload.json"
status="$(request POST /api/v1/secrets/new "${TEMP_DIR}/pat-b.headers" "${TEMP_DIR}/secret-b.payload.json" "${TEMP_DIR}/secret-b.json")"
expect_status "create Tenant B Secret" 201 "${status}" "${TEMP_DIR}/secret-b.json"
B_RECORD_ID="$(jq -er '.id | strings | select(length > 0)' "${TEMP_DIR}/secret-b.json")"
[[ "$(jq -r '.tenant_id' "${TEMP_DIR}/secret-b.json")" == "${TENANT_B}" ]] || fail "Tenant B ownership was not stamped"

printf '\n2. List as Tenant A\n'
printf '   Why: list responses must include same-tenant and global records, never foreign tenant records.\n'
status="$(request GET /api/v1/secrets "${TEMP_DIR}/pat-a.headers" "" "${TEMP_DIR}/tenant-a-list.json")"
expect_status "list Secrets as Tenant A" 200 "${status}" "${TEMP_DIR}/tenant-a-list.json"
jq -e --arg own "${A_SECRET_ID}" --arg foreign "${B_SECRET_ID}" \
    'any(.[]; .secret_id == $own) and all(.[]; .secret_id != $foreign)' \
    "${TEMP_DIR}/tenant-a-list.json" >/dev/null || fail "Tenant A list did not isolate tenant records"
printf 'PASS: Tenant A list contains its Secret and omits Tenant B\n'

printf '\n3. Attempt foreign read and update\n'
printf '   Why: reads hide foreign-resource existence with 404; mutations reject with 403.\n'
status="$(request GET "/api/v1/secrets/${B_RECORD_ID}" "${TEMP_DIR}/pat-a.headers" "" "${TEMP_DIR}/foreign-read.json")"
expect_status "Tenant A reads Tenant B Secret" 404 "${status}" "${TEMP_DIR}/foreign-read.json"
jq -n '{description:"cross-tenant attempt"}' > "${TEMP_DIR}/foreign-update.payload.json"
status="$(request PUT "/api/v1/secrets/${B_RECORD_ID}" "${TEMP_DIR}/pat-a.headers" "${TEMP_DIR}/foreign-update.payload.json" "${TEMP_DIR}/foreign-update.json")"
expect_status "Tenant A updates Tenant B Secret" 403 "${status}" "${TEMP_DIR}/foreign-update.json"

printf '\n4. Exercise tenant-header and canonical-scope gates\n'
printf '   Why: the selector header is mandatory, exact, and independent from persisted ownership.\n'
status="$(request GET /api/v1/secrets "${TEMP_DIR}/pat-a-no-tenant.headers" "" "${TEMP_DIR}/missing-header.json")"
expect_status "Tenant A PAT without selector header" 403 "${status}" "${TEMP_DIR}/missing-header.json"
status="$(request GET /api/v1/secrets "${TEMP_DIR}/pat-a-wrong-tenant.headers" "" "${TEMP_DIR}/wrong-header.json")"
expect_status "Tenant A PAT with Tenant B header" 403 "${status}" "${TEMP_DIR}/wrong-header.json"
jq -n --arg secret_id "${OUTSIDE_SECRET_ID}" \
    '{name:"Outside demo scope",secret_id:$secret_id,value:"not-persisted"}' \
    > "${TEMP_DIR}/outside.payload.json"
status="$(request POST /api/v1/secrets/new "${TEMP_DIR}/pat-a.headers" "${TEMP_DIR}/outside.payload.json" "${TEMP_DIR}/outside.json")"
expect_status "create Secret outside secrets:demo-.*" 403 "${status}" "${TEMP_DIR}/outside.json"

printf '\n5. Exercise feature-scope narrowing\n'
printf '   Why: Tenant B has a matching resource pattern but no sts_clients.edit feature scope.\n'
jq -n --arg client_id "demo-sts-scope-${RUN_ID}" --arg secret_ref "${B_SECRET_ID}" \
    '{client_id:$client_id,name:"Tenant B denied STS",client_secret_ref:$secret_ref}' \
    > "${TEMP_DIR}/sts-b.payload.json"
status="$(request POST /api/v1/sts/clients "${TEMP_DIR}/pat-b.headers" "${TEMP_DIR}/sts-b.payload.json" "${TEMP_DIR}/sts-b.json")"
expect_status "Tenant B creates STS client without feature scope" 403 "${status}" "${TEMP_DIR}/sts-b.json"

printf '\n6. Exercise same-tenant reference integrity\n'
printf '   Why: tenant-owned records may reference only same-tenant or global dependencies.\n'
jq -n --arg client_id "${STS_CLIENT_ID}" --arg secret_ref "${A_SECRET_ID}" \
    '{client_id:$client_id,name:"Tenant A STS",client_secret_ref:$secret_ref}' \
    > "${TEMP_DIR}/sts-a.payload.json"
status="$(request POST /api/v1/sts/clients "${TEMP_DIR}/pat-a.headers" "${TEMP_DIR}/sts-a.payload.json" "${TEMP_DIR}/sts-a.json")"
expect_status "Tenant A STS client references Tenant A Secret" 201 "${status}" "${TEMP_DIR}/sts-a.json"
STS_RECORD_ID="$(jq -er '.id | strings | select(length > 0)' "${TEMP_DIR}/sts-a.json")"

jq -n --arg client_id "demo-sts-cross-${RUN_ID}" --arg secret_ref "${B_SECRET_ID}" \
    '{client_id:$client_id,name:"Cross-tenant STS",client_secret_ref:$secret_ref}' \
    > "${TEMP_DIR}/sts-cross.payload.json"
status="$(request POST /api/v1/sts/clients "${TEMP_DIR}/pat-a.headers" "${TEMP_DIR}/sts-cross.payload.json" "${TEMP_DIR}/sts-cross.json")"
expect_status "Tenant A STS client references Tenant B Secret" 400 "${status}" "${TEMP_DIR}/sts-cross.json"

printf '\nSUCCESS: all management multi-tenancy assertions passed.\n'
if [[ "${KEEP_RESOURCES}" == "false" ]]; then
    printf 'Temporary API resources%s will now be removed.\n' "$(if [[ "${PROVISION_PATS}" == "true" ]]; then printf ' and PATs'; fi)"
fi