#!/usr/bin/env bash
#
# Run the published MCP conformance suite (frozen 2026-07-28 requirement set)
# against Agent Trust Gateway, then the checks the suite does not make and the
# legacy compatibility checks. See scripts/mcp-conformance/README.md.
#
# Exit codes: 0 pass, 1 failure, 2 invalid options or precondition not met,
# 3 dependency fetch failed, 130 SIGINT, 143 SIGTERM.

set -euo pipefail
unset CDPATH

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
WORK="${REPO}/target/mcp-conformance"
LOCK="${WORK}/.lock"
LOCK_CLEARING="${WORK}/.lock-clearing"
RUN="${WORK}/run"
LOGS="${RUN}/logs"
RESULTS="${RUN}/results"
REPORT_DIR="${RUN}/report"
GAPS_FILE="${RUN}/gaps.md"

SPEC_VERSION="2026-07-28"
REFERENCE_SHA="f44482ba17df816d3176962a11cdf36aec9bda00"
REFERENCE_REPO="${MCP_CONFORMANCE_REFERENCE_REPO:-https://github.com/modelcontextprotocol/conformance.git}"
REFERENCE_DIR="${WORK}/reference"
REFERENCE_SERVER_DIR="${REFERENCE_DIR}/examples/servers/typescript"
# The binary name is read from Cargo.toml.
BIN_NAME="$(sed -n 's/^name = "\(.*\)"/\1/p' "${REPO}/Cargo.toml" | head -1)"
DEFAULT_BINARY="${REPO}/target/debug/${BIN_NAME}"
NODE_MIN="22.0.0"
REQUIREMENTS_FILE="${HERE}/node_modules/@modelcontextprotocol/conformance/requirements/${SPEC_VERSION}.yaml"
SUITE_VERSION="$(sed -n 's|.*"@modelcontextprotocol/conformance": "\(.*\)".*|\1|p' "${HERE}/package.json")"
SUITE_TARGETS=(direct access-point transit owned-proxy proxy-surface fabric)
OWNED_SCENARIOS=(tools-list tools-call-simple-text caching)
# The suite's client scenarios for ${SPEC_VERSION} that need no authorization.
# The reference client has no handler for some of them; those fail the same way
# with and without the gateway, which client-parity.mjs checks.
CLIENT_SCENARIOS=(tools_call request-metadata sep-2322-client-request-state json-schema-2020-12-preservation
    json-schema-ref-no-deref http-standard-headers http-custom-headers http-invalid-tool-headers)
CLIENT_MUST_PASS=(tools_call request-metadata sep-2322-client-request-state json-schema-2020-12-preservation)
# The extension scenario in which the gateway itself asks the suite's
# authorization server for a token and attaches it to the forwarded request.
CLIENT_AUTH_SCENARIO="auth/client-credentials-jwt"

PORT_BASE="${MCP_CONFORMANCE_PORT_BASE:-18760}"
REFERENCE_PORT=$((PORT_BASE))
FIXTURE_PORT=$((PORT_BASE + 1))
SHIM_PORT=$((PORT_BASE + 2))
MODERN_INBOUND_PORT=$((PORT_BASE + 10))
MODERN_OUTBOUND_PORT=$((PORT_BASE + 11))
LEGACY_INBOUND_PORT=$((PORT_BASE + 20))
LEGACY_OUTBOUND_PORT=$((PORT_BASE + 21))
CLIENT_INBOUND_PORT=$((PORT_BASE + 30))
CLIENT_OUTBOUND_PORT=$((PORT_BASE + 31))

usage() {
    cat <<EOF
Usage: scripts/mcp-conformance/run.sh [options]

  --skip-build            Use existing binaries instead of building them
  --binary PATH           Gateway binary for the modern and legacy phases;
                          the fabric target always builds its own through Cargo
  --only LIST             Comma-separated, non-empty subset of:
                          direct,access-point,transit,owned-proxy,proxy-surface,fabric,client,legacy
                          (fabric needs Docker for the mediator between its two gateways)
  --unit-tests            Also run the full binary test suite
                          (not run, with a warning, when LIST has no modern target)
  --report                Report only: run every scenario the suite has against
                          each selected target, ignore the suite's verdicts and
                          the baselines, and list the open gaps in
                          target/mcp-conformance/run/gaps.md
  -h, --help              Show this help

Environment:
  MCP_CONFORMANCE_PORT_BASE       First of the local ports used (default 18760)
  MCP_CONFORMANCE_REFERENCE_REPO  Git URL or mirror of modelcontextprotocol/conformance
EOF
}

option_value() {
    if [[ -z "${2:-}" ]]; then
        echo "$1 needs a value" >&2
        usage >&2
        exit 2
    fi
}

SKIP_BUILD=false
UNIT_TESTS=false
REPORT=false
BINARY=""
ONLY="direct,access-point,transit,owned-proxy,proxy-surface,fabric,client,legacy"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true ;;
        --unit-tests) UNIT_TESTS=true ;;
        --report) REPORT=true ;;
        --binary) option_value "$1" "${2:-}"; BINARY="$2"; shift ;;
        --only) option_value "$1" "${2:-}"; ONLY="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        --legacy-binary) echo "--legacy-binary was removed: --binary now runs both the modern and legacy phases" >&2; exit 2 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

selected() { [[ ",${ONLY}," == *",$1,"* ]]; }

for name in ${ONLY//,/ }; do
    case "${name}" in
        direct|access-point|transit|owned-proxy|proxy-surface|fabric|client|legacy) ;;
        *) echo "Unknown --only entry: ${name}" >&2; exit 2 ;;
    esac
done

MODERN_TARGETS=()
for name in "${SUITE_TARGETS[@]}"; do
    if selected "${name}"; then MODERN_TARGETS+=("${name}"); fi
done
if [[ ${#MODERN_TARGETS[@]} -gt 0 ]]; then RUN_MODERN=true; else RUN_MODERN=false; fi
if selected legacy; then RUN_LEGACY=true; else RUN_LEGACY=false; fi
if selected client; then RUN_CLIENT=true; else RUN_CLIENT=false; fi
# The legacy target runs no suite scenario, so a report has nothing to say about it.
if [[ "${REPORT}" == true ]]; then RUN_LEGACY=false; fi
if [[ "${RUN_MODERN}" != true && "${RUN_LEGACY}" != true && "${RUN_CLIENT}" != true ]]; then
    echo "--only selects no target$([[ "${REPORT}" != true ]] || echo ' that --report covers'): '${ONLY}'" >&2
    exit 2
fi

absolute_path() {
    local var="$1" option="$2" path="$3" dir
    dir="$(dirname -- "${path}")"
    [[ "${dir}" == /* ]] || dir="./${dir}"
    if ! dir="$(cd -- "${dir}" 2>/dev/null && pwd)"; then
        echo "${option}: the directory of ${path} does not exist" >&2
        exit 2
    fi
    printf -v "${var}" '%s/%s' "${dir}" "$(basename -- "${path}")"
}
[[ -z "${BINARY}" ]] || absolute_path BINARY --binary "${BINARY}"

SUMMARY=()
REPORT_TARGETS=()
FAILED=false
STARTED_PIDS=()
OWN_LOCK=false
OWN_LOCK_CLEARING=false
RUN_CREATED=false

record() {
    SUMMARY+=("$(printf '%-5s %s' "$1" "$2")")
    printf '[%s] %s\n' "$1" "$2"
}

fail() {
    record FAIL "$2"
    exit "$1"
}

relative() { echo "${1#"${REPO}"/}"; }

check() {
    local name="$1" log="$2" skipped
    shift 2
    if "$@" 2>&1 | tee "${log}"; then
        record PASS "${name}"
    else
        record FAIL "${name} (log: $(relative "${log}"))"
        FAILED=true
    fi
    while read -r _ skipped; do
        record SKIP "${name%% (*}: ${skipped}"
    done < <(grep '^SKIP ' "${log}" || true)
}

# Signal a PID only while it is a running child of this shell. Once the shell
# has reaped a child (after `wait`, or by itself when the child exits), the OS
# can hand its PID to a process the harness did not start.
running_child() {
    local job
    for job in $(jobs -pr); do
        if [[ "${job}" == "$1" ]]; then return 0; fi
    done
    return 1
}

forget_pid() {
    local kept=() p
    for p in "${STARTED_PIDS[@]+"${STARTED_PIDS[@]}"}"; do
        if [[ "${p}" != "$1" ]]; then kept+=("${p}"); fi
    done
    STARTED_PIDS=("${kept[@]+"${kept[@]}"}")
}

stop_pid() {
    local pid="$1" waited=0
    forget_pid "${pid}"
    running_child "${pid}" || return 0
    kill "${pid}" 2>/dev/null || true
    while running_child "${pid}" && [[ ${waited} -lt 20 ]]; do
        sleep 0.5
        waited=$((waited + 1))
    done
    if running_child "${pid}"; then kill -9 "${pid}" 2>/dev/null || true; fi
    wait "${pid}" 2>/dev/null || true
}

# Runs share everything under ${WORK} and the harness node_modules, whatever
# their port base, so only one runs at a time. The lock is a symlink naming the
# holder's PID: creating it is atomic, so a lock never exists without its PID.
lock_holder() { readlink "${LOCK}" 2>/dev/null || true; }

# A lock left by a killed run names a PID the OS may since have given to an
# unrelated process, so the holder only counts while that PID runs this script.
lock_holder_running() {
    local pid="$1" command
    [[ "${pid}" =~ ^[0-9]+$ && "${pid}" -gt 1 && "${pid}" -ne $$ ]] || return 1
    kill -0 "${pid}" 2>/dev/null || ps -p "${pid}" > /dev/null 2>&1 || return 1
    if command="$(ps -o command= -p "${pid}" 2>/dev/null)" && [[ -n "${command}" ]]; then
        if [[ "${command}" != *run.sh* ]]; then return 1; fi
    fi
    return 0
}

take_lock() {
    local attempt holder
    mkdir -p "${WORK}"
    # ln would create its link inside a real directory instead of failing.
    if [[ -e "${LOCK}" && ! -L "${LOCK}" ]]; then
        fail 2 "preflight: $(relative "${LOCK}") is not a lock this harness created; remove it"
    fi
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if ln -sn "$$" "${LOCK}" 2>/dev/null; then
            OWN_LOCK=true
            return
        fi
        holder="$(lock_holder)"
        if lock_holder_running "${holder}"; then
            fail 2 "preflight: another mcp-conformance run (PID ${holder}) is in progress; wait for it to finish"
        fi
        # Stale. Only one run clears it, and only while it names the same holder,
        # so two runs that both found it stale cannot remove each other's lock.
        if mkdir "${LOCK_CLEARING}" 2>/dev/null; then
            OWN_LOCK_CLEARING=true
            if [[ "$(lock_holder)" == "${holder}" ]]; then rm -f "${LOCK}"; fi
            rmdir "${LOCK_CLEARING}"
            OWN_LOCK_CLEARING=false
        else
            sleep 0.5
        fi
    done
    fail 2 "preflight: could not take $(relative "${LOCK}"); if no run is in progress, remove it and $(relative "${LOCK_CLEARING}")"
}

release_lock() {
    if [[ "${OWN_LOCK_CLEARING}" == true ]]; then rmdir "${LOCK_CLEARING}" 2>/dev/null || true; fi
    if [[ "${OWN_LOCK}" == true && "$(lock_holder)" == "$$" ]]; then rm -f "${LOCK}"; fi
    OWN_LOCK=false
}

write_summary() {
    echo "MCP conformance harness"
    echo "suite: @modelcontextprotocol/conformance@${SUITE_VERSION}, requirements ${SPEC_VERSION}"
    echo "reference: ${REFERENCE_REPO} @ ${REFERENCE_SHA}"
    echo "targets: ${ONLY}"
    if [[ "${REPORT}" == true ]]; then echo "mode: report only; suite verdicts and baselines are ignored"; fi
    echo
    printf '%s\n' "${SUMMARY[@]+"${SUMMARY[@]}"}"
    echo
    case "$1" in
        0) if [[ "${REPORT}" == true ]]; then echo "RESULT: REPORT WRITTEN (exit 0)"; else echo "RESULT: PASS (exit 0)"; fi ;;
        2) echo "RESULT: PRECONDITION NOT MET (exit 2)" ;;
        3) echo "RESULT: DEPENDENCY FETCH FAILED (exit 3)" ;;
        *) echo "RESULT: FAIL (exit $1)" ;;
    esac
}

cleanup() {
    local code=$?
    local pid
    for pid in "${STARTED_PIDS[@]+"${STARTED_PIDS[@]}"}"; do
        stop_pid "${pid}"
    done
    if [[ ${code} -eq 0 && "${FAILED}" == true ]]; then
        code=1
    fi
    echo
    # A run that stopped before creating ${RUN} leaves the previous run's
    # outputs alone and only prints its summary.
    if [[ "${RUN_CREATED}" == true ]]; then
        write_summary "${code}" > "${RUN}/summary.txt"
        cat "${RUN}/summary.txt"
    else
        write_summary "${code}"
    fi
    release_lock
    exit "${code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

# Preflight checks every port, and each step checks its own again just before
# starting the process that listens on them, because builds and fetches run in
# between. The harness never stops a process it did not start.
require_free_ports() {
    local step="$1" port
    shift
    for port in "$@"; do
        if port_open "${port}"; then
            fail 2 "${step}: port ${port} is already in use; free it or set MCP_CONFORMANCE_PORT_BASE"
        fi
    done
}

start_process() {
    local log="$1" dir="$2"
    shift 2
    ( cd "${dir}" && exec "$@" ) > "${log}" 2>&1 &
    STARTED_PID=$!
    STARTED_PIDS+=("${STARTED_PID}")
}

# The process must still be running once its ports accept connections: if it
# exited, a listener another process opened on them would be tested instead.
wait_for_ports() {
    local pid="$1" deadline=$((SECONDS + 120))
    shift
    local port
    for port in "$@"; do
        until port_open "${port}"; do
            running_child "${pid}" || return 1
            [[ ${SECONDS} -lt ${deadline} ]] || return 1
            sleep 0.5
        done
    done
    running_child "${pid}"
}

# A fetch failure is soft in CI (exit 3); anything else, such as a lockfile out
# of sync with package.json, is a real failure.
npm_install() {
    local name="$1" dir="$2" log="${LOGS}/npm-${1}.log"
    shift 2
    if (cd "${dir}" && npm ci --include=dev --no-audit --no-fund --prefer-offline --cache "${WORK}/npm-cache" "$@") > "${log}" 2>&1; then
        record PASS "dependencies: ${name} (npm ci)"
        return
    fi
    tail -20 "${log}" >&2
    if grep -Eq 'E(NOTFOUND|AI_AGAIN|CONNRESET|CONNREFUSED|TIMEDOUT|NETUNREACH)|ETARGET|network|fetch failed|code E5[0-9][0-9]' "${log}"; then
        fail 3 "dependencies: ${name} npm ci could not fetch packages (log: $(relative "${log}"))"
    fi
    fail 1 "dependencies: ${name} npm ci failed (log: $(relative "${log}"))"
}

reference_git() {
    GIT_TERMINAL_PROMPT=0 git -c core.hooksPath=/dev/null -c advice.detachedHead=false \
        --git-dir="${REFERENCE_DIR}/.git" --work-tree="${REFERENCE_DIR}" "$@"
}

fetch_reference() {
    local log="${LOGS}/reference-fetch.log"
    if [[ "$(reference_git rev-parse -q --verify 'HEAD^{commit}' 2>/dev/null || true)" != "${REFERENCE_SHA}" ]]; then
        rm -rf "${REFERENCE_DIR}"
        mkdir -p "${REFERENCE_DIR}"
        {
            reference_git init -q &&
                reference_git remote add origin "${REFERENCE_REPO}"
        } > "${log}" 2>&1 || fail 1 "dependencies: could not initialise the reference checkout"
        if ! reference_git fetch -q --depth 1 origin "${REFERENCE_SHA}" >> "${log}" 2>&1; then
            cat "${log}" >&2
            rm -rf "${REFERENCE_DIR}"
            fail 3 "dependencies: could not fetch reference ${REFERENCE_SHA} from ${REFERENCE_REPO}"
        fi
        reference_git checkout -q --detach "${REFERENCE_SHA}" >> "${log}" 2>&1 ||
            fail 1 "dependencies: could not check out reference ${REFERENCE_SHA}"
    fi
    [[ "$(reference_git rev-parse HEAD)" == "${REFERENCE_SHA}" ]] ||
        fail 1 "dependencies: reference checkout is not at ${REFERENCE_SHA}"
    reference_git reset -q --hard "${REFERENCE_SHA}"
    record PASS "dependencies: reference server ${REFERENCE_SHA}"
}

gateway_cargo() {
    CARGO_TARGET_DIR="${REPO}/target" cargo "$1" --locked --bin "${BIN_NAME}" "${@:2}"
}

build_step() {
    local name="$1" log="$2"
    shift 2
    if (cd "${REPO}" && "$@") > "${log}" 2>&1; then
        record PASS "${name}"
    else
        tail -40 "${log}" >&2
        fail 1 "${name} (log: $(relative "${log}"))"
    fi
}

test_step() {
    local name="$1" log="$2"
    shift 2
    if (cd "${REPO}" && "$@") > "${log}" 2>&1; then
        record PASS "${name}: $(grep -E '^test result: ' "${log}" | tail -1)"
    else
        tail -40 "${log}" >&2
        record FAIL "${name} (log: $(relative "${log}"))"
        FAILED=true
    fi
}

start_gateway() {
    local phase="$1" binary="$2" inbound="$3" outbound="$4"
    local env_dir="${WORK}/env/${phase}"
    node "${HERE}/env.mjs" --dir "${env_dir}" --binary "${binary}" \
        --inbound-port "${inbound}" --outbound-port "${outbound}" \
        --reference-url "http://127.0.0.1:${REFERENCE_PORT}/mcp" \
        --upstream-url "http://127.0.0.1:${SHIM_PORT}/mcp" \
        --fixture-url "http://127.0.0.1:${FIXTURE_PORT}" > "${LOGS}/env-${phase}.log" 2>&1 ||
        fail 1 "${phase}: could not write the env (log: $(relative "${LOGS}/env-${phase}.log"))"
    require_free_ports "${phase}" "${inbound}" "${outbound}"
    (
        cd "${env_dir}/config"
        export "$(cat "${env_dir}/backup-key-var")=$(openssl rand -hex 32)"
        export RUST_LOG="${RUST_LOG:-info}"
        export AG_TEST_MODE=true AG_BDD_EGRESS_ALLOWLIST="http://127.0.0.1:${FIXTURE_PORT}"
        exec "${binary}" --config config.toml
    ) > "${LOGS}/gateway-${phase}.log" 2>&1 &
    GATEWAY_PID=$!
    STARTED_PIDS+=("${GATEWAY_PID}")
    if ! wait_for_ports "${GATEWAY_PID}" "${inbound}" "${outbound}"; then
        tail -40 "${LOGS}/gateway-${phase}.log" >&2
        fail 1 "${phase}: gateway did not start (log: $(relative "${LOGS}/gateway-${phase}.log"))"
    fi
    record PASS "${phase}: gateway started ($(relative "${binary}"))"
    TARGETS_FILE="${env_dir}/targets.json"
}

stop_gateway() {
    stop_pid "${GATEWAY_PID}"
}

suite_counts() {
    local leg="$1" dir="$2"
    shift 2
    node "${HERE}/suite-report.mjs" counts --results "${dir}" --leg "${leg}" --requirements "${REQUIREMENTS_FILE}" "$@" 2> /dev/null ||
        echo "no results"
}

suite_detail() {
    local log="$1" name="$2" baseline="$3"
    echo "$(grep -cE '^=== Running scenario: ' "${log}" || true) scenarios run; $(suite_counts server "${RESULTS}/${name}" --baseline "${HERE}/expected-failures/${baseline}.yaml")"
}

# A report-only run of one target: "$@ --scenario <name>" for every scenario the
# suite lists for the leg, ignoring the verdict. A scenario runs on the
# ${SPEC_VERSION} wire when it applies there or is an extension, and at its own
# revision otherwise. The suite's exit status marks a scenario it failed, which
# can happen without a failed check.
report_run() {
    local name="$1" log="$2" leg="$3" scenario tags flags count=0
    shift 3
    : > "${log}"
    : > "${REPORT_DIR}/${name}.failed"
    while read -r scenario tags <&3; do
        flags=()
        if [[ ",${tags}," == *",${SPEC_VERSION},"* || "${tags}" == extension ]]; then
            flags=(--spec-version "${SPEC_VERSION}" --force)
        fi
        echo "=== ${scenario} ===" >> "${log}"
        "$@" --scenario "${scenario}" "${flags[@]+"${flags[@]}"}" >> "${log}" 2>&1 ||
            echo "${scenario}" >> "${REPORT_DIR}/${name}.failed"
        count=$((count + 1))
    done 3< <("${CONFORMANCE}" list "--${leg}" 2> /dev/null | sed -n 's/^  - \([^ ]*\) \[\(.*\)\]$/\1 \2/p')
    [[ ${count} -gt 0 ]] || fail 1 "suite ${name}: the suite lists no ${leg} scenario"
    record INFO "suite ${name}: ${count} scenarios run, verdict ignored"
    REPORT_TARGETS+=("${name}")
}

run_suite() {
    local name="$1" url="$2" baseline="$3" log="${LOGS}/suite-${1}.log"
    local out="${RESULTS}/${name}"
    if [[ "${REPORT}" == true ]]; then
        report_run "${name}" "${log}" server "${CONFORMANCE}" server --url "${url}" -o "${out}"
        return
    fi
    if "${CONFORMANCE}" server --url "${url}" --requirements "${SPEC_VERSION}" \
        --expected-failures "${HERE}/expected-failures/${baseline}.yaml" -o "${out}" > "${log}" 2>&1; then
        record PASS "suite ${name}: $(suite_detail "${log}" "${name}" "${baseline}")"
    else
        tail -40 "${log}"
        record FAIL "suite ${name}: $(suite_detail "${log}" "${name}" "${baseline}") (log: $(relative "${log}"))"
        FAILED=true
    fi
}

run_owned_suite() {
    local name="$1" url="$2" log="${LOGS}/suite-${1}.log" scenario ok=true counts
    if [[ "${REPORT}" == true ]]; then
        run_suite "${name}" "${url}" owned
        return
    fi
    : > "${log}"
    for scenario in "${OWNED_SCENARIOS[@]}"; do
        echo "=== ${scenario} ===" >> "${log}"
        if ! "${CONFORMANCE}" server --url "${url}" --scenario "${scenario}" --spec-version "${SPEC_VERSION}" \
            --expected-failures "${HERE}/expected-failures/owned.yaml" -o "${RESULTS}/${name}" >> "${log}" 2>&1; then
            ok=false
        fi
    done
    counts="$(suite_counts server "${RESULTS}/${name}" --baseline "${HERE}/expected-failures/owned.yaml")"
    if [[ "${ok}" == true ]]; then
        record PASS "suite ${name}: ${OWNED_SCENARIOS[*]}; ${counts}"
    else
        tail -40 "${log}"
        record FAIL "suite ${name}: ${OWNED_SCENARIOS[*]}; ${counts} (log: $(relative "${log}"))"
        FAILED=true
    fi
}

# The fabric target runs through the g2g BDD runner (fabric.feature): it starts
# two gateways paired over a managed mediator in Docker, and a
# step runs the suite against gateway 1, whose Access Point targets fabric:// to
# gateway 2. Gateway 2 forwards to the reference server through the shim.
run_fabric_suite() {
    local log="${LOGS}/suite-fabric.log" bdd_log="${LOGS}/g2g-fabric.log" ok=true
    : > "${log}"
    (cd "${REPO}" && env \
        G2G_BDD_PARALLELISM=1 FABRIC_BDD_MANAGED_MEDIATOR=1 FABRIC_BDD_DID_METHOD=peer \
        RUST_LOG="${RUST_LOG:-info}" G2G_BDD_GATEWAY_LOG_LEVEL="${G2G_BDD_GATEWAY_LOG_LEVEL:-warn}" \
        BDD_FEATURE_PATH="${HERE}/fabric.feature" \
        MCP_CONFORMANCE_UPSTREAM_URL="http://127.0.0.1:${SHIM_PORT}/mcp" \
        MCP_CONFORMANCE_CLI="${CONFORMANCE}" \
        MCP_CONFORMANCE_REQUIREMENTS="${SPEC_VERSION}" \
        MCP_CONFORMANCE_EXPECTED_FAILURES="${HERE}/expected-failures/fabric.yaml" \
        MCP_CONFORMANCE_OUTPUT="${RESULTS}/fabric" \
        MCP_CONFORMANCE_LOG="${log}" \
        CARGO_TARGET_DIR="${REPO}/target" \
        cargo test --locked --test g2g_bdd) > "${bdd_log}" 2>&1 || ok=false
    # The BDD step runs the suite once, so a report-only run of this target has
    # the requirement set's scenarios and no others.
    if [[ "${REPORT}" == true ]] && grep -qE '^=== Running scenario: ' "${log}"; then
        sed -n 's/^✗ \(.*\): [0-9][0-9]* passed.*/\1/p' "${log}" > "${REPORT_DIR}/fabric.failed"
        record INFO "suite fabric: $(grep -cE '^=== Running scenario: ' "${log}") scenarios run, verdict ignored"
        REPORT_TARGETS+=(fabric)
        return
    fi
    if [[ "${ok}" == true ]] && grep -qE '^=== Running scenario: ' "${log}"; then
        record PASS "suite fabric: $(suite_detail "${log}" fabric fabric)"
    else
        tail -40 "${bdd_log}"
        record FAIL "suite fabric: $(suite_detail "${log}" fabric fabric) (logs: $(relative "${bdd_log}"), $(relative "${log}"))"
        FAILED=true
    fi
}

# The client target runs each client scenario twice with the suite's reference
# client: straight at the suite's own server, and through a gateway that
# client-driver.mjs starts with that server as its Target.
client_scenario() {
    local mode="$1" status=0 waited=0
    shift
    env MCP_CONFORMANCE_DRIVER_MODE="${mode}" \
        MCP_CONFORMANCE_DRIVER_REFERENCE="${REFERENCE_DIR}" \
        MCP_CONFORMANCE_DRIVER_BINARY="${BINARY}" \
        MCP_CONFORMANCE_DRIVER_WORK="${WORK}/env/client" \
        MCP_CONFORMANCE_DRIVER_INBOUND_PORT="${CLIENT_INBOUND_PORT}" \
        MCP_CONFORMANCE_DRIVER_OUTBOUND_PORT="${CLIENT_OUTBOUND_PORT}" \
        MCP_CONFORMANCE_DRIVER_FIXTURE_URL="http://127.0.0.1:${FIXTURE_PORT}" \
        "${CONFORMANCE}" client "$@" \
        -o "${RESULTS}/client-${mode}" --command "node ${HERE}/client-driver.mjs" || status=$?
    # A gateway left behind by one scenario would answer the next one.
    while port_open "${CLIENT_INBOUND_PORT}"; do
        [[ ${waited} -lt 20 ]] ||
            fail 1 "suite client: a gateway is still listening on port ${CLIENT_INBOUND_PORT} after a scenario"
        sleep 0.5
        waited=$((waited + 1))
    done
    return "${status}"
}

run_client_mode() {
    local mode="$1" log="${LOGS}/suite-client-${1}.log" scenario
    : > "${log}"
    for scenario in "${CLIENT_SCENARIOS[@]}"; do
        echo "=== ${scenario} ===" >> "${log}"
        client_scenario "${mode}" --scenario "${scenario}" --spec-version "${SPEC_VERSION}" >> "${log}" 2>&1 || true
    done
}

# An extension scenario is off the specification timeline, so the suite runs it
# only with --force. The suite's exit status is the verdict: every check passed.
run_client_auth() {
    local log="${LOGS}/suite-client-auth.log"
    local name="suite client: ${CLIENT_AUTH_SCENARIO}, the gateway fetches and attaches the token"
    if client_scenario gateway --scenario "${CLIENT_AUTH_SCENARIO}" --spec-version "${SPEC_VERSION}" --force > "${log}" 2>&1; then
        record PASS "${name}"
    else
        tail -40 "${log}"
        record FAIL "${name} (log: $(relative "${log}"))"
        FAILED=true
    fi
}

# The scenarios parity lets fail, as long as they fail the same way both ways.
client_may_fail() {
    local scenario names=()
    for scenario in "${CLIENT_SCENARIOS[@]}"; do
        [[ " ${CLIENT_MUST_PASS[*]} " == *" ${scenario} "* ]] || names+=("${scenario}")
    done
    (IFS=,; echo "${names[*]+"${names[*]}"}")
}

write_gaps() {
    local log="${LOGS}/gaps.log" line
    if ! node "${HERE}/suite-report.mjs" gaps --results "${RESULTS}" --targets "$(IFS=,; echo "${REPORT_TARGETS[*]}")" \
        --failed-dir "${REPORT_DIR}" --out "${GAPS_FILE}" > "${log}" 2>&1; then
        tail -5 "${log}"
        record FAIL "report: a target has no results (log: $(relative "${log}"))"
        FAILED=true
    fi
    while read -r line; do
        record INFO "report ${line}"
    done < <(grep -E '^[a-z-]+: [0-9]+ passed; ' "${log}" || true)
    record INFO "report: the open gaps are in $(relative "${GAPS_FILE}")"
}

run_client_suite() {
    require_free_ports client "${CLIENT_INBOUND_PORT}" "${CLIENT_OUTBOUND_PORT}"
    if [[ "${REPORT}" == true ]]; then
        report_run client "${LOGS}/suite-client-gateway.log" client client_scenario gateway
        return
    fi
    run_client_mode direct
    run_client_mode gateway
    check "suite client: ${#CLIENT_SCENARIOS[@]} scenarios, same result with and without the gateway; $(suite_counts client "${RESULTS}/client-gateway" --expected-scenarios "$(client_may_fail)")" \
        "${LOGS}/client-parity.log" \
        node "${HERE}/client-parity.mjs" --direct "${RESULTS}/client-direct" --gateway "${RESULTS}/client-gateway" \
        --scenarios "$(IFS=,; echo "${CLIENT_SCENARIOS[*]}")" --must-pass "$(IFS=,; echo "${CLIENT_MUST_PASS[*]}")"
    run_client_auth
}

# 1. Preflight. Apart from the lock, nothing under ${WORK} changes until this
# run holds it and every check has passed.
take_lock

# --skip-build uses the binary a build would write, so it is checked below like
# one passed in. While the binary is still unset, the first phase builds it.
if [[ "${SKIP_BUILD}" == true && -z "${BINARY}" ]]; then BINARY="${DEFAULT_BINARY}"; fi
NEED_CARGO=false
if [[ -z "${BINARY}" ]] || [[ "${RUN_MODERN}" == true && "${UNIT_TESTS}" == true ]]; then
    NEED_CARGO=true
fi
if selected fabric; then NEED_CARGO=true; fi
TOOLS=(node npm git openssl)
[[ "${NEED_CARGO}" == true ]] && TOOLS+=(cargo)
selected fabric && TOOLS+=(docker)
for tool in "${TOOLS[@]}"; do
    command -v "${tool}" > /dev/null 2>&1 || fail 2 "preflight: ${tool} is required"
done
if [[ "${NEED_CARGO}" == true && ( -n "${RUSTFLAGS:-}" || -n "${CARGO_ENCODED_RUSTFLAGS:-}" ) ]]; then
    fail 2 "preflight: unset RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS; Cargo would use them instead of the rustflags in .cargo/config.toml"
fi
node -e '
const [a, b, c] = process.versions.node.split(".").map(Number);
const [x, y, z] = process.argv[1].split(".").map(Number);
process.exit(a > x || (a === x && (b > y || (b === y && c >= z))) ? 0 : 1);
' "${NODE_MIN}" || fail 2 "preflight: node >= ${NODE_MIN} is required (found $(node --version))"
require_free_ports preflight "${REFERENCE_PORT}" "${FIXTURE_PORT}" "${SHIM_PORT}" "${MODERN_INBOUND_PORT}" "${MODERN_OUTBOUND_PORT}" \
    "${LEGACY_INBOUND_PORT}" "${LEGACY_OUTBOUND_PORT}" "${CLIENT_INBOUND_PORT}" "${CLIENT_OUTBOUND_PORT}"
[[ -z "${BINARY}" || ( -f "${BINARY}" && -x "${BINARY}" ) ]] || fail 2 "preflight: $(relative "${BINARY}") is not an executable file"
if selected fabric && ! docker info > /dev/null 2>&1; then
    fail 2 "preflight: the fabric target needs a running Docker daemon for its mediator"
fi
record PASS "preflight: node $(node --version), ports ${PORT_BASE}+ free"
if [[ "${UNIT_TESTS}" == true && "${RUN_MODERN}" != true ]]; then
    record WARN "unit tests: not run; --unit-tests needs a modern target in --only (${ONLY})"
fi
rm -rf "${RUN}"
mkdir -p "${LOGS}" "${RESULTS}" "${REPORT_DIR}"
RUN_CREATED=true

# 2. Pinned dependencies
npm_install harness "${HERE}"
CONFORMANCE="${HERE}/node_modules/.bin/conformance"
fetch_reference
npm_install reference-server "${REFERENCE_SERVER_DIR}"
# The reference client imports the suite's sources, so it needs the packages of
# the checkout's root; its `prepare` build is not needed to run it under tsx.
if [[ "${RUN_CLIENT}" == true ]]; then npm_install reference-client "${REFERENCE_DIR}" --ignore-scripts; fi

# 3. Fixtures
require_free_ports fixtures "${FIXTURE_PORT}" "${REFERENCE_PORT}" "${SHIM_PORT}"
start_process "${LOGS}/fixture.log" "${HERE}" node fixture.mjs --port "${FIXTURE_PORT}"
FIXTURE_PID="${STARTED_PID}"
start_process "${LOGS}/reference-server.log" "${REFERENCE_SERVER_DIR}" \
    env PORT="${REFERENCE_PORT}" node --import tsx everything-server.ts
REFERENCE_PID="${STARTED_PID}"
wait_for_ports "${FIXTURE_PID}" "${FIXTURE_PORT}" || fail 1 "fixtures: REST fixture did not start"
wait_for_ports "${REFERENCE_PID}" "${REFERENCE_PORT}" || fail 1 "fixtures: reference server did not start"
node --test "${HERE}/shim.test.mjs" "${HERE}/client-shim.test.mjs" "${HERE}/client-parity.test.mjs" \
    "${HERE}/client-auth.test.mjs" "${HERE}/suite-report.test.mjs" > "${LOGS}/shim-test.log" 2>&1 ||
    fail 1 "fixtures: harness unit tests failed (log: $(relative "${LOGS}/shim-test.log"))"
start_process "${LOGS}/shim.log" "${HERE}" node shim.mjs --port "${SHIM_PORT}" \
    --upstream "http://127.0.0.1:${REFERENCE_PORT}"
SHIM_PID="${STARTED_PID}"
wait_for_ports "${SHIM_PID}" "${SHIM_PORT}" || fail 1 "fixtures: upstream shim did not start"
record PASS "fixtures: reference server :${REFERENCE_PORT}, upstream shim :${SHIM_PORT}, REST fixture :${FIXTURE_PORT}"

# 4. Modern phase
if [[ "${RUN_MODERN}" == true ]]; then
    if [[ -z "${BINARY}" ]]; then
        BINARY="${DEFAULT_BINARY}"
        build_step "modern: build" "${LOGS}/build.log" gateway_cargo build
    fi
    if [[ "${UNIT_TESTS}" == true ]]; then
        test_step "modern: cargo test --bin ${BIN_NAME}" "${LOGS}/unit-tests.log" gateway_cargo test
    fi

    start_gateway modern "${BINARY}" "${MODERN_INBOUND_PORT}" "${MODERN_OUTBOUND_PORT}"
    probe_log="${LOGS}/compat-probe.log"
    set +e
    node "${HERE}/compat.mjs" probe --targets "${TARGETS_FILE}" > "${probe_log}" 2>&1
    probe_status=$?
    set -e
    cat "${probe_log}"
    case "${probe_status}" in
        0) record PASS "modern: probe admits ${SPEC_VERSION}" ;;
        2) fail 2 "modern: the binary does not admit ${SPEC_VERSION} (probe got -32022)" ;;
        *) fail 1 "modern: probe failed (log: $(relative "${probe_log}"))" ;;
    esac

    for name in "${MODERN_TARGETS[@]}"; do
        url="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))[process.argv[2]])' "${TARGETS_FILE}" "${name}")"
        case "${name}" in
            direct) run_suite direct "${url}" direct ;;
            access-point|transit) run_suite "${name}" "${url}" forwarding ;;
            owned-proxy|proxy-surface) run_owned_suite "${name}" "${url}" ;;
            fabric) run_fabric_suite ;;
        esac
    done

    if [[ "${REPORT}" != true ]]; then
        targets_csv="$(IFS=,; echo "${MODERN_TARGETS[*]}")"
        owned_csv="$(IFS=,; echo "${OWNED_SCENARIOS[*]}")"
        check "modern: check-results (caching parity, real owned calls, results present)" "${LOGS}/check-results.log" \
            node "${HERE}/check-results.mjs" --results "${RESULTS}" --targets "${targets_csv}" \
            --owned-scenarios "${owned_csv}" --requirements "${REQUIREMENTS_FILE}"
        check "modern: compat admitted (every endpoint admits ${SPEC_VERSION})" "${LOGS}/compat-admitted-modern.log" \
            node "${HERE}/compat.mjs" admitted --targets "${TARGETS_FILE}"
        check "modern: compat legacy session (2024-11-05)" "${LOGS}/compat-legacy-modern.log" \
            node "${HERE}/compat.mjs" legacy --targets "${TARGETS_FILE}"
    fi
    stop_gateway
fi

# 5. Client phase: the gateway as the MCP client of the suite's own server
if [[ "${RUN_CLIENT}" == true ]]; then
    if [[ -z "${BINARY}" ]]; then
        BINARY="${DEFAULT_BINARY}"
        build_step "client: build" "${LOGS}/build.log" gateway_cargo build
    fi
    run_client_suite
fi

# 6. Legacy phase: the legacy regression checks on their own gateway
if [[ "${RUN_LEGACY}" == true ]]; then
    if [[ -z "${BINARY}" ]]; then
        BINARY="${DEFAULT_BINARY}"
        build_step "legacy: build" "${LOGS}/build.log" gateway_cargo build
    fi
    start_gateway legacy "${BINARY}" "${LEGACY_INBOUND_PORT}" "${LEGACY_OUTBOUND_PORT}"
    check "legacy: compat rejected (every endpoint -32022 for 2099-01-01)" "${LOGS}/compat-rejected-legacy.log" \
        node "${HERE}/compat.mjs" rejected --targets "${TARGETS_FILE}"
    check "legacy: compat legacy session (2024-11-05)" "${LOGS}/compat-legacy-legacy.log" \
        node "${HERE}/compat.mjs" legacy --targets "${TARGETS_FILE}"
    stop_gateway
fi

if [[ "${REPORT}" == true && ${#REPORT_TARGETS[@]} -gt 0 ]]; then write_gaps; fi

[[ "${FAILED}" == true ]] && exit 1
exit 0
