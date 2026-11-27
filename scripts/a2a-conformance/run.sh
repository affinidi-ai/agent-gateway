#!/usr/bin/env bash
#
# Run the A2A conformance suite (the A2A TCK) against the suite's own test
# agent directly and through Agent Trust Gateway, then score each gateway
# target on how it differs from the direct run. See
# scripts/a2a-conformance/README.md.
#
# Exit codes: 0 pass, 1 failure, 2 invalid options or precondition not met,
# 3 dependency fetch failed, 129 SIGHUP, 130 SIGINT, 143 SIGTERM.

set -euo pipefail
unset CDPATH

# The caller's environment must not change what is tested. A proxy would take
# the loopback traffic of the suite, the probes and the gateway, so loopback is
# exempt; fetches still use the proxy. Tools differ in which spelling they
# read, so both carry the entries of both. "*" exempts every host, but for pip
# and git only as the whole value, so it is kept as it is.
if [[ "${no_proxy:-}" == "*" || "${NO_PROXY:-}" == "*" ]]; then
    no_proxy="*"
else
    no_proxy="${no_proxy:+${no_proxy},}${NO_PROXY:+${NO_PROXY},}127.0.0.1,localhost"
fi
NO_PROXY="${no_proxy}"
export NO_PROXY no_proxy
# Python settings of the caller would reach every interpreter the run starts:
# PYTHONPATH puts other packages in front of the pinned ones, and
# PYTHONSAFEPATH takes the suite's checkout off the import path.
unset "${!PYTHON@}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
WORK="${REPO}/target/a2a-conformance"
LOCK="${WORK}/.lock"
LOCK_CLEARING="${WORK}/.lock-clearing"

TCK_REPO="${A2A_CONFORMANCE_TCK_REPO:-https://github.com/a2aproject/a2a-tck.git}"
UV_VERSION="0.13.10"
TOOLS_VENV="${WORK}/tools-venv"
BIN_NAME="$(sed -n 's/^name = "\(.*\)"/\1/p' "${REPO}/Cargo.toml" | head -1)"
DEFAULT_BINARY="${REPO}/target/debug/${BIN_NAME}"
GATEWAY_TARGETS=(access-point access-point-full transit a2a-proxy)
# Targets that are agents themselves: scored on their own failures, not against the direct run.
AGENT_TARGETS=(a2a-proxy)
PORT_BASE="${A2A_CONFORMANCE_PORT_BASE:-18860}"

usage() {
    cat <<EOF
Usage: scripts/a2a-conformance/run.sh [options]

  --a2a-version VERSION   Suite to run: 1.0 (default) or 0.3
  --skip-build            Use the existing gateway binary instead of building it
  --binary PATH           Gateway binary to test
  --only LIST             Comma-separated, non-empty subset of:
                          access-point,access-point-full,transit,a2a-proxy
                          (the direct run always happens: the forwarding targets are scored against it)
  --report                Write every difference to gaps.md in the run directory
                          and exit 0 whatever the baselines say
  -h, --help              Show this help

Environment:
  A2A_CONFORMANCE_PORT_BASE      First of the local ports used (default 18860)
  A2A_CONFORMANCE_TCK_REPO       Git URL or mirror of a2aproject/a2a-tck
  A2A_CONFORMANCE_PYTHON         Python 3.15 or later, for the 1.0 suite; the only one tried when set
  A2A_CONFORMANCE_LEGACY_PYTHON  Python 3.13 or 3.14, for the 0.3 suite; the only one tried when set
EOF
}

option_value() {
    if [[ -z "${2:-}" ]]; then
        echo "$1 needs a value" >&2
        usage >&2
        exit 2
    fi
}

A2A_VERSION="1.0"
SKIP_BUILD=false
REPORT=false
BINARY=""
ONLY="access-point,access-point-full,transit,a2a-proxy"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --a2a-version) option_value "$1" "${2:-}"; A2A_VERSION="$2"; shift ;;
        --skip-build) SKIP_BUILD=true ;;
        --report) REPORT=true ;;
        --binary) option_value "$1" "${2:-}"; BINARY="$2"; shift ;;
        --only) option_value "$1" "${2:-}"; ONLY="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# Everything that differs between the two suites. The 0.3 suite is the TCK's
# 0.3.x branch: other tests, another test agent, an older Python, and no
# lockfile, so its packages are pinned here.
case "${A2A_VERSION}" in
    1.0)
        TCK_SHA="5e6f37c2d38eb3d7684686243c34d365c83df49b"
        TCK_DIR="${WORK}/tck"
        SUITE_VENV="${TCK_DIR}/.venv"
        SUITE_PYTHON="${SUITE_VENV}/bin/python"
        PYTHON_MIN="3.15"
        PYTHON_BELOW=""
        PYTHON_OVERRIDE_NAME="A2A_CONFORMANCE_PYTHON"
        PYTHON_CANDIDATES=(python3.15 python3)
        AGENT_VENV="${WORK}/agent-venv"
        AGENT_REQUIREMENTS="${HERE}/agent-requirements.txt"
        AGENT_DESCRIPTION="the suite's generated a2a-python agent"
        ACCEPTED_VERSIONS="1.0"
        RUN="${WORK}/run"
        ENV_DIR="${WORK}/env"
        PORT_OFFSET=0
        ;;
    0.3)
        TCK_SHA="917352a0f63e8c1ed728507e7d2e0d0f8d291b04"
        TCK_DIR="${WORK}/tck-0.3"
        SUITE_VENV="${WORK}/suite-venv-0.3"
        SUITE_PYTHON="${SUITE_VENV}/bin/python"
        SUITE_REQUIREMENTS="${HERE}/legacy-suite-requirements.txt"
        PYTHON_MIN="3.13"
        PYTHON_BELOW="3.15"
        PYTHON_OVERRIDE_NAME="A2A_CONFORMANCE_LEGACY_PYTHON"
        PYTHON_CANDIDATES=(python3.14 python3.13 python3)
        AGENT_VENV="${WORK}/agent-venv-0.3"
        AGENT_REQUIREMENTS="${HERE}/legacy-agent-requirements.txt"
        AGENT_DESCRIPTION="the suite's bundled tck_core_agent"
        ACCEPTED_VERSIONS="0.3,1.0"
        RUN="${WORK}/run-0.3"
        ENV_DIR="${WORK}/env-0.3"
        PORT_OFFSET=20
        ;;
    *) echo "--a2a-version must be 1.0 or 0.3" >&2; exit 2 ;;
esac
PYTHON_OVERRIDE="${!PYTHON_OVERRIDE_NAME:-}"
LOGS="${RUN}/logs"
RESULTS="${RUN}/results"
EXPECTED="${HERE}/expected/${A2A_VERSION}"
AGENT_PORT=$((PORT_BASE + PORT_OFFSET))
AGENT_GRPC_PORT=$((PORT_BASE + PORT_OFFSET + 1))
DIRECT_LINE_PORT=$((PORT_BASE + PORT_OFFSET + 2))
INBOUND_PORT=$((PORT_BASE + PORT_OFFSET + 10))
OUTBOUND_PORT=$((PORT_BASE + PORT_OFFSET + 11))
PORTS=("${AGENT_PORT}" "${DIRECT_LINE_PORT}" "${INBOUND_PORT}" "${OUTBOUND_PORT}")
[[ "${A2A_VERSION}" == "1.0" ]] && PORTS+=("${AGENT_GRPC_PORT}")

selected() { [[ ",${ONLY}," == *",$1,"* ]]; }

IFS=, read -r -a ONLY_ITEMS <<< "${ONLY}"
for name in "${ONLY_ITEMS[@]+"${ONLY_ITEMS[@]}"}"; do
    case "${name}" in
        access-point|access-point-full|transit|a2a-proxy) ;;
        *) echo "Unknown --only entry: '${name}'" >&2; exit 2 ;;
    esac
done

TARGETS=()
for name in "${GATEWAY_TARGETS[@]}"; do
    if selected "${name}"; then TARGETS+=("${name}"); fi
done
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "--only selects no target: '${ONLY}'" >&2
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

# Signal a PID only while it is a running child of this shell. Once the shell
# has reaped a child, the OS can hand its PID to a process the harness did not
# start.
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

# Runs share everything under ${WORK}, whatever their port base or suite, so
# only one runs at a time. The lock is a symlink naming the holder's PID:
# creating it is atomic, so a lock never exists without its PID.
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
    local holder
    mkdir -p "${WORK}"
    # ln would create its link inside a real directory instead of failing.
    if [[ -e "${LOCK}" && ! -L "${LOCK}" ]]; then
        fail 2 "preflight: $(relative "${LOCK}") is not a lock this harness created; remove it"
    fi
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if ln -sn "$$" "${LOCK}" 2>/dev/null; then
            OWN_LOCK=true
            return
        fi
        holder="$(lock_holder)"
        if lock_holder_running "${holder}"; then
            fail 2 "preflight: another a2a-conformance run (PID ${holder}) is in progress; wait for it to finish"
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
    echo "A2A conformance harness"
    echo "suite: a2a-tck @ ${TCK_SHA}, A2A ${A2A_VERSION}, JSON-RPC binding"
    echo "test agent: ${AGENT_DESCRIPTION} ($(grep -m1 '^a2a-sdk==' "${AGENT_REQUIREMENTS}"))"
    echo "targets: direct,${ONLY}"
    echo
    printf '%s\n' "${SUMMARY[@]+"${SUMMARY[@]}"}"
    echo
    case "$1" in
        0) echo "RESULT: PASS (exit 0)" ;;
        2) echo "RESULT: PRECONDITION NOT MET (exit 2)" ;;
        3) echo "RESULT: DEPENDENCY FETCH FAILED (exit 3)" ;;
        *) echo "RESULT: FAIL (exit $1)" ;;
    esac
}

cleanup() {
    local code=$?
    local pid
    # A second signal must not cut the cleanup short and leave processes on the
    # ports, and neither may a failed write: after a hangup the terminal is gone.
    trap '' HUP INT TERM
    set +e
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
trap 'exit 129' HUP
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
            fail 2 "${step}: port ${port} is already in use; free it or set A2A_CONFORMANCE_PORT_BASE"
        fi
    done
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

start_process() {
    local log="$1"
    shift
    "$@" > "${log}" 2>&1 &
    STARTED_PID=$!
    STARTED_PIDS+=("${STARTED_PID}")
}

python_in_range() {
    "$1" -c '
import sys
version = sys.version_info[:2]
low = tuple(map(int, sys.argv[1].split(".")))
below = tuple(map(int, sys.argv[2].split("."))) if sys.argv[2] else (99,)
sys.exit(0 if low <= version < below else 1)' "${PYTHON_MIN}" "${PYTHON_BELOW}" 2>/dev/null
}

# An interpreter the caller names is the only one tried: falling back to
# another would run the suite on a Python the caller did not choose.
find_python() {
    local candidate candidates=("${PYTHON_CANDIDATES[@]}")
    [[ -z "${PYTHON_OVERRIDE}" ]] || candidates=("${PYTHON_OVERRIDE}")
    for candidate in "${candidates[@]}"; do
        if command -v "${candidate}" > /dev/null 2>&1 && python_in_range "${candidate}"; then
            PYTHON="$(command -v "${candidate}")"
            return 0
        fi
    done
    return 1
}

# What pip and uv print when the network is the cause. A version the index
# does not have is not one of them: pip reports that as "No matching
# distribution", and uv reports a build requirement it cannot meet as "Failed
# to resolve", with and without a network. Nor is a build that fails: its log
# names source files such as timeout_encoding.cc, so only whole phrases about
# a timeout count. pip words an index that answers 5xx like a missing version,
# so that outage is reported as a failure (1), not as a fetch failure.
FETCH_FAILURE='could not resolve|nodename nor servname|name or service not known|temporary failure|dns error'
FETCH_FAILURE+='|failed to (fetch|download|establish a new connection)|connection (refused|reset|broken)'
FETCH_FAILURE+='|network is unreachable|timed out|(read|connect)timeout|HTTP error 5[0-9][0-9]'

# A fetch failure has its own exit code (3), so a caller can tell an outage
# from a broken harness. The step runs as an `if` condition, where `set -e` is
# off, so each step function chains its commands with `&&`.
install_step() {
    local name="$1" log="${LOGS}/install-${1%% *}.log"
    shift
    if "$@" > "${log}" 2>&1; then
        record PASS "dependencies: ${name}"
        return
    fi
    tail -20 "${log}" >&2
    if grep -Eiq "${FETCH_FAILURE}" "${log}"; then
        fail 3 "dependencies: ${name} could not be fetched (log: $(relative "${log}"))"
    fi
    fail 1 "dependencies: ${name} failed (log: $(relative "${log}"))"
}

tck_git() {
    GIT_TERMINAL_PROMPT=0 git -c core.hooksPath=/dev/null -c advice.detachedHead=false \
        --git-dir="${TCK_DIR}/.git" --work-tree="${TCK_DIR}" "$@"
}

fetch_tck() {
    local log="${LOGS}/tck-fetch.log"
    if [[ "$(tck_git rev-parse -q --verify 'HEAD^{commit}' 2>/dev/null || true)" != "${TCK_SHA}" ]]; then
        rm -rf "${TCK_DIR}"
        mkdir -p "${TCK_DIR}"
        {
            tck_git init -q &&
                tck_git remote add origin "${TCK_REPO}"
        } > "${log}" 2>&1 || fail 1 "dependencies: could not initialise the suite checkout"
        if ! tck_git fetch -q --depth 1 origin "${TCK_SHA}" >> "${log}" 2>&1; then
            cat "${log}" >&2
            rm -rf "${TCK_DIR}"
            fail 3 "dependencies: could not fetch the suite ${TCK_SHA} from ${TCK_REPO}"
        fi
        tck_git checkout -q --detach "${TCK_SHA}" >> "${log}" 2>&1 ||
            fail 1 "dependencies: could not check out the suite ${TCK_SHA}"
    fi
    [[ "$(tck_git rev-parse HEAD)" == "${TCK_SHA}" ]] ||
        fail 1 "dependencies: suite checkout is not at ${TCK_SHA}"
    # Nothing a previous run or a person left in the checkout may change what the suite does.
    { tck_git reset -q --hard "${TCK_SHA}" && tck_git clean -qffdx -e .venv; } ||
        fail 1 "dependencies: could not restore the suite checkout to ${TCK_SHA}"
    record PASS "dependencies: suite a2a-tck ${TCK_SHA}"
}

# A virtual environment holding exactly the pinned packages of a requirements
# file, built with the chosen interpreter. It is rebuilt when the file or the
# interpreter changes, or when its own interpreter no longer runs, and reused
# otherwise.
pinned_venv() {
    local venv="$1" requirements="$2" stamp="$1/.requirements" wanted
    wanted="$(cat "${requirements}" && "${PYTHON}" -c 'import sys; print("# built with", sys.version.split()[0], sys.executable)')" ||
        return 1
    if "${venv}/bin/python" -c '' 2>/dev/null && [[ "$(cat "${stamp}" 2>/dev/null)" == "${wanted}" ]]; then return; fi
    rm -rf "${venv}" &&
        "${PYTHON}" -m venv "${venv}" &&
        "${venv}/bin/pip" install --disable-pip-version-check --quiet --requirement "${requirements}" &&
        printf '%s\n' "${wanted}" > "${stamp}"
}

# The 1.0 suite pins its packages in uv.lock, so uv installs them. uv itself is
# pinned and lives in a virtual environment under ${WORK}; nothing is installed
# outside it. The suite project itself is not installed: pytest runs from its
# checkout, and installing it would run a build backend the lock does not pin.
# The project and its environment are named here, so a UV_PROJECT or
# UV_PROJECT_ENVIRONMENT of the caller cannot send the install elsewhere.
install_uv() {
    if [[ "$("${TOOLS_VENV}/bin/uv" --version 2>/dev/null || true)" == "uv ${UV_VERSION}"* ]]; then return; fi
    rm -rf "${TOOLS_VENV}" &&
        "${PYTHON}" -m venv "${TOOLS_VENV}" &&
        "${TOOLS_VENV}/bin/pip" install --disable-pip-version-check --quiet "uv==${UV_VERSION}"
}

install_locked_suite() {
    UV_PROJECT_ENVIRONMENT="${SUITE_VENV}" "${TOOLS_VENV}/bin/uv" sync --project "${TCK_DIR}" \
        --frozen --no-dev --no-install-project --python "${PYTHON}"
}

install_suite() {
    if [[ "${A2A_VERSION}" == "1.0" ]]; then
        install_step "uv ${UV_VERSION}" install_uv
        install_step "suite packages (uv.lock)" install_locked_suite
    else
        install_step "suite packages ($(basename "${SUITE_REQUIREMENTS}"))" pinned_venv "${SUITE_VENV}" "${SUITE_REQUIREMENTS}"
    fi
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

# Both launchers start the suite's own test agent unchanged, on loopback only.
start_agent() {
    local ports=("${AGENT_PORT}")
    if [[ "${A2A_VERSION}" == "1.0" ]]; then
        ports+=("${AGENT_GRPC_PORT}")
        require_free_ports "test agent" "${ports[@]}"
        start_process "${LOGS}/agent.log" env SUT_HOST="127.0.0.1:${AGENT_PORT}" GRPC_PORT="${AGENT_GRPC_PORT}" \
            "${AGENT_VENV}/bin/python" "${HERE}/agent.py" "${TCK_DIR}/sut/a2a-python/sut_agent.py"
    else
        require_free_ports "test agent" "${ports[@]}"
        start_process "${LOGS}/agent.log" env SUT_HOST="127.0.0.1:${AGENT_PORT}" \
            "${AGENT_VENV}/bin/python" "${HERE}/agent_legacy.py" "${TCK_DIR}/python-sut/tck_core_agent"
    fi
    if ! wait_for_ports "${STARTED_PID}" "${ports[@]}"; then
        tail -40 "${LOGS}/agent.log" >&2
        fail 1 "test agent did not start (log: $(relative "${LOGS}/agent.log"))"
    fi
    record PASS "test agent: ports ${ports[*]} (loopback only)"
}

start_direct_line() {
    require_free_ports "Direct Line stand-in" "${DIRECT_LINE_PORT}"
    start_process "${LOGS}/directline.log" "${PYTHON}" "${HERE}/directline.py" --port "${DIRECT_LINE_PORT}"
    wait_for_ports "${STARTED_PID}" "${DIRECT_LINE_PORT}" ||
        fail 1 "Direct Line stand-in did not start (log: $(relative "${LOGS}/directline.log"))"
    record PASS "Direct Line stand-in: port ${DIRECT_LINE_PORT} (loopback only)"
}

# Listening ports are not enough: the gateway reports ready on its health
# endpoint once its stores and surfaces are loaded.
gateway_healthy() {
    "${PYTHON}" -c '
import sys, urllib.request
sys.exit(0 if urllib.request.urlopen(sys.argv[1], timeout=2).status == 200 else 1)' \
        "http://127.0.0.1:${INBOUND_PORT}/api/v1/health" 2>/dev/null
}

wait_for_gateway() {
    local deadline=$((SECONDS + 60))
    wait_for_ports "${GATEWAY_PID}" "${INBOUND_PORT}" "${OUTBOUND_PORT}" || return 1
    until gateway_healthy; do
        running_child "${GATEWAY_PID}" || return 1
        [[ ${SECONDS} -lt ${deadline} ]] || return 1
        sleep 0.5
    done
}

start_gateway() {
    "${PYTHON}" "${HERE}/env.py" --dir "${ENV_DIR}" --binary "${BINARY}" \
        --inbound-port "${INBOUND_PORT}" --outbound-port "${OUTBOUND_PORT}" \
        --agent-url "http://127.0.0.1:${AGENT_PORT}" --accepted-versions "${ACCEPTED_VERSIONS}" \
        --direct-line-url "http://127.0.0.1:${DIRECT_LINE_PORT}/v3/directline" \
        > "${LOGS}/env.log" 2>&1 ||
        fail 1 "gateway: could not write the env (log: $(relative "${LOGS}/env.log"))"
    require_free_ports gateway "${INBOUND_PORT}" "${OUTBOUND_PORT}"
    (
        cd "${ENV_DIR}/config"
        export "$(cat "${ENV_DIR}/backup-key-var")=$(openssl rand -hex 32)"
        export RUST_LOG="${RUST_LOG:-info}"
        # The A2A proxy refuses a loopback backend unless this development switch
        # is set. Test mode is not needed, and one inherited from the caller's
        # shell would let other test switches change the gateway under test.
        unset AG_TEST_MODE
        export AG_ALLOW_LOCAL_A2A_PROXY=true
        exec "${BINARY}" --config config.toml
    ) > "${LOGS}/gateway.log" 2>&1 &
    GATEWAY_PID=$!
    STARTED_PIDS+=("${GATEWAY_PID}")
    if ! wait_for_gateway; then
        tail -40 "${LOGS}/gateway.log" >&2
        fail 1 "gateway did not start (log: $(relative "${LOGS}/gateway.log"))"
    fi
    record PASS "gateway started ($(relative "${BINARY}")), accepting A2A ${ACCEPTED_VERSIONS}"
    TARGETS_FILE="${ENV_DIR}/targets.json"
}

target_url() {
    "${PYTHON}" -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "${TARGETS_FILE}" "$1"
}

# One pytest invocation of the suite, from its checkout, with the harness
# plugins on the path. pytest exits 0 when every test passed and 1 when some
# failed; both leave a complete JUnit report, which check_results.py scores.
# The 1.0 suite's pytest also exits 1 when it stops before collecting (a plugin
# that does not import), and then writes no report, so the report is required
# as well. Anything else means the suite did not run to the end.
suite_pytest() {
    local log="$1" junit="$2" status=0
    shift 2
    (cd "${TCK_DIR}" && PYTHONPATH="${HERE}/plugins" "${SUITE_PYTHON}" -m pytest -p no:cacheprovider -p tck_loopback \
        --tb=short -q "--junitxml=${junit}" "$@") >> "${log}" 2>&1 || status=$?
    [[ ${status} -le 1 && -s "${junit}" ]]
}

# The 1.0 suite, as its run_tck.py runs it, on the JSON-RPC binding.
run_modern_suite() {
    local url="$1" log="$2" out="$3"
    shift 3
    suite_pytest "${log}" "${out}/junitreport.xml" tests/compatibility/ -p tck_plugin "--sut-host=${url}" \
        --transport=jsonrpc "--compatibility-report=${out}/compatibility" "--html=${out}/tck_report.html" \
        --self-contained-html "$@"
}

# The 0.3 suite's two categories that decide compliance, as its run_tck.py
# runs them: mandatory, then capabilities.
run_legacy_suite() {
    local url="$1" log="$2" out="$3"
    local common=(-p tck_plugin_legacy "--sut-url=${url}" --test-scope=all --transport-strategy prefer_jsonrpc --transports jsonrpc)
    suite_pytest "${log}" "${out}/junit-mandatory.xml" tests/mandatory/ \
        -m "mandatory_jsonrpc or mandatory_protocol" "${common[@]}" &&
        suite_pytest "${log}" "${out}/junit-capabilities.xml" tests/optional/capabilities/ "${common[@]}"
}

run_suite() {
    local name="$1" url="$2" log="${LOGS}/suite-${1}.log" out="${RESULTS}/${1}" ran=true
    shift 2
    mkdir -p "${out}"
    : > "${log}"
    if [[ "${A2A_VERSION}" == "1.0" ]]; then
        run_modern_suite "${url}" "${log}" "${out}" "$@" || ran=false
    else
        run_legacy_suite "${url}" "${log}" "${out}" || ran=false
    fi
    if [[ "${ran}" != true ]]; then
        tail -40 "${log}"
        record FAIL "suite ${name}: the suite did not run to the end (log: $(relative "${log}"))"
        FAILED=true
        return
    fi
    if ! "${SUITE_PYTHON}" "${HERE}/probes.py" --a2a-version "${A2A_VERSION}" --url "${url}" --out "${out}/probes.json" \
        > "${LOGS}/probes-${name}.log" 2>&1; then
        tail -20 "${LOGS}/probes-${name}.log"
        record FAIL "suite ${name}: probes did not run (log: $(relative "${LOGS}/probes-${name}.log"))"
        FAILED=true
        return
    fi
    record PASS "suite ${name}: ran"
}

# 1. Preflight. Apart from the lock, nothing under ${WORK} changes until this
# run holds it and every check has passed.
take_lock

if [[ "${SKIP_BUILD}" == true && -z "${BINARY}" ]]; then BINARY="${DEFAULT_BINARY}"; fi
TOOLS=(git openssl)
[[ -n "${BINARY}" ]] || TOOLS+=(cargo)
for tool in "${TOOLS[@]}"; do
    command -v "${tool}" > /dev/null 2>&1 || fail 2 "preflight: ${tool} is required"
done
PYTHON_NEEDED="Python >= ${PYTHON_MIN}${PYTHON_BELOW:+ and < ${PYTHON_BELOW}}"
if ! find_python; then
    [[ -z "${PYTHON_OVERRIDE}" ]] ||
        fail 2 "preflight: ${PYTHON_OVERRIDE_NAME}=${PYTHON_OVERRIDE} is not ${PYTHON_NEEDED}, which the A2A ${A2A_VERSION} suite needs"
    fail 2 "preflight: the A2A ${A2A_VERSION} suite needs ${PYTHON_NEEDED}; set ${PYTHON_OVERRIDE_NAME} to one"
fi
if [[ -z "${BINARY}" && ( -n "${RUSTFLAGS:-}" || -n "${CARGO_ENCODED_RUSTFLAGS:-}" ) ]]; then
    fail 2 "preflight: unset RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS; Cargo would use them instead of the rustflags in .cargo/config.toml"
fi
require_free_ports preflight "${PORTS[@]}"
[[ -z "${BINARY}" || ( -f "${BINARY}" && -x "${BINARY}" ) ]] || fail 2 "preflight: $(relative "${BINARY}") is not an executable file"
record PASS "preflight: $("${PYTHON}" --version), ports ${AGENT_PORT}-${OUTBOUND_PORT} free"
rm -rf "${RUN}"
mkdir -p "${LOGS}" "${RESULTS}"
RUN_CREATED=true

# 2. Harness self-tests: the scoring has to be right before it scores anything.
if "${PYTHON}" -m unittest discover -s "${HERE}" -p 'test_*.py' > "${LOGS}/self-test.log" 2>&1; then
    record PASS "self-test: $(grep -E '^Ran ' "${LOGS}/self-test.log")"
else
    tail -40 "${LOGS}/self-test.log" >&2
    fail 1 "self-test failed (log: $(relative "${LOGS}/self-test.log"))"
fi

# 3. Pinned dependencies
fetch_tck
install_suite
install_step "test agent packages ($(basename "${AGENT_REQUIREMENTS}"))" pinned_venv "${AGENT_VENV}" "${AGENT_REQUIREMENTS}"

# 4. Direct run: the reference the forwarding targets are scored against
start_agent
run_suite direct "http://127.0.0.1:${AGENT_PORT}"
[[ "${FAILED}" == true ]] && exit 1

# 5. Gateway targets
if [[ -z "${BINARY}" ]]; then
    BINARY="${DEFAULT_BINARY}"
    build_step "gateway: build" "${LOGS}/build.log" gateway_cargo build
fi
selected a2a-proxy && start_direct_line
start_gateway
for name in "${TARGETS[@]}"; do
    case "${name}-${A2A_VERSION}" in
        # The 1.0 suite adds a trailing slash a Transit Point refuses; the probe
        # entry_point::accepts_trailing_slash reports that on its own.
        transit-1.0) run_suite transit "$(target_url transit)" --strip-trailing-slash ;;
        *) run_suite "${name}" "$(target_url "${name}")" ;;
    esac
done
stop_pid "${GATEWAY_PID}"

# 6. Score
targets_csv="direct,$(IFS=,; echo "${TARGETS[*]}")"
agents_csv="$(IFS=,; echo "${AGENT_TARGETS[*]}")"
score_args=(--results "${RESULTS}" --expected "${EXPECTED}" --targets "${targets_csv}" --agents "${agents_csv}")
[[ "${REPORT}" == true ]] && score_args+=(--report "${RUN}/gaps.md")
score_log="${LOGS}/check-results.log"
if "${PYTHON}" "${HERE}/check_results.py" "${score_args[@]}" > "${score_log}" 2>&1; then
    score_ok=true
else
    score_ok=false
fi
# Each target's verdict goes into the summary; the lines under a verdict name
# the tests behind it. In report mode a FAIL verdict is recorded as a gap.
while IFS= read -r line; do
    case "${line}" in
        PASS\ \ *) record PASS "score ${line#PASS  }" ;;
        FAIL\ \ *)
            if [[ "${REPORT}" == true ]]; then
                record GAP "score ${line#FAIL  }"
            else
                record FAIL "score ${line#FAIL  }"
            fi
            ;;
        *) SUMMARY+=("${line}"); echo "${line}" ;;
    esac
done < "${score_log}"
[[ "${score_ok}" == true ]] || FAILED=true

[[ "${FAILED}" == true ]] && exit 1
exit 0
