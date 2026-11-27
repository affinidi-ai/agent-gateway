#!/usr/bin/env bash
# Tests for parallel.sh, the runner behind `make local` and `make ci-happy-*`:
# a fake make stands in for every group, so each case checks the runner's exit
# status, its as-it-ends lines and its summary without running a real build.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARALLEL_SH="${HERE}/parallel.sh"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT
export PARALLEL_SH

# Each target it is given: ok passes, fail fails, slow passes after 3 seconds,
# die kills the runner's subshell before it can record a status, and
# nested-ok / nested-fail run parallel.sh again with two groups of their own.
FAKE_MAKE="${TEMP_DIR}/fake-make"
cat >"${FAKE_MAKE}" <<'EOF'
#!/usr/bin/env bash
set -u
for target in "$@"; do
    case "$target" in
        -*) ;;
        ok) echo "ok done" ;;
        fail) echo "fail done" >&2; exit 2 ;;
        slow) echo "slow working"; sleep 3; echo "slow done" ;;
        die) kill -9 "$PPID"; sleep 1 ;;
        nested-ok) bash "$PARALLEL_SH" "Inner" "inner-a=ok" "inner-b=ok" || exit 1 ;;
        nested-fail) bash "$PARALLEL_SH" "Inner" "inner-a=ok" "inner-b=fail" || exit 1 ;;
        *) echo "fake-make: unknown target $target" >&2; exit 99 ;;
    esac
done
EOF
chmod +x "${FAKE_MAKE}"

failures=0

fail() {
    echo "❌ $1" >&2
    failures=$((failures + 1))
}

# Runs parallel.sh in a folder of its own, so its tmp/local/ run folders stay
# apart, and gives up on it after 30 seconds: a runner that never ends is a
# failure, not a hung test.
run_case() { # name, expected exit status, groups...
    local name=$1 want=$2 dir="${TEMP_DIR}/$1" rc=0 waited=0 pid
    shift 2
    mkdir -p "${dir}"
    (
        cd "${dir}" &&
            MAKE="${FAKE_MAKE}" exec bash "${PARALLEL_SH}" "${name}" "$@"
    ) >"${dir}/out.txt" 2>&1 </dev/null &
    pid=$!
    while kill -0 "${pid}" 2>/dev/null; do
        if [ "${waited}" -ge 30 ]; then
            kill -TERM "${pid}" 2>/dev/null || true
            fail "${name}: still running after 30 seconds"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    wait "${pid}" || rc=$?
    [ "${rc}" = "${want}" ] || fail "${name}: exit status ${rc}, expected ${want}"
}

expect() { # name, file under the case folder, text that must appear in it
    local file="${TEMP_DIR}/$1/$2"
    grep -qF -- "$3" "${file}" 2>/dev/null || fail "$1: '$3' not in $2"
}

expect_not() { # name, file under the case folder, text that must not appear
    local file="${TEMP_DIR}/$1/$2"
    if grep -qF -- "$3" "${file}" 2>/dev/null; then fail "$1: '$3' in $2"; fi
}

export PROGRESS_SECS=0

PARALLEL=1 run_case parallel-ok 0 "a=ok" "b=ok"
expect parallel-ok out.txt "· ✅ a ("
expect parallel-ok out.txt "· ✅ b ("
expect parallel-ok out.txt "■ parallel-ok"
expect_not parallel-ok out.txt "❌"

PARALLEL=1 run_case parallel-fail 1 "a=ok" "b=fail"
expect parallel-fail out.txt "· ✅ a ("
expect parallel-fail out.txt "· ❌ b ("
expect parallel-fail out.txt "fail done"

PARALLEL=0 run_case serial-ok 0 "a=ok" "b=ok"
expect serial-ok out.txt "· ✅ a ("
expect serial-ok out.txt "· ✅ b ("

PARALLEL=0 run_case serial-fail 1 "a=fail" "b=ok"
expect serial-fail out.txt "· ❌ a ("
expect serial-fail out.txt "· ✅ b ("

PARALLEL=1 run_case nested-ok 0 "outer=nested-ok"
expect nested-ok out.txt "· ✅ outer ("
expect nested-ok tmp/local/latest/outer.log "✅ inner-a ("
expect nested-ok tmp/local/latest/outer.log "✅ inner-b ("

PARALLEL=1 run_case nested-fail 1 "outer=nested-fail"
expect nested-fail out.txt "· ❌ outer ("
expect nested-fail tmp/local/latest/outer.log "❌ inner-b ("

PARALLEL=0 run_case nested-serial-fail 1 "outer=nested-fail"
expect nested-serial-fail out.txt "· ❌ outer ("

PARALLEL=1 run_case killed 1 "a=ok" "b=die"
expect killed out.txt "· ✅ a ("
expect killed out.txt "· ❌ b ("

ALLOW_FAIL=a PARALLEL=1 run_case allowed-fail 0 "a=fail" "b=ok"
expect allowed-fail out.txt "⚠️  a ("
expect allowed-fail out.txt "· ✅ b ("

PROGRESS_SECS=1 PARALLEL=1 run_case heartbeat 0 "a=slow"
expect heartbeat out.txt "… a ("
expect heartbeat out.txt "slow working"

if [ "${failures}" -ne 0 ]; then
    echo "❌ parallel.sh: ${failures} check(s) failed" >&2
    exit 1
fi
echo "✅ parallel.sh: every case passed"
