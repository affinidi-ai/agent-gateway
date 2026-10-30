#!/usr/bin/env bash
#
# Fetches an agent card with the official A2A SDK card resolvers and checks that each parses it:
# a2a-python 1.x and 0.3.x, a2a-js 1.x and 0.3.x. Fixture cards (A2A 1.0 shape, 0.3 shape and the
# dual-era shape) are served from a local static server; --live checks the card at a URL.
#
# Usage: run.sh [--fixtures] [--live CARD_URL]   (default: --fixtures)
# Environment:
#   OIDC_SDK_DIR        folder holding the installed SDKs: py1, py03 (virtualenvs) and js1, js03
#                       (npm folders). Default: tmp/oidc-sdk under the repository root.
#   SDK_CHECK_BEARER    optional bearer token sent when fetching the live card (never printed).
# Known SDK rejections live in expected-failures.json; an unlisted failure, or a listed one that
# now passes, fails the run.

set -euo pipefail
unset CDPATH
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../../.." && pwd)"
SDK_DIR="${OIDC_SDK_DIR:-${REPO_ROOT}/tmp/oidc-sdk}"

RUN_FIXTURES=false
LIVE_URL=""
if [[ $# -eq 0 ]]; then RUN_FIXTURES=true; fi
while [[ $# -gt 0 ]]; do
    case "$1" in
        --fixtures) RUN_FIXTURES=true; shift ;;
        --live)
            [[ $# -ge 2 ]] || { echo "--live needs a card URL" >&2; exit 2; }
            LIVE_URL="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

for tool in python3 node curl; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "missing tool: ${tool}" >&2; exit 2; }
done
for sdk in py1 py03; do
    [[ -x "${SDK_DIR}/${sdk}/bin/python" ]] || { echo "missing ${SDK_DIR}/${sdk}: set OIDC_SDK_DIR to the folder holding the installed SDKs" >&2; exit 2; }
done
for sdk in js1 js03; do
    [[ -d "${SDK_DIR}/${sdk}/node_modules/@a2a-js/sdk" ]] || { echo "missing ${SDK_DIR}/${sdk}: set OIDC_SDK_DIR to the folder holding the installed SDKs" >&2; exit 2; }
done

python3 -I -B -m unittest discover -s "${HERE}" >/dev/null 2>&1 || { echo "report.py tests fail" >&2; exit 1; }

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
    if [[ -n "${SERVER_PID}" ]]; then kill "${SERVER_PID}" 2>/dev/null || true; fi
    rm -rf "${WORK}"
}
trap cleanup EXIT

collect() {
    local label="$1" url="$2" out
    out="${WORK}/${label}.jsonl"
    : >"${out}"
    "${SDK_DIR}/py1/bin/python" -I -B "${HERE}/check_py.py" "${url}" >>"${out}"
    "${SDK_DIR}/py03/bin/python" -I -B "${HERE}/check_py.py" "${url}" >>"${out}"
    node "${HERE}/check_js.mjs" "${SDK_DIR}/js1" "${url}" >>"${out}"
    node "${HERE}/check_js.mjs" "${SDK_DIR}/js03" "${url}" >>"${out}"
    TARGETS+=("${label}=${out}")
}

TARGETS=()
if [[ "${RUN_FIXTURES}" == true ]]; then
    PORT="$(python3 -I -B -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
    python3 -I -B -m http.server "${PORT}" --bind 127.0.0.1 --directory "${HERE}/fixtures" >/dev/null 2>&1 &
    SERVER_PID=$!
    disown "${SERVER_PID}"
    for _ in $(seq 1 50); do
        curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/card-v1.json" 2>/dev/null && break
        sleep 0.1
    done
    for fixture in card-v1 card-v03 card-dual; do
        collect "${fixture}" "http://127.0.0.1:${PORT}/${fixture}.json"
    done
fi

# Fixture cards are compared with the expected summary; a live card is only checked for a clean,
# self-consistent parse, so the two are judged in separate calls.
STATUS=0
if [[ "${#TARGETS[@]}" -gt 0 ]]; then
    python3 -I -B "${HERE}/report.py" --expect "${HERE}/fixtures/expected.json" \
        --expected-failures "${HERE}/expected-failures.json" "${TARGETS[@]}" || STATUS=1
fi
if [[ -n "${LIVE_URL}" ]]; then
    TARGETS=()
    collect live "${LIVE_URL}"
    [[ "${RUN_FIXTURES}" == true ]] && printf '\n'
    python3 -I -B "${HERE}/report.py" --expected-failures "${HERE}/expected-failures.json" "${TARGETS[@]}" || STATUS=1
fi
exit "${STATUS}"
