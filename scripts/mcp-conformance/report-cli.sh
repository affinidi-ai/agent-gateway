#!/usr/bin/env bash
#
# Stands in for the suite's `server` command in the Fabric BDD step of a
# report-only run. The step passes the requirement set and the baseline; this
# runs every scenario the suite has instead, one at a time, ignoring both and
# the suite's verdict, so the Fabric report is complete and baseline-free.
#
# Environment:
#   MCP_CONFORMANCE_REAL_CLI       the suite's CLI
#   MCP_CONFORMANCE_REPORT_SPEC    the requirement-set revision
#   MCP_CONFORMANCE_REPORT_FAILED  file that receives the names of failed scenarios

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ "${1:-}" == server ]] || { echo "report-cli.sh: only the server command is supported" >&2; exit 2; }
shift
url="" out=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --url) url="${2:?--url needs a value}"; shift ;;
        -o) out="${2:?-o needs a value}"; shift ;;
        --requirements|--expected-failures) shift ;;
        *) echo "report-cli.sh: unsupported option $1" >&2; exit 2 ;;
    esac
    shift
done
[[ -n "${url}" && -n "${out}" ]] || { echo "report-cli.sh: --url and -o are required" >&2; exit 2; }

list="$(mktemp)"
trap 'rm -f "${list}"' EXIT
# A file rather than a process substitution: bash 3.2 cannot wait for one, and a
# list that stops partway must not become a short report.
"${HERE}/report-scenarios.sh" "${MCP_CONFORMANCE_REAL_CLI}" server "${MCP_CONFORMANCE_REPORT_SPEC}" > "${list}" ||
    { echo "report-cli.sh: the suite could not list its server scenarios" >&2; exit 1; }

: > "${MCP_CONFORMANCE_REPORT_FAILED}"
count=0
while read -r scenario flags <&3; do
    echo "=== ${scenario} ==="
    # shellcheck disable=SC2086
    "${MCP_CONFORMANCE_REAL_CLI}" server --url "${url}" --scenario "${scenario}" ${flags} -o "${out}" 2>&1 ||
        echo "${scenario}" >> "${MCP_CONFORMANCE_REPORT_FAILED}"
    count=$((count + 1))
done 3< "${list}"
[[ ${count} -gt 0 ]] || { echo "report-cli.sh: the suite lists no server scenario" >&2; exit 1; }
