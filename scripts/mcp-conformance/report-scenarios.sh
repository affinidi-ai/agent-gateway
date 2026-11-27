#!/usr/bin/env bash
#
# Lists the scenarios a report-only run executes: one line per scenario the
# suite lists for a leg, followed by the flags that run it on the wire of the
# requirement set. A scenario that applies to that revision, or is an extension,
# runs on that wire; one of older revisions only runs at its own revision.
# The authorization command has no --force.
#
# Usage: report-scenarios.sh CLI LEG SPEC_VERSION
#   LEG is client, server or authorization.

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "Usage: report-scenarios.sh CLI LEG SPEC_VERSION" >&2
    exit 2
fi
cli="$1" leg="$2" spec="$3"
force=" --force"
if [[ "${leg}" == authorization ]]; then force=""; fi

"${cli}" list "--${leg}" 2> /dev/null | sed -n 's/^  - \([^ ]*\) \[\(.*\)\]$/\1 \2/p' | while read -r scenario tags; do
    if [[ ",${tags}," == *",${spec},"* || "${tags}" == extension ]]; then
        echo "${scenario} --spec-version ${spec}${force}"
    else
        echo "${scenario}"
    fi
done
