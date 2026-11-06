#!/usr/bin/env bash
# Scan the Dockerfile for misconfigurations, or a built image for known
# vulnerabilities and embedded secrets, with a pinned Trivy container. The image
# is handed over as a tarball, so the Docker socket and registry credentials are
# never exposed to the scanner.
#
# Findings are HIGH and CRITICAL only; vulnerabilities with no available fix are
# ignored. They are listed in the job summary and as warnings. The script exits
# non-zero on findings only when TRIVY_ENFORCE=true, so a rollout can start in
# warn-only mode and be switched to blocking later.
#
# Usage:
#   trivy-scan.sh config              scan ./Dockerfile
#   trivy-scan.sh image <reference>   scan a local or already-pulled image
#   trivy-scan.sh summarize <report.json> <title>
set -euo pipefail

TRIVY_IMAGE="${TRIVY_IMAGE:-ghcr.io/aquasecurity/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
MAX_ROWS=50

summarize() {
  local report="$1" title="$2" count
  count="$(jq '[.Results[]? | (.Vulnerabilities[]?, .Misconfigurations[]?, .Secrets[]?)] | length' "${report}")"
  {
    echo "### ${title}"
    echo
    if [[ "${count}" -eq 0 ]]; then
      echo "No HIGH or CRITICAL findings."
    else
      echo "${count} HIGH or CRITICAL finding(s)$([[ ${count} -gt ${MAX_ROWS} ]] && echo ", first ${MAX_ROWS} shown")."
      echo
      echo "| Severity | Target | Finding | Detail |"
      echo "| --- | --- | --- | --- |"
      jq -r --argjson max "${MAX_ROWS}" '
        [.Results[]? | .Target as $t | (
            (.Vulnerabilities[]? | [.Severity, $t, .VulnerabilityID, "\(.PkgName) \(.InstalledVersion) → fixed in \(.FixedVersion)"]),
            (.Misconfigurations[]? | [.Severity, $t, .ID, .Title]),
            (.Secrets[]? | [.Severity, $t, .RuleID, .Title])
        )]
        | sort_by(.[0] != "CRITICAL")
        | .[:$max][]
        | "| " + (map(gsub("\\|"; "\\|")) | join(" | ")) + " |"' "${report}"
    fi
    echo
  } >>"${GITHUB_STEP_SUMMARY:-/dev/stdout}"
  echo "${count}"
}

report_and_gate() {
  local report="$1" title="$2" count
  count="$(summarize "${report}" "${title}" | tail -n 1)"
  if [[ "${count}" -gt 0 ]]; then
    if [[ "${TRIVY_ENFORCE:-false}" == "true" ]]; then
      echo "::error title=${title}::${count} HIGH or CRITICAL finding(s); see the job summary."
      exit 1
    fi
    echo "::warning title=${title}::${count} HIGH or CRITICAL finding(s); see the job summary. Not blocking while TRIVY_ENFORCE is not true."
  fi
}

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
chmod 777 "${work}"

case "${1:-}" in
  config)
    cp Dockerfile "${work}/Dockerfile"
    docker run --rm -v "${work}:/work" "${TRIVY_IMAGE}" \
      config --severity HIGH,CRITICAL --format json --output /work/report.json /work/Dockerfile
    report_and_gate "${work}/report.json" "Dockerfile scan"
    ;;
  image)
    ref="${2:?image reference required}"
    docker save "${ref}" -o "${work}/image.tar"
    docker run --rm -v "${work}:/work" "${TRIVY_IMAGE}" \
      image --input /work/image.tar --scanners vuln,secret \
      --severity HIGH,CRITICAL --ignore-unfixed --format json --output /work/report.json
    report_and_gate "${work}/report.json" "Image scan"
    ;;
  summarize)
    summarize "${2:?report required}" "${3:-Scan}" >/dev/null
    ;;
  *)
    echo "usage: $0 config | image <reference> | summarize <report.json> <title>" >&2
    exit 2
    ;;
esac
