#!/bin/bash
# Version-bump guard: when a pull request changes shipped source, the Cargo.toml
# package version must be bumped relative to the pull request base. Releases are
# cut from a tag, so leaving the version unchanged would ship a different binary
# under a version that was already released.
#
# Scope is deliberately narrow. Changelog fragments are enforced separately by
# the `changelog` job in .github/workflows/ci.yml, and this repository is a
# single `publish = false` binary, so there is no crates.io or workspace-member
# concern to police here.
set -euo pipefail

base="${1:-}"
if [[ -z "${base}" ]]; then
  echo "usage: check-version-bumps.sh <base-sha>" >&2
  exit 1
fi

# Paths whose contents end up in the released binary.
watched=(src Cargo.toml Cargo.lock)

if ! changed=$(git diff --name-only "${base}...HEAD" -- "${watched[@]}"); then
  echo "could not diff against base '${base}' — is the history deep enough?" >&2
  exit 1
fi

if [[ -z "${changed}" ]]; then
  echo "No shipped source changes (${watched[*]}) — version bump not required."
  exit 0
fi

# First line-anchored `version = "..."`, i.e. the [package] version rather than
# any dependency pin. awk exits on the first match, so this stays safe under
# `set -o pipefail` (unlike `grep ... | head -1`).
read_package_version() {
  awk -F'"' '/^version[[:space:]]*=/ { print $2; exit }'
}

head_version=$(read_package_version <Cargo.toml)
if [[ -z "${head_version}" ]]; then
  echo "::error file=Cargo.toml::could not read the package version" >&2
  exit 1
fi

base_toml=$(git show "${base}:Cargo.toml" 2>/dev/null || true)
base_version=$(printf '%s\n' "${base_toml}" | read_package_version)
if [[ -z "${base_version}" ]]; then
  echo "Base '${base}' has no readable Cargo.toml version — nothing to compare."
  exit 0
fi

# True iff $1 is a strictly higher version than $2.
version_gt() {
  [[ "$1" != "$2" ]] &&
    [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" ]]
}

echo "Cargo.toml version: base=${base_version} head=${head_version}"

if [[ "${head_version}" == "${base_version}" ]]; then
  echo "::error file=Cargo.toml::shipped source changed but the package version is still ${head_version} — bump it"
  echo "changed files:"
  printf '%s\n' "${changed}" | sed 's/^/  /'
  exit 1
fi

if ! version_gt "${head_version}" "${base_version}"; then
  echo "::error file=Cargo.toml::package version ${head_version} is not greater than the base version ${base_version}"
  exit 1
fi

echo "version bumped ${base_version} -> ${head_version}"
