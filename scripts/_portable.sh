# shellcheck shell=bash
# Sourced by Bash setup scripts; intentionally not executable.

sedi() {
  if sed --version >/dev/null 2>&1; then
    sed -i "$@"
  else
    sed -i '' "$@"
  fi
}
