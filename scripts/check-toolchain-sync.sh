#!/usr/bin/env bash
# Toolchain-sync guard: every `toolchain:` pin under .github/workflows/* must
# match the crate MSRV (`rust-version` in Cargo.toml). Kills the multi-file edit
# trap where a toolchain bump misses a workflow and CI silently builds on a
# different compiler than the one the crate declares. Pure bash — no Rust build.
set -euo pipefail

msrv=$(grep -E '^rust-version[[:space:]]*=' Cargo.toml | head -1 |
  sed -E 's/.*"([0-9.]+)".*/\1/')
if [[ -z "$msrv" ]]; then
  echo "could not read rust-version (MSRV) from Cargo.toml" >&2
  exit 1
fi
echo "Cargo.toml rust-version (MSRV): $msrv"

fail=0
while IFS= read -r line; do
  file=${line%%:*}
  pin=$(sed -E 's/.*toolchain:[[:space:]]*['\''"]?([0-9][0-9.]*)['\''"]?.*/\1/' <<<"$line")
  if [[ "$pin" != "$msrv" ]]; then
    echo "::error file=${file}::toolchain pin '${pin}' != Cargo.toml MSRV '${msrv}'"
    fail=1
  fi
done < <(grep -rEn 'toolchain:[[:space:]]*['\''"]?[0-9]' .github/workflows || true)

if [[ "$fail" -ne 0 ]]; then
  echo "toolchain pins are out of sync with the Cargo.toml MSRV" >&2
  exit 1
fi
echo "all workflow toolchain pins match the MSRV"
