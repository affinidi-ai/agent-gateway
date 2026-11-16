#!/usr/bin/env bash
# Toolchain-sync guard: every `toolchain:` pin under .github/workflows/*, and
# the `channel` in rust-toolchain.toml, must match the crate MSRV
# (`rust-version` in Cargo.toml). Kills the multi-file edit trap where a
# toolchain bump misses a workflow and CI silently builds on a different
# compiler than the one the crate declares. rust-toolchain.toml is checked
# because rustup lets it decide which compiler a cargo command uses, so a stale
# channel there outranks every workflow pin; a branch without the file has no
# pin that can drift, so its check is skipped out loud rather than failed.
# Pure bash — no Rust build.
set -euo pipefail

msrv=$(grep -E '^rust-version[[:space:]]*=' Cargo.toml | head -1 |
  sed -E 's/.*"([0-9.]+)".*/\1/')
if [[ -z "$msrv" ]]; then
  echo "could not read rust-version (MSRV) from Cargo.toml" >&2
  exit 1
fi
echo "Cargo.toml rust-version (MSRV): $msrv"

fail=0
pinned=1
if [[ ! -f rust-toolchain.toml ]]; then
  # Nothing to drift from: an older or release branch that predates the file is
  # not failed for a condition this guard does not exist to catch. Said out
  # loud so a run without the file is not read as one that checked it.
  echo "rust-toolchain.toml is not present: skipping the channel check"
  pinned=0
else
  channel=$(grep -E '^channel[[:space:]]*=' rust-toolchain.toml | head -1 |
    sed -E 's/.*"([0-9.]+)".*/\1/')
  if [[ "$channel" != "$msrv" ]]; then
    echo "::error file=rust-toolchain.toml::channel '${channel}' != Cargo.toml MSRV '${msrv}'"
    fail=1
  fi
fi

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
if [[ "$pinned" -eq 1 ]]; then
  echo "rust-toolchain.toml and all workflow toolchain pins match the MSRV"
else
  echo "all workflow toolchain pins match the MSRV; rust-toolchain.toml was not checked"
fi
