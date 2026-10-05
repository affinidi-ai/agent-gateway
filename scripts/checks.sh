#!/bin/bash

set -euo pipefail

if command -v sccache >/dev/null 2>&1 && [[ -z "${RUSTC_WRAPPER:-}" ]]; then
  export RUSTC_WRAPPER=sccache
fi

echo "Running mediator configuration fixtures..."
"$(dirname "${BASH_SOURCE[0]}")/mediator/test-reconcile-mediator-config.sh"

echo "Running cargo fmt..."
cargo fmt --all --check

echo "Running cargo check..."
cargo check --all-targets --all-features

echo "Running cargo clippy..."
cargo clippy --all-targets --all-features -- -D warnings

echo "Running cargo tests..."
cargo test --no-fail-fast --all-targets --all-features
