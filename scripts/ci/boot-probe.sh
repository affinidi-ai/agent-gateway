#!/usr/bin/env bash
# Boot-probe a built image: run the entrypoint with --help and assert a clean
# exit — the same probe the docker-compose healthcheck uses. Catches an image
# that panics on startup or is missing shared libraries before it is published.
# Also fails when the binary links a shared library the image does not contain,
# and when the xmlsec1 CLI the gateway shells out to cannot run.
set -euo pipefail

: "${IMAGE:?IMAGE must be set (e.g. agent-gateway:verify)}"

docker run --rm "$IMAGE" --help

missing="$(docker run --rm --entrypoint ldd "$IMAGE" /usr/local/bin/agent-gateway | grep 'not found' || true)"
if [[ -n "${missing}" ]]; then
  echo "::error::agent-gateway links shared libraries the image does not contain:"
  echo "${missing}"
  exit 1
fi

docker run --rm --entrypoint xmlsec1 "$IMAGE" --version
echo "image booted and exited 0"
