#!/usr/bin/env bash
# Boot-probe a built image: run the entrypoint with --help and assert a clean
# exit — the same probe the docker-compose healthcheck uses. Catches an image
# that panics on startup or is missing shared libraries before it is published.
set -euo pipefail

: "${IMAGE:?IMAGE must be set (e.g. agent-gateway:verify)}"

docker run --rm "$IMAGE" --help
echo "image booted and exited 0"
