#!/bin/bash

set -euo pipefail

current_dir=$(pwd)

DOCKER_COMPOSE_DIR="${current_dir}/envs/mediator/affinidi-messaging/conf"

if [ -d "${DOCKER_COMPOSE_DIR}" ]; then
    cd "${DOCKER_COMPOSE_DIR}" || exit 1
    docker-compose down
fi
