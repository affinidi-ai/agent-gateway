#!/bin/bash

# -x Print out all executed commands to the terminal.
# set -x

# -e  Exit immediately if a command exits with a non-zero status.
set -e

source ./scripts/_env.sh

if [[ ! -d "${docker_env_dir}" ]]
then
  echo "❌ docker directory does not exist, pls run make config-docker to set up environments"
  exit 1
fi

cleanup() {
  echo "SIGINT caught, cleaning up..."
  docker container stop "${agent_name}"
  docker container rm "${agent_name}"
  echo "Cleanup done."
}
trap 'cleanup' SIGINT

# Ports are read from ${docker_env_dir}/config/gateway.json

http_port=$(jq -r '.listeners[] | select(.id == "http-listener") | .port' "${docker_env_dir}/config/gateway.json")
https_port=$(jq -r '.listeners[] | select(.id == "https-listener") | .port' "${docker_env_dir}/config/gateway.json")

# Publish every inbound listener the config defines. The HTTPS listener (8443)
# serves the dashboard where WebAuthn passkey login is pinned (external_origin),
# so it must be reachable from the host or login fails with an origin mismatch.
publish_args=()
[[ -n "${http_port}" && "${http_port}" != "null" ]] && publish_args+=("--publish=${http_port}:${http_port}")
[[ -n "${https_port}" && "${https_port}" != "null" ]] && publish_args+=("--publish=${https_port}:${https_port}")

docker network create agent-network 2>/dev/null || echo "Network agent-network already exists."

docker rm -f "${agent_name}" 2>/dev/null || true

docker run \
    --name="${agent_name}" \
    --interactive \
    --network agent-network \
    --add-host=localhost:host-gateway \
    --cpus="${DOCKER_CPUS:-2}" \
    --memory="${DOCKER_MEMORY:-512m}" \
    --volume="${docker_env_dir}/config:/app/config" \
    --volume="${docker_env_dir}/certs:/app/certs" \
    --volume="${docker_env_dir}/_storage:/app/_storage" \
    "${publish_args[@]}" \
    --env RUST_LOG="info" \
    --env AWS_ACCESS_KEY_ID \
    --env AWS_SECRET_ACCESS_KEY \
    --env AWS_SESSION_TOKEN \
    --env AWS_REGION \
    --env AG_IDENTITY_HASH_PEPPER \
    --env AG_BACKUP_ENCRYPTION_KEY \
    --workdir /app \
    "${tag}"
