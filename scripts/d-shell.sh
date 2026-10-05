#!/bin/bash

# -x Print out all executed commands to the terminal.
# set -x

# -e  Exit immediately if a command exits with a non-zero status.
set -e

source ./scripts/_env.sh

if [[ ! -d "${docker_env_dir}" ]]
then
  echo "❌ docker directory does not exist, run 'make config-docker' to set up environments"
  exit 1
fi

	# --volume ${docker_env_dir}/data:/app/data \
    # --volume ./config/local-www-config.json:/app/www/dashboard/config.json \
container_id=$(docker run \
	--interactive \
	--detach \
	--network host \
	--entrypoint "/bin/bash" \
    --volume="${docker_env_dir}/config:/app/config" \
	--volume="${docker_env_dir}/_storage:/app/_storage" \
	--publish=8080:8080 \
	--env RUST_LOG="info" \
    --env AWS_ACCESS_KEY_ID \
    --env AWS_SECRET_ACCESS_KEY \
    --env AWS_SESSION_TOKEN \
    --env AWS_REGION \
    --env AG_IDENTITY_HASH_PEPPER \
    --env AG_BACKUP_ENCRYPTION_KEY \
    --workdir /app \
	"${tag}")

echo "container_id=${container_id}"
 
docker exec \
	--interactive \
	--tty \
	"${container_id}" \
	/bin/bash

# ${agent_name}
# /usr/local/bin/agent-gateway --config config/config.toml

docker container stop "${container_id}"
docker container rm "${container_id}"
