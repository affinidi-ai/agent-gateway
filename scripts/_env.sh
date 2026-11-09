#!/bin/bash

# -x Print out all executed commands to the terminal.
# set -x

# -e  Exit immediately if a command exits with a non-zero status.
set -e

envs_dir="$(pwd)/envs"
export envs_dir
export local_env_dir="${envs_dir}/local"
export docker_env_dir="${envs_dir}/docker"
export agent_name="agent-gateway"
export WWW_DIR="${WWW_DIR:-www/default}"

export enable_docker=false
export tag="${TAG:-${agent_name}:local}"

export AG_IDENTITY_HASH_PEPPER="${AG_IDENTITY_HASH_PEPPER:-$(cat "${envs_dir}/identity_hash_pepper" 2>/dev/null || true)}"
export AG_BACKUP_ENCRYPTION_KEY="${AG_BACKUP_ENCRYPTION_KEY:-$(cat "${envs_dir}/backup_encryption_key" 2>/dev/null || true)}"

# Per-instance ports are derived from these bases by adding a stable offset
# (see scripts/_prepare.sh → assign_ports). Each local-* instance gets a
# unique (HTTP_PORT, HTTPS_PORT, OUTBOUND_PORT, FRONTEND_PORT) tuple persisted to
# ${target_dir}/instance.env so run scripts can source it directly.
export DEFAULT_HTTP_PORT=8080
export DEFAULT_HTTPS_PORT=8443
export DEFAULT_OUTBOUND_PORT=9000
export DEFAULT_FRONTEND_PORT=3002
