#!/bin/bash

# -x Print out all executed commands to the terminal.
# set -x

# -e  Exit immediately if a command exits with a non-zero status.
set -e

source "$(dirname "$0")/_env.sh"

# Values the sourced helper above must provide.
: "${local_env_dir:?_env.sh must set local_env_dir}"

target_dir=${local_env_dir}

if [[ ! -d "${target_dir}" ]]
then
  echo "❌ ${target_dir} directory does not exist, pls run 'make help' for guidance on setting up environments"
  exit 1
fi

repo_dir=$(pwd)

ln -sf "${repo_dir}/${WWW_DIR}/build" "${target_dir}/www" 2>/dev/null || true

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

echo "🔧 Running in RELEASE mode"
echo "Backend: Using release binary"
echo "Frontend: Using existing www"

cd "${target_dir}"
"${repo_dir}/target/release/agent-gateway" --config config/config.toml
