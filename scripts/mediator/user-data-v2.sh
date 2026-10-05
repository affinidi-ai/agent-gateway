#!/bin/bash
set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_url.sh"

# echo "📦 Setup..."
# yum update --assumeyes
# # docker is in the AL2023 amazonlinux repo; aws CLI is pre-installed on the AMI.
# yum install --assumeyes jq docker
# systemctl enable --now docker
# # AL2023 has no docker-compose-plugin package — fetch the standalone binary.
# curl -fsSL \
#   "https://github.com/docker/compose/releases/download/v2.40.0/docker-compose-$(uname -s)-$(uname -m)" \
#   -o /usr/local/bin/docker-compose
# chmod +x /usr/local/bin/docker-compose
# echo "✅ Setup done!"

# ── Arguments ─────────────────────────────────────────────────────────────────
TARGET_DIR="${1}"
MEDIATOR_IMAGE="${2}"
MEDIATOR_URL="${3}"
MEDIATOR_PORT="${4}"
MEDIATOR_ACL_MODE="${5}"
GLOBAL_DEFAULT_ACL="${6}"
MEDIATOR_ENV="${7}"
DID_METHOD="${8}"
DID_WEB_FROM_DID_WEBVH="${9}"
BLOCK_ANONYMOUS_OUTER_ENVELOPE="${10}"
USE_P256_KEY_SUITE="${11:-true}"
ADMIN_DID="${12:-}"

# ECR login — only needed for private ECR (*.dkr.ecr.*.amazonaws.com);
# public.ecr.aws is pulled anonymously.
ECR_REGISTRY=$(echo "$MEDIATOR_IMAGE" | cut -d/ -f1)
if echo "$ECR_REGISTRY" | grep -qF '.dkr.ecr.'; then
  ECR_REGION=$(echo "$ECR_REGISTRY" | cut -d. -f4)
  aws ecr get-login-password --region "$ECR_REGION" | \
    docker login --username AWS --password-stdin "$ECR_REGISTRY"
fi


# ── Prepare directories ────────────────────────────────────────────────────────
APP_DIR="${TARGET_DIR}"
cd "${APP_DIR}"
mkdir -p affinidi-messaging/conf affinidi-messaging/data
# chown -R 999:999 affinidi-messaging/conf affinidi-messaging/data
cd affinidi-messaging/conf

# ── mediator-setup (declarative recipe, api_prefix = "/") ─────────────────────
# Recipe-driven setup writes api_prefix = "/" into both mediator.toml and the
# DID service endpoints — so the mediator serves at host root (/healthchecker,
# /.well-known/did.json, etc.), matching V1 behaviour.
#
# IDEMPOTENT GUARD: only provision when no config exists yet. mediator-setup
# refuses (exits non-zero) when conf/mediator.toml + secrets are already present,
# and under set -e that would abort the whole script, so a redeploy would pull
# the new image but never reach the docker-compose up below, leaving the mediator
# stopped on the old image. Skipping setup on an already-provisioned host preserves
# the existing DID/secrets and lets the script fall through to re-pull the new
# image and restart. To rotate identity, wipe conf/ (or run mediator-setup
# --force-reprovision) before redeploying.
if [ -f mediator.toml ]; then
  echo "♻️  Existing mediator config found — skipping setup, preserving DID/secrets."
else
RECIPE_PUBLIC_URL=""
RECIPE_SAVE_DID_WEB=""
if [ "$DID_METHOD" = "webvh" ]; then
  RECIPE_PUBLIC_URL="$(mediator_recipe_public_url "${MEDIATOR_URL}")"
  [ "$DID_WEB_FROM_DID_WEBVH" = "true" ] && RECIPE_SAVE_DID_WEB="save_did_web = true"
fi
RECIPE_EXTRA_KEY_SUITES=""
[ "$USE_P256_KEY_SUITE" = "true" ] && RECIPE_EXTRA_KEY_SUITES='extra_key_suites = ["p256"]'
# admin = "skip" when an external admin DID is supplied; mediator-setup then
# omits the generated admin credential and we inject the DID into mediator.toml.
RECIPE_ADMIN_MODE="generate"
[ -n "$ADMIN_DID" ] && RECIPE_ADMIN_MODE="skip"

cat > recipe.toml <<EOF
[deployment]
type = "server"
protocols = ["didcomm"]
use_vta = false

[identity]
did_method = "${DID_METHOD}"
${RECIPE_PUBLIC_URL}
${RECIPE_SAVE_DID_WEB}
${RECIPE_EXTRA_KEY_SUITES}

[secrets]
storage = "file://"

[security]
ssl = "none"
admin = "${RECIPE_ADMIN_MODE}"

[database]
url = "redis://127.0.0.1/"

[output]
config_path = "conf/mediator.toml"
listen_address = "0.0.0.0:${MEDIATOR_PORT}"
api_prefix = "/"
EOF

docker run --rm \
  --entrypoint 'mediator-setup' \
  --volume "$PWD":/app/conf \
  --volume "${APP_DIR}affinidi-messaging/data":/app/data \
  "$MEDIATOR_IMAGE" \
  --from /app/conf/recipe.toml

fi  # end idempotent setup guard

# listen_address is always a wildcard bind (0.0.0.0:${MEDIATOR_PORT}), so
# Routing 2.0 self-loopback delivery needs the public URL in local_endpoints.
# Reconcile it on every run so existing configs are repaired without reprovisioning.
"${SCRIPT_DIR}/reconcile-mediator-config.sh" \
  mediator.toml \
  "${MEDIATOR_URL}" \
  "${ADMIN_DID}"

cd ..

# ── Container env file ─────────────────────────────────────────────────────────
# Flat KEY=VALUE file consumed via env_file: in compose.
{
  echo "RUST_LOG=info"
  echo "DATABASE_URL=redis://redis:6379"
  echo "LISTEN_ADDRESS=0.0.0.0:${MEDIATOR_PORT}"
  echo "MEDIATOR_ACL_MODE=${MEDIATOR_ACL_MODE}"
  echo "BLOCK_ANONYMOUS_OUTER_ENVELOPE=${BLOCK_ANONYMOUS_OUTER_ENVELOPE}"
  # force_session_did_match requires block_anonymous_outer_envelope=true; disable together
  if [ "$BLOCK_ANONYMOUS_OUTER_ENVELOPE" = "false" ]; then
    echo "FORCE_SESSION_DID_MATCH=false"
  fi
  echo "GLOBAL_DEFAULT_ACL=${GLOBAL_DEFAULT_ACL}"
  if [ "$MEDIATOR_ENV" != "{}" ]; then
    echo "$MEDIATOR_ENV" | jq -r 'to_entries[] | "\(.key)=\(.value)"'
  fi
  if [ "$DID_METHOD" = "webvh" ] && [ "$DID_WEB_FROM_DID_WEBVH" = "true" ]; then
    echo "DID_WEB_SELF_HOSTED=file:///app/conf/did.jsonl"
  fi
} > conf/mediator.env

# ── docker-compose.yml ─────────────────────────────────────────────────────────
cat > docker-compose.yml <<EOF
services:
  mediator:
    image: ${MEDIATOR_IMAGE}
    container_name: mediator
    restart: unless-stopped
    ports:
      - "${MEDIATOR_PORT}:${MEDIATOR_PORT}"
    volumes:
      - ${APP_DIR}/affinidi-messaging/conf:/app/conf
      - ${APP_DIR}/affinidi-messaging/data:/app/data
    working_dir: /app
    env_file:
      - ${APP_DIR}/affinidi-messaging/conf/mediator.env
    depends_on:
      - redis
    logging:
      driver: json-file

  redis:
    image: valkey/valkey:8.1.4
    container_name: redis
    restart: unless-stopped
    environment:
      ALLOW_EMPTY_PASSWORD: yes
EOF

docker-compose down
docker-compose up -d
