#!/bin/bash
#
# Generate a DIDComm mediator stack for the gateway-to-gateway BDD E2E test
# (g2g_bdd). Produces a self-contained mediator under a target
# directory (default: tmp/g2g-mediator/) using bridged docker networking so it
# works on macOS and Linux. Uses `mediator-setup --non-interactive` from the
# mediator image to provision keys into a file-based secrets backend.
#
# Idempotent: if conf/mediator.toml already exists, skips regeneration
# unless --force is passed.
#
# Usage:
#   scripts/g2g-mediator.sh [--target-dir DIR] [--force]
#
# Environment overrides:
#   G2G_MEDIATOR_DIR         Target directory (default: tmp/g2g-mediator)
#   G2G_MEDIATOR_PORT        Host port to publish (default: 7037)
#   G2G_MEDIATOR_NAME        Docker Compose project/container prefix (default: g2g-mediator)
#   G2G_MEDIATOR_EXTRA_PORTS Space-separated list of extra host ports to also
#                            publish on the mediator container. Used when
#                            other containers piggyback on the mediator's
#                            netns via `network_mode: container:<mediator>`
#                            (they can't publish their own ports in that mode).
#   MEDIATOR_VERSION         Mediator image tag (default: v0.18.0)
#   VALKEY_VERSION           Valkey image tag (default: 8.1.4)

set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "docker CLI is required to generate the G2G mediator stack" >&2
  exit 127
fi

MEDIATOR_VERSION="${MEDIATOR_VERSION:-v0.18.0}"
VALKEY_VERSION="${VALKEY_VERSION:-8.1.4}"
MEDIATOR_PORT="${G2G_MEDIATOR_PORT:-7037}"
MEDIATOR_NAME="${G2G_MEDIATOR_NAME:-g2g-mediator}"
TARGET_DIR="${G2G_MEDIATOR_DIR:-tmp/g2g-mediator}"
# Extra ports to publish on the mediator container (for services that share its
# network namespace via network_mode: container:). Space-separated.
EXTRA_PORTS="${G2G_MEDIATOR_EXTRA_PORTS:-}"
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-dir)
      TARGET_DIR="$2"; shift 2 ;;
    --force)
      FORCE=1; shift ;;
    -h|--help)
      sed -n '2,22p' "$0"; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ABS_TARGET="${REPO_ROOT}/${TARGET_DIR}"
CONF_DIR="${ABS_TARGET}/conf"

mkdir -p "${CONF_DIR}"

MEDIATOR_IMAGE="public.ecr.aws/affinidi/messaging-mediator:${MEDIATOR_VERSION}"

needs_regen=1
if [[ -f "${CONF_DIR}/mediator.toml" && "${FORCE}" -eq 0 ]]; then
  if grep -q "listen_address" "${CONF_DIR}/mediator.toml" 2>/dev/null; then
    needs_regen=0
  fi
fi

if [[ "${needs_regen}" -eq 1 ]]; then
  echo "🔧 Generating mediator config in ${ABS_TARGET} via mediator-setup"
  pushd "${ABS_TARGET}" >/dev/null

  # Use the mediator image's own setup wizard to provision keys + config.
  # Do NOT pass --database-url: redis isn't running yet during setup.
  # The database URL is provided via env var at container runtime.
  # Mount the entire target dir as /app so the tool can write mediator.toml,
  # build recipes, and secrets all under its working directory.
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    --entrypoint mediator-setup \
    --volume "$(pwd):/app" \
    --workdir /app \
    "${MEDIATOR_IMAGE}" \
    --non-interactive \
    --deployment container \
    --protocol didcomm \
    --did-method webvh \
    --public-url "http://localhost:${MEDIATOR_PORT}" \
    --secret-storage file \
    --ssl none \
    --admin generate \
    --listen-address "0.0.0.0:${MEDIATOR_PORT}" \
    2>&1 | tee mediator_config_output.txt

  # Ensure config files are accessible by the mediator container's non-root user.
  # In CI (running as root), mediator-setup writes root-owned files that the
  # mediator image's runtime user cannot access without this.
  # secrets.json needs write access (the secrets backend probes by writing/locking).
  chmod -R a+rwX "${CONF_DIR}"

  # Extract the mediator DID from the generated config (macOS-compatible)
  SETUP_DID=$(sed -n 's/^mediator_did *= *"did:\/\/\(did:[^"]*\)"/\1/p' "${CONF_DIR}/mediator.toml" | head -1)
  if [[ -z "${SETUP_DID}" ]]; then
    SETUP_DID=$(sed -n 's/^mediator_did *= *"\(did:[^"]*\)"/\1/p' "${CONF_DIR}/mediator.toml" | head -1)
  fi
  if [[ -z "${SETUP_DID}" ]]; then
    SETUP_DID=$(sed -n 's/.*Mediator DID: *//p' mediator_config_output.txt | head -1)
  fi
  if [[ -n "${SETUP_DID}" ]]; then
    echo "  Mediator DID from setup: ${SETUP_DID}"
  fi

  cat > docker-compose.yml <<EOF
name: ${MEDIATOR_NAME}
networks:
  mediatornet:
    driver: bridge
services:
  redis:
    image: valkey/valkey:${VALKEY_VERSION}
    container_name: ${MEDIATOR_NAME}-redis
    networks: [mediatornet]
    environment:
      ALLOW_EMPTY_PASSWORD: "yes"
  mediator:
    image: ${MEDIATOR_IMAGE}
    container_name: ${MEDIATOR_NAME}
    networks: [mediatornet]
    depends_on: [redis]
    ports:
      - "${MEDIATOR_PORT}:${MEDIATOR_PORT}"
$(for p in ${EXTRA_PORTS}; do echo "      - \"${p}:${p}\""; done)
    volumes:
      - ./conf:/app/conf
    working_dir: /app
    environment:
      RUST_LOG: info
      DATABASE_URL: redis://redis:6379/
      LISTEN_ADDRESS: 0.0.0.0:${MEDIATOR_PORT}
      MEDIATOR_ACL_MODE: explicit_deny
      GLOBAL_DEFAULT_ACL: "ALLOW_ALL"
EOF

  popd >/dev/null
  echo "✅ Mediator config generated"
else
  echo "✅ Mediator config already present at ${ABS_TARGET} (use --force to regenerate)"
fi

echo "TARGET_DIR=${ABS_TARGET}"
