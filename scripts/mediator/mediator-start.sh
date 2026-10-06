#!/bin/bash

current_dir=$(pwd)
source "$(dirname "$0")/_url.sh"

# must contain trailing slash
TARGET_DIR="${current_dir}/envs/mediator/"
VERSION="v0.33.1"
MEDIATOR_IMAGE="public.ecr.aws/affinidi/messaging-mediator:${VERSION}"
MEDIATOR_PORT="7037"
# Plain host:port — used for the prompt, the recipe public_url, and the healthchecker
# URLs. The did:web/did:webvh identifier needs its port colon percent-encoded (%3A);
# that encoding is applied only where the DID is built (see below), not stored here.
MEDIATOR_DOMAIN="localhost:${MEDIATOR_PORT}"
MEDIATOR_ACL_MODE="explicit_deny"
# GLOBAL_DEFAULT_ACL="DENY_ALL,ALLOW_ALL_SELF_CHANGE,SEND_MESSAGES,RECEIVE_MESSAGES,SEND_FORWARDED,RECEIVE_FORWARDED,CREATE_INVITES,ANON_RECEIVE,SELF_MANAGE_LIST,SELF_MANAGE_SEND_QUEUE_LIMIT,SELF_MANAGE_RECEIVE_QUEUE_LIMIT,MODE_SELF_CHANGE,MODE_EXPLICIT_DENY,LOCAL"
# GLOBAL_DEFAULT_ACL="ALLOW_ALL,ALLOW_ALL_SELF_CHANGE,MODE_SELF_CHANGE,MODE_EXPLICIT_DENY,LOCAL"
GLOBAL_DEFAULT_ACL="ALLOW_ALL"
MEDIATOR_ENV="{}"
DID_METHOD="webvh"
DID_WEB_FROM_DID_WEBVH="true"
BLOCK_ANONYMOUS_OUTER_ENVELOPE="false"
USE_P256_KEY_SUITE="true"
ADMIN_DID=""
# A gateway keeps each fabric message queued until processed; the mediator's
# default per-peer cap of 50 times out larger bursts to one peer gateway.
QUEUED_SEND_MESSAGES_PER_PEER="150"

# check if envs/mediator exists and ask for mediator domain if it doesn't exist
if [ -d "${TARGET_DIR}" ]; then
    # fetch the mediator domain from the existing envs/mediator/mediator.env file
    if [ -f "${TARGET_DIR}/mediator.env" ]; then
        # Older revisions stored the DID-encoded form (localhost%3A7037); decode it back to a
        # plain host:port so URL building and tunnel matching see a real colon.
        MEDIATOR_DOMAIN=$(mediator_normalize_domain "$(grep -E '^MEDIATOR_DOMAIN=' "${TARGET_DIR}/mediator.env" | cut -d '=' -f2)")
    fi
else
    echo "${TARGET_DIR} directory does not exist."
    mkdir -p "${TARGET_DIR}"

    echo "Enter public URL for this mediator (e.g., https://mediator.example.com), leave empty for default (http://${MEDIATOR_DOMAIN}):"
    read -r MEDIATOR_URL
    if [ -z "$MEDIATOR_URL" ]; then
        MEDIATOR_URL="http://${MEDIATOR_DOMAIN}"
    fi
    MEDIATOR_DOMAIN=$(echo "$MEDIATOR_URL" | sed -E 's|https?://([^/]+).*|\1|')
    echo "Mediator domain set to: ${MEDIATOR_DOMAIN}"
    echo "MEDIATOR_DOMAIN=${MEDIATOR_DOMAIN}" > "${TARGET_DIR}/mediator.env"
fi

MEDIATOR_URL="$(mediator_url_for_domain "${MEDIATOR_DOMAIN}")"

echo "📦 Starting Affinidi Mediator..."

"${current_dir}/scripts/mediator/user-data-v2.sh" \
    "${TARGET_DIR}" \
    "${MEDIATOR_IMAGE}" \
    "${MEDIATOR_URL}" \
    "${MEDIATOR_PORT}" \
    "${MEDIATOR_ACL_MODE}" \
    "${GLOBAL_DEFAULT_ACL}" \
    "${MEDIATOR_ENV}" \
    "${DID_METHOD}" \
    "${DID_WEB_FROM_DID_WEBVH}" \
    "${BLOCK_ANONYMOUS_OUTER_ENVELOPE}" \
    "${USE_P256_KEY_SUITE}" \
    "${ADMIN_DID}" \
    "${QUEUED_SEND_MESSAGES_PER_PEER}"

echo "✅ Mediator setup done!"

echo "📦 Mediator is running at: ${MEDIATOR_URL}/healthchecker"
echo "📦 Mediator did doc:       ${MEDIATOR_URL}/.well-known/did.json"
# get webvh did from envs/mediator/affinidi-messaging/conf/did.jsonl .id
scid=$(jq -r '.parameters.scid' "${TARGET_DIR}/affinidi-messaging/conf/did.jsonl" 2>/dev/null)
# did:web/did:webvh requires the port colon to be percent-encoded (localhost:7037 → localhost%3A7037).
did_domain="${MEDIATOR_DOMAIN//:/%3A}"
echo "📦 Mediator SCID:          ${scid}"
echo "📦 Mediator DID:           did:webvh:${scid}:${did_domain}"
