#!/bin/sh
# Entrypoint for the bundled sidecar VTA. Idempotent, and safe to kill at any
# point: the next start finishes whatever was left undone.
#
#   1. set the VTA up once, with no admin (the super-admin slot stays empty)
#   2. wait for the gateway's control DID, then register it with a fixed,
#      narrow grant, offline, before the daemon ever listens
#   3. publish the VTA's own DID for the gateway to pin
#   4. run the daemon
#
# Never `source`s or `eval`s a file the gateway wrote: it reads one value and
# checks it against a strict pattern. The context and the capabilities are fixed
# here, never taken from the gateway.
set -eu

DATA="${BUNDLED_DATA:-/var/lib/vta}"
BOOT="${BUNDLED_BOOT:-/bootstrap}"
SETUP="${BUNDLED_SETUP:-/etc/vta/setup.base.toml}"
WAIT_SECS="${BUNDLED_WAIT_SECS:-300}"
CONFIG="$DATA/config.toml"
MARK="$DATA/.gateway-enrolled"

CTX=gateway
ROLE=initiator
CAPS=context-create,key-mint,sign-jws,sign-document
DID_RE='^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{40,60}$'

if [ ! -f "$CONFIG" ]; then
  vta setup --from "$SETUP"
fi

if [ ! -f "$MARK" ]; then
  waited=0
  while [ ! -s "$BOOT/gateway-enrolment.env" ]; do
    waited=$((waited + 1))
    if [ "$waited" -gt "$WAIT_SECS" ]; then
      echo "vta-entrypoint: no gateway enrolment after ${WAIT_SECS}s" >&2
      exit 1
    fi
    sleep 1
  done
  GW_DID=$(sed -n 's/^GATEWAY_CONTROL_DID=//p' "$BOOT/gateway-enrolment.env" | head -n 1)
  printf '%s' "$GW_DID" | grep -Eq "$DID_RE" || {
    echo "vta-entrypoint: refusing a malformed gateway DID" >&2
    exit 1
  }

  vta --config "$CONFIG" contexts get "$CTX" >/dev/null 2>&1 \
    || vta --config "$CONFIG" contexts create --id "$CTX" --name "Agent Gateway"
  vta --config "$CONFIG" acl get "$GW_DID" >/dev/null 2>&1 \
    || vta --config "$CONFIG" acl create --did "$GW_DID" --role "$ROLE" \
         --contexts "$CTX" --capabilities "$CAPS" --label agent-gateway-bundled
  echo "vta-entrypoint: enrolled $GW_DID as $ROLE in $CTX with $CAPS (offline, break-glass)" >&2
  : > "$MARK"
fi

VTA_DID=$(sed -n 's/^vta_did[[:space:]]*=[[:space:]]*"\(did:[^"]*\)".*/\1/p' "$CONFIG" | head -n 1)
if [ -z "$VTA_DID" ]; then
  echo "vta-entrypoint: no vta_did in $CONFIG" >&2
  exit 1
fi
printf 'FORMAT=1\nVTA_DID=%s\nBASE_URL=http://127.0.0.1:8100\n' "$VTA_DID" > "$BOOT/vta-identity.env.tmp"
mv "$BOOT/vta-identity.env.tmp" "$BOOT/vta-identity.env"

exec vta --config "$CONFIG"
