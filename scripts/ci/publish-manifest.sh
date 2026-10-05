#!/usr/bin/env bash
# Assemble the per-arch digests (pushed by the build matrix) into one multi-arch
# manifest list under the derived tags, then resolve the published manifest
# digest for the provenance attestation. Run from the directory holding the
# per-digest marker files.
#
# Env:
#   IMAGE_NAME  target image reference without a tag, e.g. ghcr.io/owner/repo
#   META_JSON   docker/metadata-action JSON output (its .tags[] drive the -t set)
#   VERSION     semver tag used to resolve the published manifest digest
# Writes `digest=<sha256:...>` to $GITHUB_OUTPUT.
set -euo pipefail

: "${IMAGE_NAME:?}"
: "${META_JSON:?}"
: "${VERSION:?}"
: "${GITHUB_OUTPUT:?}"

# One -t flag per derived tag; reference each pushed digest as a manifest source
# so the list spans every built architecture.
tags=$(jq -cr '.tags | map("-t " + .) | join(" ")' <<<"$META_JSON")
sources=$(printf "${IMAGE_NAME}@sha256:%s " *)

# shellcheck disable=SC2086 # tags/sources are intentionally word-split into args
docker buildx imagetools create $tags $sources

digest=$(docker buildx imagetools inspect "${IMAGE_NAME}:${VERSION}" \
  --format '{{ json .Manifest.Digest }}' | tr -d '"')
echo "digest=$digest" >>"${GITHUB_OUTPUT}"
