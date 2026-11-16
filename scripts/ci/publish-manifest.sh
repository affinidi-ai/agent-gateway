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

# One -t flag per derived tag.
tag_args=()
while IFS= read -r line; do
  tag_args+=("${line}")
done < <(jq -r '.tags[] | "-t", .' <<<"$META_JSON")

# Each marker file is named after a pushed digest. Refuse anything else so a
# stray or tampered file cannot add an arbitrary source reference.
sources=()
for marker in *; do
  if [[ ! "${marker}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "::error::unexpected digest marker '${marker}'"
    exit 1
  fi
  sources+=("${IMAGE_NAME}@sha256:${marker}")
done

docker buildx imagetools create "${tag_args[@]}" "${sources[@]}"

digest=$(docker buildx imagetools inspect "${IMAGE_NAME}:${VERSION}" \
  --format '{{ json .Manifest.Digest }}' | tr -d '"')
echo "digest=$digest" >>"${GITHUB_OUTPUT}"
