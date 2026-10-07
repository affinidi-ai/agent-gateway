#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECONCILE="${SCRIPT_DIR}/reconcile-mediator-config.sh"
source "${SCRIPT_DIR}/_url.sh"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

run_case() {
  local name="$1"
  local input="$2"
  local expected="$3"
  local per_peer="${4:-}"
  local config="${TEMP_DIR}/${name}.toml"
  local first_run="${TEMP_DIR}/${name}.first.toml"

  printf '%s' "${input}" > "${config}"
  "${RECONCILE}" "${config}" "https://mediator.example.com" "did:example:admin" "${per_peer}"

  if [[ "$(cat "${config}")" != "${expected}" ]]; then
    echo "❌ ${name}: unexpected reconciled config" >&2
    diff -u <(printf '%s' "${expected}") "${config}" >&2 || true
    return 1
  fi

  cp "${config}" "${first_run}"
  "${RECONCILE}" "${config}" "https://mediator.example.com" "did:example:admin" "${per_peer}"
  if ! cmp -s "${first_run}" "${config}"; then
    echo "❌ ${name}: reconciliation is not idempotent" >&2
    diff -u "${first_run}" "${config}" >&2 || true
    return 1
  fi
}

run_case \
  "fresh" \
  $'[server]\nlisten_address = "0.0.0.0:7037"\n\n[database]\nurl = "redis://localhost/"\n' \
  $'[server]\nlisten_address = "0.0.0.0:7037"\n\nlocal_endpoints = ["https://mediator.example.com"]\nadmin_did = "did://did:example:admin"\n[database]\nurl = "redis://localhost/"'

run_case \
  "single-line" \
  $'[server]\nlocal_endpoints = ["http://old.example.com"]\nadmin_did = "did://did:old:admin"\n' \
  $'[server]\nlocal_endpoints = ["https://mediator.example.com"]\nadmin_did = "did://did:example:admin"'

run_case \
  "duplicate" \
  $'[server]\nlocal_endpoints = ["http://first.example.com"]\nadmin_did = "did://did:first:admin"\nlocal_endpoints = ["http://second.example.com"]\nadmin_did = "did://did:second:admin"\n' \
  $'[server]\nlocal_endpoints = ["https://mediator.example.com"]\nadmin_did = "did://did:example:admin"'

run_case \
  "multi-line" \
  $'[server]\nlocal_endpoints = [\n  "http://first.example.com",\n  "http://second.example.com", # old endpoint\n]\nadmin_did = "did://did:old:admin"\n\n[database]\nurl = "redis://localhost/"\n' \
  $'[server]\nlocal_endpoints = ["https://mediator.example.com"]\nadmin_did = "did://did:example:admin"\n\n[database]\nurl = "redis://localhost/"'

run_case \
  "per-peer-replaced" \
  $'[server]\nadmin_did = "did://did:example:admin"\n\n[limits]\nqueued_send_messages_per_peer = "50"\nqueued_send_messages_soft = "2000"\n' \
  $'[server]\nadmin_did = "did://did:example:admin"\n\nlocal_endpoints = ["https://mediator.example.com"]\n[limits]\nqueued_send_messages_per_peer = "150"\nqueued_send_messages_soft = "2000"' \
  "150"

run_case \
  "per-peer-inserted" \
  $'[server]\nadmin_did = "did://did:example:admin"\n\n[limits]\nqueued_send_messages_soft = "200"\n\n[database]\nurl = "redis://localhost/"\n' \
  $'[server]\nadmin_did = "did://did:example:admin"\n\nlocal_endpoints = ["https://mediator.example.com"]\n[limits]\nqueued_send_messages_soft = "200"\n\nqueued_send_messages_per_peer = "150"\n[database]\nurl = "redis://localhost/"' \
  "150"

run_case \
  "per-peer-unset-leaves-limits" \
  $'[server]\nadmin_did = "did://did:example:admin"\n\n[limits]\nqueued_send_messages_per_peer = "50"\n' \
  $'[server]\nadmin_did = "did://did:example:admin"\n\nlocal_endpoints = ["https://mediator.example.com"]\n[limits]\nqueued_send_messages_per_peer = "50"'

missing_limits="${TEMP_DIR}/missing-limits.toml"
printf '%s' $'[server]\nadmin_did = "did://did:example:admin"\n' > "${missing_limits}"
if "${RECONCILE}" "${missing_limits}" "https://mediator.example.com" "did:example:admin" "150" >/dev/null 2>&1; then
  echo "❌ missing-limits: reconciliation unexpectedly succeeded" >&2
  exit 1
fi

missing_server="${TEMP_DIR}/missing-server.toml"
missing_server_before="${TEMP_DIR}/missing-server.before.toml"
printf '%s' $'[database]\nurl = "redis://localhost/"\n' > "${missing_server}"
cp "${missing_server}" "${missing_server_before}"
if "${RECONCILE}" "${missing_server}" "https://mediator.example.com" "did:example:admin" >/dev/null 2>&1; then
  echo "❌ missing-server: reconciliation unexpectedly succeeded" >&2
  exit 1
fi
if ! cmp -s "${missing_server_before}" "${missing_server}"; then
  echo "❌ missing-server: failed reconciliation mutated the config" >&2
  exit 1
fi

assert_scheme_consistency() {
  local name="$1"
  local domain="$2"
  local expected_url="$3"
  local config="${TEMP_DIR}/${name}.toml"
  local first_run="${TEMP_DIR}/${name}.first.toml"
  local mediator_url
  local recipe_public_url

  mediator_url="$(mediator_url_for_domain "${domain}")"
  recipe_public_url="$(mediator_recipe_public_url "${mediator_url}")"
  printf '%s' $'[server]\nlocal_endpoints = ["http://stale.example.com"]\n' > "${config}"
  "${RECONCILE}" "${config}" "${mediator_url}"

  if [[ "${recipe_public_url}" != "public_url = \"${expected_url}\"" ]] \
    || ! grep -Fqx "local_endpoints = [\"${expected_url}\"]" "${config}"; then
    echo "❌ ${name}: recipe public_url and local_endpoints do not match ${expected_url}" >&2
    return 1
  fi

  cp "${config}" "${first_run}"
  "${RECONCILE}" "${config}" "${mediator_url}"
  if ! cmp -s "${first_run}" "${config}"; then
    echo "❌ ${name}: URL reconciliation is not idempotent" >&2
    return 1
  fi
}

assert_scheme_consistency "localhost-scheme" "localhost:7037" "http://localhost:7037"
assert_scheme_consistency "public-scheme" "mediator.example.com" "https://mediator.example.com"

assert_legacy_domain_normalizes() {
  local name="$1"
  local stored="$2"
  local expected_url="$3"
  local env_file="${TEMP_DIR}/${name}.env"
  local domain

  printf 'MEDIATOR_DOMAIN=%s\n' "${stored}" > "${env_file}"
  domain=$(mediator_normalize_domain "$(grep -E '^MEDIATOR_DOMAIN=' "${env_file}" | cut -d '=' -f2)")

  if [[ "$(mediator_url_for_domain "${domain}")" != "${expected_url}" ]]; then
    echo "❌ ${name}: stored domain ${stored} did not resolve to ${expected_url}" >&2
    return 1
  fi
}

assert_legacy_domain_normalizes "legacy-encoded-colon" "localhost%3A7037" "http://localhost:7037"
assert_legacy_domain_normalizes "legacy-encoded-colon-lowercase" "localhost%3a7037" "http://localhost:7037"
assert_legacy_domain_normalizes "plain-colon-unchanged" "localhost:7037" "http://localhost:7037"
assert_legacy_domain_normalizes "public-domain-unchanged" "mediator.example.com" "https://mediator.example.com"

echo "✅ mediator config reconciliation fixtures passed"
