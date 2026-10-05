#!/bin/bash
# Apply SAML authentication configuration to a target env directory.
# Downloads the IdP certificate once into envs/certs/ (shared), copies it to
# the target env, switches auth_mode to "saml" in config.toml, and substitutes
# $AZURE_TENANT and the SP domain placeholders in config/saml.json.
#
# Usage:
#   ./scripts/_saml-setup.sh <target_dir> <azure_tenant>
# Example:
#   ./scripts/_saml-setup.sh envs/local-name 06244208-f06b-4a99-85d8-ca5481d17d2e

set -e

source "$(dirname "$0")/_env.sh"
source "$(dirname "$0")/_portable.sh"

# Values the sourced helpers above must provide.
: "${envs_dir:?_env.sh must set envs_dir}"

target_dir="${1:?target_dir required (e.g. envs/local-name)}"
azure_tenant="${2:?AZURE_TENANT required — pass as: make run-debug auth=saml AZURE_TENANT=<tenant-guid>}"

# Read public hostname from gateway.json (set during _prepare.sh).
domain_url=$(jq -r '[.. | objects | select(has("external_origin")) | .external_origin] | first // empty' \
  "${target_dir}/config/gateway.json" 2>/dev/null || true)
domain_host=""
if [[ -n "${domain_url}" && "${domain_url}" != "null" ]]; then
  domain_host="${domain_url#*://}"   # strip scheme
  domain_host="${domain_host%%/*}"   # strip path and trailing slash
fi

# 1. Copy the IdP cert into the shared envs/certs/ directory on every
# explicit `auth=saml` run (this script only runs when that flag is passed).
# The cert is the Entra app's per-application "Microsoft Azure Federated SSO
# Certificate" (Entra: Enterprise Applications > your app > Single sign-on >
# SAML Certificates > Certificate (Base64)), NOT the tenant-wide cert(s) at the
# generic tenant federation metadata endpoint, which do not carry the app's
# signing cert. Place it at config/certs/saml-idp.cer (gitignored); it
# is re-copied on every run so a rotation rolls out to every env.
idp_cert="$(pwd)/config/certs/saml-idp.cer"
if [[ ! -f "${idp_cert}" ]]; then
  echo "❌ SAML IdP certificate not found at config/certs/saml-idp.cer" >&2
  echo "   Download it from Entra: Enterprise Applications > your app > Single sign-on >" >&2
  echo "   SAML Certificates > Certificate (Base64), and save it at that path." >&2
  exit 1
fi
mkdir -p "${envs_dir}/certs"
local_cert="${envs_dir}/certs/affinidi-trust-fabric-sso.cer"
cp "${idp_cert}" "${local_cert}"
echo "✅ IdP certificate → envs/certs/affinidi-trust-fabric-sso.cer"

# 2. Copy cert into the target env certs/ so the gateway can read it at startup.
mkdir -p "${target_dir}/certs"
cp "${local_cert}" "${target_dir}/certs/affinidi-trust-fabric-sso.cer"
cp "${envs_dir}/certs/key.pem" "${target_dir}/certs/saml-sp-key.pem"
cp "${envs_dir}/certs/cert.pem" "${target_dir}/certs/saml-sp-cert.pem"

# 3. Swap _storage/passkeys before changing auth_mode.
"$(dirname "$0")/_swap-auth-storage.sh" "${target_dir}" "saml"

# 4. Switch auth_mode to "saml" in config.toml (idempotent).
sedi 's/auth_mode = "passkey"/auth_mode = "saml"/' "${target_dir}/config/config.toml"

# 5. Substitute $AZURE_TENANT placeholder in saml.json (idempotent — no-op if already replaced).
sedi "s|\\\$AZURE_TENANT|${azure_tenant}|g" "${target_dir}/config/saml.json"

# 6. Replace the template SP domain in sp_acs_url only (leave sp_entity_id/metadata untouched).
# NOTE: sp_entity_id ("https://agent-gateway-1.example.com/api/saml/metadata") must stay
#       as-is — it is the registered entity ID in Entra and must not be changed per-instance.
if [[ -n "${domain_host}" ]]; then
  sedi "/\/api\/saml\/acs/s|agent-gateway-1\.example\.com|${domain_host}|" "${target_dir}/config/saml.json"
  echo "✅ SAML configured: tenant=${azure_tenant}, domain=${domain_host}"
else
  echo "✅ SAML configured: tenant=${azure_tenant} (no public domain set — sp_acs_url uses template placeholder)"
fi

# ──────────────────────────────────────────────────────────────────────────────
_entra_notice_marker="${target_dir}/.saml_entra_notice_shown"
if [[ ! -f "${_entra_notice_marker}" ]]; then
  _BOLD=$'\033[1m'
  _CYAN=$'\033[0;36m'
  _YELLOW=$'\033[1;33m'
  _NC=$'\033[0m'
  echo ""
  echo "${_YELLOW}╔══════════════════════════════════════════════════════════════════╗${_NC}"
  echo "${_YELLOW}║  ⚠️   ACTION REQUIRED — Register these redirect URIs with your   ║${_NC}"
  echo "${_YELLOW}║       identity administrator:                                    ║${_NC}"
  echo "${_YELLOW}╚══════════════════════════════════════════════════════════════════╝${_NC}"
  echo ""
  echo "${_YELLOW}  ┌─ select & copy both lines ─────────────────────────────────────${_NC}"
  if [[ -n "${domain_host}" ]]; then
    echo "${_BOLD}${_CYAN}  https://${domain_host}/acs/entra${_NC}"
    echo "${_BOLD}${_CYAN}  https://${domain_host}/oidc-callback/entra${_NC}"
  else
    echo "${_BOLD}${_CYAN}  https://<your-domain>/acs/entra${_NC}"
    echo "${_BOLD}${_CYAN}  https://<your-domain>/oidc-callback/entra${_NC}"
  fi
  echo "${_YELLOW}  └────────────────────────────────────────────────────────────────${_NC}"
  echo ""
  read -r -p "Press Enter once your identity administrator has registered the URLs..." _
  touch "${_entra_notice_marker}"
fi
