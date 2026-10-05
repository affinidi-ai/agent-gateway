#!/bin/bash
# Swap _storage/passkeys between auth modes.
# Must be called BEFORE auth_mode is changed in config.toml so the current
# value can be read as "old".
#
# Usage:
#   ./scripts/_swap-auth-storage.sh <target_dir> <new_auth_mode>
# Example:
#   ./scripts/_swap-auth-storage.sh envs/local-name saml

set -e

target_dir="${1:?target_dir required}"
new_auth="${2:?new_auth required (saml or passkey)}"

current_auth=$(grep -E '^auth_mode[[:space:]]*=' "${target_dir}/config/config.toml" \
  | sed 's/.*=[ ]*"\(.*\)".*/\1/' | head -1)

if [[ -z "${current_auth}" || "${current_auth}" == "${new_auth}" ]]; then
  exit 0
fi

storage_dir="${target_dir}/_storage"
current_passkeys="${storage_dir}/passkeys"
backup_dir="${storage_dir}/passkeys-${current_auth}"
restore_dir="${storage_dir}/passkeys-${new_auth}"

# 1. Archive current passkeys storage under the old auth name.
if [[ -d "${current_passkeys}" ]]; then
  mv "${current_passkeys}" "${backup_dir}"
  echo "💾 _storage/passkeys → _storage/passkeys-${current_auth}"
fi

# 2. Restore the new auth's passkeys storage (if a prior snapshot exists).
if [[ -d "${restore_dir}" ]]; then
  mv "${restore_dir}" "${current_passkeys}"
  echo "♻️  _storage/passkeys-${new_auth} → _storage/passkeys"
fi
