#!/bin/bash
# Switch a target env back to passkey authentication mode.
# Reverses the auth_mode change made by _saml-setup.sh.
#
# Usage:
#   ./scripts/_passkey-setup.sh <target_dir>
# Example:
#   ./scripts/_passkey-setup.sh envs/local-name

set -e

source "$(dirname "$0")/_env.sh"
source "$(dirname "$0")/_portable.sh"

target_dir="${1:?target_dir required (e.g. envs/local-name)}"

# Swap _storage/passkeys before changing auth_mode.
"$(dirname "$0")/_swap-auth-storage.sh" "${target_dir}" "passkey"

# Switch auth_mode back to "passkey" in config.toml (idempotent).
sedi 's/auth_mode = "saml"/auth_mode = "passkey"/' "${target_dir}/config/config.toml"

echo "✅ auth_mode switched to passkey"
