#!/bin/bash
# Fixtures for the encryption at rest that the development setup turns on: the
# [encryption] table helpers, the master key scripts/_certs.sh generates, and the
# table scripts/_prepare.sh writes. Each setup run uses a scratch checkout with a
# stub cargo and a stub bootstrap binary, so nothing is built and neither envs/
# nor the system trust store is touched.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "${SCRIPT_DIR}")"
source "${SCRIPT_DIR}/_encryption_table.sh"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

failures=0

fail() {
  echo "❌ $1" >&2
  failures=$((failures + 1))
}

# Usage: expect_eq <case> <expected> <actual>
expect_eq() {
  if [[ "$3" != "$2" ]]; then
    fail "$1"
    diff -u <(printf '%s\n' "$2") <(printf '%s\n' "$3") >&2 || true
  fi
}

# Usage: write_file <path> <content>
write_file() {
  mkdir -p "$(dirname "$1")"
  printf '%s' "$2" > "$1"
}

# --- encryption_table ---------------------------------------------------------

file="${TEMP_DIR}/table.toml"

write_file "${file}" $'top = 1\n[tls]\ncert = "a"\n'
expect_eq "encryption_table: no table prints nothing" "" "$(encryption_table "${file}")"

write_file "${file}" $'top = 1\n\n# Encryption at rest\n[encryption]\n# Master switch\nenabled = true\nkey_source = "file"\n# kms_key_id = "arn"\n\n# Configuration file paths\n[config_files]\nlimits = "limits.json"\n'
expect_eq "encryption_table: stops before the next table and its comment" \
  $'[encryption]\n# Master switch\nenabled = true\nkey_source = "file"\n# kms_key_id = "arn"' \
  "$(encryption_table "${file}")"

write_file "${file}" $'[encryption]\nenabled = true\n[encryption.extra]\nx = 1\n[tls]\ncert = "a"\n'
expect_eq "encryption_table: keeps [encryption.*] sub-tables" \
  $'[encryption]\nenabled = true\n[encryption.extra]\nx = 1' \
  "$(encryption_table "${file}")"

write_file "${file}" $'[tls]\ncert = "a"\n\n[encryption]\nenabled = false\n# trailing note\n'
expect_eq "encryption_table: table at the end of the file" \
  $'[encryption]\nenabled = false\n# trailing note' \
  "$(encryption_table "${file}")"

# --- set_encryption_table -----------------------------------------------------

write_file "${file}" $'top = 1\n\n[encryption]\nenabled = false\nkey_source = "environment"\n[encryption.extra]\nx = 1\n\n# Configuration file paths\n[config_files]\nlimits = "limits.json"\n'
set_encryption_table "${file}" $'[encryption]\nenabled = true'
replaced=$'top = 1\n\n[encryption]\nenabled = true\n\n# Configuration file paths\n[config_files]\nlimits = "limits.json"'
expect_eq "set_encryption_table: replaces in place, keeps the next table's comment" \
  "${replaced}" "$(cat "${file}")"
set_encryption_table "${file}" $'[encryption]\nenabled = true'
expect_eq "set_encryption_table: is idempotent" "${replaced}" "$(cat "${file}")"

write_file "${file}" $'top = 1\n[tls]\ncert = "a"\n'
set_encryption_table "${file}" $'[encryption]\nenabled = true'
expect_eq "set_encryption_table: appends when the file has no table" \
  $'top = 1\n[tls]\ncert = "a"\n\n[encryption]\nenabled = true' \
  "$(cat "${file}")"

# --- new_encryption_table -----------------------------------------------------

expect_eq "new_encryption_table: local reads the key file" \
  $'[encryption]\nenabled = true\nkey_source = "file"\nkey_file = "/srv/envs/master_encryption_key"' \
  "$(new_encryption_table local /srv/envs/master_encryption_key)"
expect_eq "new_encryption_table: local escapes the path for TOML" \
  'key_file = "/srv/a\"b\\c/key"' \
  "$(new_encryption_table local '/srv/a"b\c/key' | grep '^key_file')"
expect_eq "new_encryption_table: docker reads AG_MASTER_KEY" \
  $'[encryption]\nenabled = true\nkey_source = "environment"\nkey_env_var = "AG_MASTER_KEY"' \
  "$(new_encryption_table docker /srv/envs/master_encryption_key)"
if new_encryption_table other /srv/key >/dev/null 2>&1; then
  fail "new_encryption_table: an unknown kind is refused"
fi

# --- scratch checkout ---------------------------------------------------------

# The checkout sits under a /local path component, which must not make
# envs/docker look like a local environment.
checkout="${TEMP_DIR}/usr/local/src/agent-gateway"
stub_bin="${TEMP_DIR}/bin"
mkdir -p "${checkout}/envs/certs" "${checkout}/target/debug" "${stub_bin}"
ln -s "${REPO_DIR}/config" "${checkout}/config"
touch "${checkout}/envs/certs/cert.pem" "${checkout}/envs/certs/key.pem"
printf '#!/bin/bash\n' > "${stub_bin}/cargo"
cat > "${checkout}/target/debug/agent-gateway" <<'EOF'
#!/bin/bash
cat <<'TOML'
channel_config_source = "local"
backup_encryption_key = "env://AG_BACKUP_ENCRYPTION_KEY"
auth_mode = "passkey"

[encryption]
enabled = false
key_source = "environment"
key_env_var = "AG_MASTER_KEY"

[config_files]
gateway = "gateway.json"
limits = "limits.json"

[did_cache]
allow_private_hosts = false
TOML
EOF
chmod +x "${stub_bin}/cargo" "${checkout}/target/debug/agent-gateway"
master_key_file="${checkout}/envs/master_encryption_key"

# Usage: in_checkout <script> [args...]
in_checkout() {
  (
    cd "${checkout}"
    env -u AG_IDENTITY_PEPPER_FILE -u AG_BACKUP_KEY_FILE -u AG_MASTER_KEY \
      PATH="${stub_bin}:${PATH}" bash "$@" </dev/null
  )
}

prepare() {
  in_checkout "${SCRIPT_DIR}/_prepare.sh" "$@" --auto-accept
}

# Runs a setup script in the checkout and records a failure, with the end of its
# output, when it exits non-zero.
# Usage: expect_runs <_certs.sh | _prepare.sh> [args...]
expect_runs() {
  local script="$1" output
  shift
  if [[ "${script}" == "_prepare.sh" ]]; then
    output="$(prepare "$@" 2>&1)" && return 0
  else
    output="$(in_checkout "${SCRIPT_DIR}/${script}" "$@" 2>&1)" && return 0
  fi
  fail "${script} $* exited non-zero"
  printf '%s\n' "${output}" | tail -n 5 >&2
}

# --- _prepare.sh before the key exists -----------------------------------------

if output="$(prepare debug envs/local 2>&1)"; then
  fail "_prepare.sh: a new environment without the master key is refused"
else
  [[ "${output}" == *"Run 'make config-certs'"* ]] || fail "_prepare.sh: the refusal names make config-certs"
fi
[[ ! -e "${checkout}/envs/local/config/config.toml" ]] || fail "_prepare.sh: no config.toml is written without the key"

# --- _certs.sh ----------------------------------------------------------------

expect_runs _certs.sh
key="$(cat "${master_key_file}" 2>/dev/null || true)"
[[ "${key}" =~ ^[0-9a-f]{64}$ ]] || fail "_certs.sh: the master key is 32 bytes in hex"
expect_eq "_certs.sh: the master key is owner-only" "-rw-------" "$(ls -l "${master_key_file}" | cut -c1-10)"
expect_runs _certs.sh
expect_eq "_certs.sh: a second run keeps the master key" "${key}" "$(cat "${master_key_file}")"

# --- _prepare.sh: new environments ----------------------------------------------

expect_runs _prepare.sh debug envs/local
local_config="${checkout}/envs/local/config/config.toml"
expect_eq "_prepare.sh: a new local environment reads the key file" \
  "$(new_encryption_table local "${master_key_file}")" \
  "$(encryption_table "${local_config}")"
expect_eq "_prepare.sh: a new config has one [encryption] table" "1" "$(grep -c '^\[encryption\]' "${local_config}")"
grep -q '^limits = "limits.json"' "${local_config}" || fail "_prepare.sh: the rest of the generated config is kept"

expect_runs _prepare.sh docker envs/docker
docker_config="${checkout}/envs/docker/config/config.toml"
expect_eq "_prepare.sh: a new Docker environment reads AG_MASTER_KEY, under a /local path too" \
  "$(new_encryption_table docker "${master_key_file}")" \
  "$(encryption_table "${docker_config}")"

before="$(encryption_table "${docker_config}" 2>/dev/null || true)"
expect_runs _prepare.sh docker envs/docker
expect_eq "_prepare.sh: a complete config keeps its [encryption] table" "${before}" "$(encryption_table "${docker_config}")"

# --- _prepare.sh: regenerated configs -------------------------------------------

custom=$'[encryption]\nenabled = true\nkey_source = "environment"\nkey_env_var = "OTHER_MASTER_KEY"'
set_encryption_table "${local_config}" "${custom}"
sed '/^limits = /d' "${local_config}" > "${local_config}.tmp" && mv "${local_config}.tmp" "${local_config}"
mv "${master_key_file}" "${master_key_file}.aside"
expect_runs _prepare.sh debug envs/local
mv "${master_key_file}.aside" "${master_key_file}"
expect_eq "_prepare.sh: a regenerated config keeps the old [encryption] table, without the key file" \
  "${custom}" "$(encryption_table "${local_config}")"
[[ -f "${local_config}.bak" ]] || fail "_prepare.sh: the replaced config is kept as config.toml.bak"

# Usage: expect_stays_unencrypted <env dir name> <old [encryption] table or "">
expect_stays_unencrypted() {
  local old_config="${checkout}/envs/$1/config/config.toml"
  write_file "${old_config}" $'backup_encryption_key = "env://AG_BACKUP_ENCRYPTION_KEY"\n\n'"$2"$'\n\n[config_files]\ngateway = "gateway.json"\n'
  expect_runs _prepare.sh debug "envs/$1"
  [[ "$(encryption_table "${old_config}")" == *"enabled = false"* ]] \
    || fail "_prepare.sh: an unencrypted environment stays unencrypted ($1)"
}
expect_stays_unencrypted local-2 ""
expect_stays_unencrypted local-3 $'[encryption]\nenabled = false'

# --- _certs.sh with encrypted storage and no key ---------------------------------

write_file "${checkout}/envs/local/_storage/vc_keys/issuer.json.enc" "ciphertext"
rm "${master_key_file}"
if output="$(in_checkout "${SCRIPT_DIR}/_certs.sh" 2>&1)"; then
  fail "_certs.sh: a lost master key is not replaced while encrypted storage exists"
else
  [[ "${output}" == *"issuer.json.enc"* ]] || fail "_certs.sh: the refusal names the encrypted file"
fi
[[ ! -e "${master_key_file}" ]] || fail "_certs.sh: no new master key is written over encrypted storage"

if [[ "${failures}" -gt 0 ]]; then
  echo "❌ ${failures} encryption setup fixture(s) failed" >&2
  exit 1
fi
echo "✅ Encryption setup fixtures passed"
