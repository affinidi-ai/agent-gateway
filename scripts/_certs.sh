#!/bin/bash

# -x Print out all executed commands to the terminal.
# set -x

# -e  Exit immediately if a command exits with a non-zero status.
set -e

current_dir=$(pwd)
envs_dir=envs

(mkdir -p "${envs_dir}" && echo "✅ ${envs_dir} directory created") || echo "✅ ${envs_dir} directory exist"

# Generate a persistent local identity pepper (hex, 32 bytes) so credential-derived
# agent DIDs are stable across restarts and shared across local instances. The
# Makefile reads this file into AG_IDENTITY_HASH_PEPPER. Absent = ephemeral pepper.
pepper_file="${AG_IDENTITY_PEPPER_FILE:-${envs_dir}/identity_hash_pepper}"
if [[ ! -s "${pepper_file}" ]]
then
  mkdir -p "$(dirname "${pepper_file}")"
  openssl rand -hex 32 > "${pepper_file}"
  chmod 600 "${pepper_file}"
  echo "🔑 Generated local identity pepper (${pepper_file})"
fi

# Generate a persistent local backup encryption key (hex, 32 bytes). The backup key
# is required at runtime; the Makefile reads this file into AG_BACKUP_ENCRYPTION_KEY so
# local backups/restores work seamlessly. This dev key is local-only (envs/ is gitignored).
backup_key_file="${AG_BACKUP_KEY_FILE:-${envs_dir}/backup_encryption_key}"
if [[ ! -s "${backup_key_file}" ]]
then
  mkdir -p "$(dirname "${backup_key_file}")"
  openssl rand -hex 32 > "${backup_key_file}"
  chmod 600 "${backup_key_file}"
  echo "🔑 Generated local backup encryption key (${backup_key_file})"
fi

# Generate a persistent master key (hex, 32 bytes) for encryption at rest. Every
# environment scripts/_prepare.sh creates encrypts its storage with it. Keep it:
# without it the storage it encrypted cannot be read. A missing key is not replaced
# while encrypted storage is left, since a new key cannot read it.
master_key_file="${envs_dir}/master_encryption_key"
if [[ ! -s "${master_key_file}" ]]
then
  encrypted_file="$(find "${envs_dir}" -path '*/_storage/*' -name '*.enc' -print 2>/dev/null | head -n 1)"
  if [[ -n "${encrypted_file}" ]]
  then
    echo "❌ ${master_key_file} is missing, but storage under ${envs_dir} is encrypted (${encrypted_file})."
    echo "   A new key cannot read it. Restore the key to ${master_key_file}, or move the"
    echo "   encrypted environments out of ${envs_dir}, then run 'make config-certs' again."
    exit 1
  fi
  (umask 077 && openssl rand -hex 32 > "${master_key_file}")
  chmod 600 "${master_key_file}"
  echo "🔑 Generated local master encryption key (${master_key_file})"
fi

if [[ ! -f "${envs_dir}/certs/cert.pem" ]]
then
  cd "${envs_dir}"
  mkdir -p config/certs
  "${current_dir}/scripts/certs/generate-cert.sh"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain config/certs/cert.pem
  else
    echo "ℹ️  Generated the development certificate without changing the Linux trust store."
  fi
  rm -Rf certs && mv config/certs .
  rm -Rf config
fi
