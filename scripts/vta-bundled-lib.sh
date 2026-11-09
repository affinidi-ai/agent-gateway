# shellcheck shell=bash
# shellcheck disable=SC2154
# Shared by vta-bundled-compose-e2e.sh and vta-bundled-manual.sh (sourced, not run).
# Needs `repo` set, and `make config-debug` run once so `envs/local` and
# `envs/certs` exist.

# prepare_stack <dir>: copy the shipped Compose example into <dir>, with a gateway
# configuration, certificates and secrets made from the local dev environment.
prepare_stack() {
  local work="$1"
  for f in "${repo}/envs/local/config/config.toml" "${repo}/envs/certs/cert.pem"; do
    [[ -e "${f}" ]] || { echo "missing: ${f} (run make config-debug)" >&2; return 2; }
  done
  mkdir -p "${work}"
  cp -R "${repo}/config/examples/vta-bundled/." "${work}/"
  mkdir -p "${work}/config" "${work}/certs" "${work}/secrets"
  cp -R "${repo}/envs/local/config/." "${work}/config/"
  cp "${repo}/envs/certs/cert.pem" "${repo}/envs/certs/key.pem" "${work}/certs/"
  python3 - "${work}" "${repo}" <<'PY'
import sys
work, repo = sys.argv[1:3]
p = work + "/config/config.toml"
s = open(p).read()
s = s.replace(repo + "/envs/local/certs", "/app/certs").replace(repo + "/envs/local", "/app")
s = s.replace("TRUST_GATEWAY_MASTER_KEY", "TG_ENCRYPTION_KEY")
s = s.replace("env://TRUST_GATEWAY_BACKUP_ENCRYPTION_KEY", "env://AG_BACKUP_ENCRYPTION_KEY")
s += open(work + "/config.bundled.toml").read()
open(p, "w").write(s)

# The local dev gateway.json carries legacy channel and proxy prefixes that
# collide with the dashboard's pages once the image's dashboard is present, and a
# dashboard path on the host. A deployment would not have either.
import json
gp = work + "/config/gateway.json"
g = json.loads(open(gp).read().replace(repo + "/www/default/build", "/app/www").replace(repo + "/envs/local", "/app"))
g["channels"] = []
g["mcp_proxies"] = []
open(gp, "w").write(json.dumps(g, indent=2))
PY
  [[ -s "${work}/secrets/vta_seed_passphrase" ]] || openssl rand -base64 32 > "${work}/secrets/vta_seed_passphrase"
}

# export_stack_env: the variables the Compose file requires.
export_stack_env() {
  export TG_ENCRYPTION_KEY="${TG_ENCRYPTION_KEY:-$(openssl rand -base64 32)}"
  export AG_BACKUP_ENCRYPTION_KEY
  AG_BACKUP_ENCRYPTION_KEY="$(cat "${repo}/envs/backup_encryption_key")"
  export AG_IDENTITY_HASH_PEPPER
  AG_IDENTITY_HASH_PEPPER="$(cat "${repo}/envs/identity_hash_pepper")"
}
