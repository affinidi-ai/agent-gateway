#!/bin/bash
set -euo pipefail

config_path="${1:?mediator.toml path required}"
mediator_url="${2:?mediator URL required}"
admin_did="${3:-}"

upsert_server_setting() {
  local key="$1"
  local value="$2"
  local temporary
  temporary="$(mktemp "${config_path}.XXXXXX")"
  cp -p "${config_path}" "${temporary}"

  if awk -v key="${key}" -v value="${value}" '
    BEGIN {
      single_quote = sprintf("%c", 39)
    }
    function write_setting() {
      if (!written) {
        print key " = " value
        written = 1
      }
    }
    function array_balance(text,    i, char, escaped, quote, balance) {
      for (i = 1; i <= length(text); i++) {
        char = substr(text, i, 1)
        if (quote != "") {
          if (escaped) {
            escaped = 0
          } else if (quote == "\"" && char == "\\") {
            escaped = 1
          } else if (char == quote) {
            quote = ""
          }
        } else if (char == "#") {
          break
        } else if (char == "\"" || char == single_quote) {
          quote = char
        } else if (char == "[") {
          balance++
        } else if (char == "]") {
          balance--
        }
      }
      return balance
    }
    consuming {
      remaining += array_balance($0)
      if (remaining < 0) {
        malformed = 1
        exit 2
      }
      if (remaining == 0) {
        consuming = 0
      }
      next
    }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
      if (in_server) {
        write_setting()
      }
      in_server = ($0 ~ /^[[:space:]]*\[server\][[:space:]]*$/)
      if (in_server) {
        found_server = 1
      }
      print
      next
    }
    {
      if (in_server && $0 ~ "^[[:space:]]*" key "[[:space:]]*=") {
        write_setting()
        remaining = array_balance(substr($0, index($0, "=") + 1))
        if (remaining < 0) {
          malformed = 1
          exit 2
        }
        consuming = (remaining > 0)
        next
      }
      print
    }
    END {
      if (consuming || malformed) {
        exit 2
      }
      if (in_server) {
        write_setting()
      }
      if (!found_server) {
        exit 1
      }
    }
  ' "${config_path}" > "${temporary}"; then
    :
  else
    status=$?
    rm -f "${temporary}"
    if [[ "${status}" -eq 2 ]]; then
      echo "❌ ${config_path} has a malformed multi-line ${key} value" >&2
    else
      echo "❌ ${config_path} has no [server] section" >&2
    fi
    exit 1
  fi

  mv "${temporary}" "${config_path}"
}

upsert_server_setting "local_endpoints" "[\"${mediator_url}\"]"
if [[ -n "${admin_did}" ]]; then
  upsert_server_setting "admin_did" "\"did://${admin_did}\""
fi
