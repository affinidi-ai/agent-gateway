#!/bin/bash
set -euo pipefail

config_path="${1:?mediator.toml path required}"
mediator_url="${2:?mediator URL required}"
admin_did="${3:-}"
queued_send_messages_per_peer="${4:-}"

upsert_setting() {
  local section="$1"
  local key="$2"
  local value="$3"
  local temporary
  temporary="$(mktemp "${config_path}.XXXXXX")"
  cp -p "${config_path}" "${temporary}"

  if awk -v section="${section}" -v key="${key}" -v value="${value}" '
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
      if (in_section) {
        write_setting()
      }
      in_section = ($0 ~ "^[[:space:]]*\\[" section "\\][[:space:]]*$")
      if (in_section) {
        found_section = 1
      }
      print
      next
    }
    {
      if (in_section && $0 ~ "^[[:space:]]*" key "[[:space:]]*=") {
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
      if (in_section) {
        write_setting()
      }
      if (!found_section) {
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
      echo "❌ ${config_path} has no [${section}] section" >&2
    fi
    exit 1
  fi

  # Rewrite in place: replacing the file leaves Docker Desktop bind mounts
  # briefly serving the old, deleted copy to a mediator started right after.
  cat "${temporary}" > "${config_path}"
  rm -f "${temporary}"
}

upsert_setting "server" "local_endpoints" "[\"${mediator_url}\"]"
if [[ -n "${admin_did}" ]]; then
  upsert_setting "server" "admin_did" "\"did://${admin_did}\""
fi
if [[ -n "${queued_send_messages_per_peer}" ]]; then
  upsert_setting "limits" "queued_send_messages_per_peer" "\"${queued_send_messages_per_peer}\""
fi
