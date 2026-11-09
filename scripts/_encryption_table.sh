#!/bin/bash

# The [encryption] table of a gateway config.toml. Sourced by scripts/_prepare.sh.
#
# The table is the [encryption] header and its [encryption.*] sub-tables, with every
# line up to the next other table header. A comment block between a blank line and
# that next header belongs to the next header, not to [encryption].

# Prints the [encryption] table of a config.toml. Prints nothing when it has none.
# Usage: encryption_table <config_toml>
encryption_table() {
  awk '
    function flush(before_header,   i, last) {
      last = n
      if (before_header) {
        i = n
        while (i > 1 && lines[i] ~ /^[ \t]*#/) i--
        if (i < n && lines[i] ~ /^[ \t]*$/) last = i
      }
      while (last > 0 && lines[last] ~ /^[ \t]*$/) last--
      for (i = 1; i <= last; i++) print lines[i]
      n = 0
    }
    /^[ \t]*\[encryption(\.[^]]*)?\]/ { on = 1; lines[++n] = $0; next }
    /^[ \t]*\[/ { if (on) flush(1); on = 0; next }
    on { lines[++n] = $0 }
    END { if (on) flush(0) }
  ' "$1"
}

# Replaces the [encryption] table of a config.toml with the given one, where the
# old one was, or appends it when the file has none.
# Usage: set_encryption_table <config_toml> <table>
set_encryption_table() {
  local file="$1"
  TABLE="$2" awk '
    function table() { print ENVIRON["TABLE"]; written = 1 }
    /^[ \t]*\[encryption(\.[^]]*)?\]/ {
      if (!written) table()
      skip = 1; pending = ""; after_blank = 0
      next
    }
    skip && /^[ \t]*\[/ { skip = 0; print ""; printf "%s", pending }
    skip {
      if ($0 ~ /^[ \t]*$/) { pending = ""; after_blank = 1 }
      else if (after_blank && $0 ~ /^[ \t]*#/) { pending = pending $0 "\n" }
      else { pending = ""; after_blank = 0 }
      next
    }
    { print }
    END { if (!written) { print ""; table() } }
  ' "${file}" > "${file}.tmp"
  mv "${file}.tmp" "${file}"
}

# Prints the [encryption] table of an environment the setup creates: a local one
# reads the master key from <master_key_file>, a Docker one from AG_MASTER_KEY.
# Usage: new_encryption_table <local|docker> <master_key_file>
new_encryption_table() {
  local kind="$1" key_file="$2"
  case "${kind}" in
    local)
      key_file="${key_file//\\/\\\\}"
      key_file="${key_file//\"/\\\"}"
      printf '[encryption]\nenabled = true\nkey_source = "file"\nkey_file = "%s"\n' "${key_file}"
      ;;
    docker)
      printf '[encryption]\nenabled = true\nkey_source = "environment"\nkey_env_var = "AG_MASTER_KEY"\n'
      ;;
    *)
      echo "new_encryption_table: unknown environment kind '${kind}'" >&2
      return 1
      ;;
  esac
}
