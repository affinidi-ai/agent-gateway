# shellcheck shell=bash
# Sourced URL/domain helpers shared by the mediator scripts.

mediator_normalize_domain() {
  local domain="$1"
  domain="${domain//%3A/:}"
  printf '%s' "${domain//%3a/:}"
}

mediator_url_for_domain() {
  case "$1" in
    localhost|localhost:*|127.0.0.1|127.0.0.1:*|\[::1\]|\[::1\]:*)
      printf 'http://%s' "$1"
      ;;
    *)
      printf 'https://%s' "$1"
      ;;
  esac
}

mediator_recipe_public_url() {
  printf 'public_url = "%s"' "$1"
}
