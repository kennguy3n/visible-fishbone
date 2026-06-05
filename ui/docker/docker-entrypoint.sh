#!/bin/sh
# Regenerate the runtime config consumed by the SPA (window.__SNG_CONFIG__).
#
# The static bundle is environment-agnostic; deploy-time configuration is
# supplied via environment variables and written to /config.js at container
# start. This is invoked automatically by the nginx image, which runs every
# executable in /docker-entrypoint.d before launching nginx.
set -eu

CONFIG_PATH="${SNG_CONFIG_PATH:-/usr/share/nginx/html/config.js}"

# Defaults keep the image bootable without any configuration.
SNG_API_BASE_URL="${SNG_API_BASE_URL:-/api/v1}"
SNG_AUTH_MODE="${SNG_AUTH_MODE:-jwt}"
SNG_OIDC_ISSUER="${SNG_OIDC_ISSUER:-}"
SNG_OIDC_CLIENT_ID="${SNG_OIDC_CLIENT_ID:-}"
SNG_OIDC_SCOPE="${SNG_OIDC_SCOPE:-openid profile email}"

# Emit a value as a quoted JSON string literal. The output is parsed by the
# JS engine when config.js loads as an inline <script>, so every character
# that is significant to JSON, JavaScript, or the HTML parser must be
# escaped. Without this, a value containing `"`, `\`, a newline, or the
# `</script>` sequence would break the bundle (leaving window.__SNG_CONFIG__
# unset) or allow script injection. We escape, in order:
#   \  -> \\        backslash first so later escapes aren't doubled
#   "  -> \"        string terminator
#   /  -> \/        so the substring </script> can never appear verbatim
#   newline -> \n   (JSON strings cannot contain raw newlines)
# The surrounding quotes are added by printf so an empty value still yields
# a valid "" literal.
json_string() {
  escaped=$(
    printf '%s' "$1" \
      | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's#/#\\/#g' \
      | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'
  )
  printf '"%s"' "$escaped"
}

{
  printf 'window.__SNG_CONFIG__ = {\n'
  printf '  "apiBaseUrl": %s,\n' "$(json_string "$SNG_API_BASE_URL")"
  printf '  "authMode": %s,\n' "$(json_string "$SNG_AUTH_MODE")"
  printf '  "oidcIssuer": %s,\n' "$(json_string "$SNG_OIDC_ISSUER")"
  printf '  "oidcClientId": %s,\n' "$(json_string "$SNG_OIDC_CLIENT_ID")"
  printf '  "oidcScope": %s\n' "$(json_string "$SNG_OIDC_SCOPE")"
  printf '};\n'
} > "$CONFIG_PATH"

echo "sng-ui: wrote runtime config to $CONFIG_PATH (apiBaseUrl=$SNG_API_BASE_URL authMode=$SNG_AUTH_MODE)"
