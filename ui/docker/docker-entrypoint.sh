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

{
  printf 'window.__SNG_CONFIG__ = {\n'
  printf '  "apiBaseUrl": "%s",\n' "$SNG_API_BASE_URL"
  printf '  "authMode": "%s",\n' "$SNG_AUTH_MODE"
  printf '  "oidcIssuer": "%s",\n' "$SNG_OIDC_ISSUER"
  printf '  "oidcClientId": "%s",\n' "$SNG_OIDC_CLIENT_ID"
  printf '  "oidcScope": "%s"\n' "$SNG_OIDC_SCOPE"
  printf '};\n'
} > "$CONFIG_PATH"

echo "sng-ui: wrote runtime config to $CONFIG_PATH (apiBaseUrl=$SNG_API_BASE_URL authMode=$SNG_AUTH_MODE)"
