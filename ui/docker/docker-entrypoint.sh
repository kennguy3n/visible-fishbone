#!/bin/sh
# Regenerate the runtime config consumed by the SPA (window.__SNG_CONFIG__).
#
# The static bundle is environment-agnostic; deploy-time configuration is
# supplied via environment variables and written to /config.js at container
# start. This is invoked automatically by the nginx image, which runs every
# executable in /docker-entrypoint.d before launching nginx.
set -eu

CONFIG_PATH="${SNG_CONFIG_PATH:-/usr/share/nginx/html/config.js}"
CSP_PATH="${SNG_CSP_PATH:-/etc/nginx/snippets/sng-csp.conf}"

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
#   tab -> \t, CR -> \r, newline -> \n   (JSON forbids raw control chars)
# These four whitespace controls are the only C0 characters that plausibly
# appear in a deployment env var (URLs, client IDs, scopes); other control
# bytes are not handled because they cannot occur here in practice.
# The surrounding quotes are added by printf so an empty value still yields
# a valid "" literal.
json_string() {
  escaped=$(
    printf '%s' "$1" \
      | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's#/#\\/#g' \
      | sed -e 's/\t/\\t/g' -e 's/\r/\\r/g' \
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

# --- Content-Security-Policy generation ---------------------------------
# The CSP `connect-src` must list every origin the SPA legitimately calls
# (XHR/fetch). Those origins — the API and the OIDC IdP — are only known at
# deploy time via the same env vars that drive config.js, so we generate the
# CSP header here instead of baking a permissive `https:` into the image. This
# narrows the policy from "any HTTPS host" to "self + the configured backends",
# so a hypothetical script-injection can't exfiltrate to an arbitrary endpoint.
#
# Inputs:
#   SNG_API_BASE_URL      — relative (e.g. /api/v1 => same-origin, needs nothing
#                           beyond 'self') or absolute (its origin is allowed).
#   SNG_OIDC_ISSUER       — when set, its origin is allowed (discovery + token).
#   SNG_CSP_CONNECT_EXTRA — optional space-separated extra sources, e.g. an IdP
#                           whose token_endpoint lives on a different origin than
#                           the issuer (the token endpoint comes from discovery
#                           and can't be derived here).
#   SNG_CSP_CONNECT_SRC   — optional full override of the connect-src value.

# Echo scheme://host[:port] for an absolute http(s) URL; nothing otherwise (so
# a relative apiBaseUrl contributes no cross-origin source).
origin_of() {
  case "$1" in
    http://* | https://*)
      printf '%s' "$1" |
        sed -E 's#^([a-zA-Z][a-zA-Z0-9+.-]*://[^/]+).*#\1#'
      ;;
    *) : ;;
  esac
}

if [ -n "${SNG_CSP_CONNECT_SRC:-}" ]; then
  CONNECT_SRC="$SNG_CSP_CONNECT_SRC"
else
  CONNECT_SRC="'self'"
  for url in "$SNG_API_BASE_URL" "$SNG_OIDC_ISSUER"; do
    o=$(origin_of "$url")
    [ -n "$o" ] || continue
    case " $CONNECT_SRC " in *" $o "*) ;; *) CONNECT_SRC="$CONNECT_SRC $o" ;; esac
  done
  # Word-splitting on the extras is intentional (space-separated list).
  # shellcheck disable=SC2086
  for extra in ${SNG_CSP_CONNECT_EXTRA:-}; do
    case " $CONNECT_SRC " in *" $extra "*) ;; *) CONNECT_SRC="$CONNECT_SRC $extra" ;; esac
  done
fi

# Single quotes inside the double-quoted shell string are literal, so the CSP
# keywords ('self', 'none', …) need no extra escaping. CSP values never contain
# a double quote, so wrapping in printf's "%s" is safe.
CSP_VALUE="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src ${CONNECT_SRC}; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"

# A double quote can only enter via the operator-supplied connect-src overrides
# (SNG_CSP_CONNECT_SRC / SNG_CSP_CONNECT_EXTRA); a legitimate CSP value never
# has one. If one slips in it would close the add_header argument early and
# produce invalid nginx config, so fail fast here with a clear message instead
# of letting nginx die at boot with a cryptic parse error.
case "$CSP_VALUE" in
  *'"'*)
    echo "sng-ui: refusing to write CSP — connect-src override contains a double quote (would emit invalid nginx config). Check SNG_CSP_CONNECT_SRC / SNG_CSP_CONNECT_EXTRA." >&2
    exit 1
    ;;
esac

printf 'add_header Content-Security-Policy "%s" always;\n' "$CSP_VALUE" > "$CSP_PATH"

echo "sng-ui: wrote CSP to $CSP_PATH (connect-src $CONNECT_SRC)"
