#!/bin/sh
# ShieldNet Gateway — anycast health gate.
#
# Health-gates the BGP announce so a PoP that is no longer ready stops
# attracting anycast traffic. Run as a sidecar next to the BIRD speaker
# (bird.conf.tftpl). It polls the edge readiness endpoint (/readyz on the
# health-bind port, default 9119) and enables/disables the `sng_announce`
# static protocol accordingly. When disabled, BIRD withdraws the anycast
# prefix and BGP reconverges onto the remaining PoPs.
#
# This is a reference; adapt to your process supervisor. Placeholders:
#   READYZ_URL  - edge readiness URL (default http://127.0.0.1:9119/readyz)
#   BIRDC       - birdc control socket client (default "birdc")
#   INTERVAL    - poll seconds (default 5)
set -eu

READYZ_URL="${READYZ_URL:-http://127.0.0.1:9119/readyz}"
BIRDC="${BIRDC:-birdc}"
INTERVAL="${INTERVAL:-5}"

announced=""
while true; do
  if curl -fsS --max-time 2 "$READYZ_URL" >/dev/null 2>&1; then
    if [ "$announced" != "yes" ]; then
      "$BIRDC" enable sng_announce
      announced="yes"
      echo "readyz ok: anycast announce ENABLED"
    fi
  else
    if [ "$announced" != "no" ]; then
      "$BIRDC" disable sng_announce
      announced="no"
      echo "readyz failing: anycast announce WITHDRAWN"
    fi
  fi
  sleep "$INTERVAL"
done
