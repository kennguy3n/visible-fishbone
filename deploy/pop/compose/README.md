# Local multi-PoP simulation

Runnable two-PoP topology on a single host: two edge stand-ins in
different region-groups (SEA, DACH) behind a front-door, so the
cross-region **failover** behaviour is observable without DNS, BGP, or
the proprietary edge image.

```
client ──▶ frontdoor (127.0.0.1:18080) ──▶ pop-sea-edge   (primary)
                                        └▶ pop-dach-edge  (backup)
```

> The `pop-*-edge` services are tiny nginx stand-ins that serve only the
> edge's `/healthz` and `/readyz` endpoints — enough to demonstrate the
> front-door's failover, not the real data plane. In production you swap
> in `ghcr.io/kennguy3n/sng-edge` and the front-door is GeoDNS/anycast
> (see [`../frontdoor`](../frontdoor)). The proxy here is OSS nginx, which
> has passive health checks only, so failover is shown via `max_fails` +
> a `backup` upstream rather than active probing.

## Validate (no daemon)

```bash
docker compose -f docker-compose.pop.yml config -q && echo OK
```

## Run and watch failover

```bash
docker compose -f docker-compose.pop.yml up -d

curl -s localhost:18080/            # -> PoP sea (region-group SEA)

# Take the primary PoP down; the front-door fails traffic over.
docker compose -f docker-compose.pop.yml exec pop-sea-edge nginx -s stop
curl -s localhost:18080/            # -> PoP dach (region-group DACH)

docker compose -f docker-compose.pop.yml down
```
