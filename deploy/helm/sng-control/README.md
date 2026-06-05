# sng-control Helm chart

Deploys the ShieldNet Gateway control plane (`sng-control`) plus its
observability and scaling surfaces.

## What it renders

- **Deployment** (with an optional **PgBouncer** transaction-pooling
  sidecar), **Service**, optional **Ingress**.
- **ConfigMap** + **Secret** covering every `internal/config/config.go`
  environment variable.
- **HPA** and **PodDisruptionBudget**.
- **ServiceAccount** (IRSA-ready via annotations for the S3 cold archive).
- A `pre-install`/`pre-upgrade` **Job** that runs `sng-migrate up`
  (always against the primary, never through PgBouncer).
- Prometheus-Operator **ServiceMonitor** and **PrometheusRule** (the
  latter vendored from `deploy/prometheus/alerts/sng.rules.yml`).
- Grafana dashboard **ConfigMaps** (vendored from
  `deploy/grafana/dashboards/`) labelled for the Grafana sidecar.

## Optional bundled backends (subcharts)

PostgreSQL (Bitnami), NATS (nats-io), and the Altinity ClickHouse
operator are declared as **optional** dependencies, disabled by default.
Production should point the `config.*` knobs at managed/external services
(see `deploy/terraform/sng-infra`). For an all-in-one dev install:

```bash
helm dependency build deploy/helm/sng-control
helm install sng deploy/helm/sng-control \
  --set postgresql.enabled=true \
  --set nats.enabled=true
```

> The resolved subchart archives under `charts/` are git-ignored. Run
> `helm dependency build` once (it reads the pinned `Chart.lock`) before
> `helm template`/`helm install`/`helm lint`.

## Scaling knobs

Read replicas, PgBouncer, ClickHouse sharding, and NATS partitioning are
all surfaced in `values.yaml`. See [`docs/scaling.md`](../../../docs/scaling.md)
for the sizing model and [`docs/cost-model.md`](../../../docs/cost-model.md)
for cost projections.

## Validate locally

```bash
helm dependency build deploy/helm/sng-control
helm lint deploy/helm/sng-control
helm template rel deploy/helm/sng-control
```
