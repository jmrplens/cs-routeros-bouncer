# Prometheus Metrics

cs-routeros-bouncer exports Prometheus metrics for monitoring its operation.

## Setup

Enable metrics in the configuration:

```yaml
metrics:
  enabled: true
  listen_addr: "0.0.0.0"
  listen_port: 2112
```

Or via environment variables:

```bash
METRICS_ENABLED=true
METRICS_PORT=2112
```

Metrics are available at `http://bouncer-host:2112/metrics`.

### Prometheus scrape config

Add a scrape target to your Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'cs-routeros-bouncer'
    static_configs:
      - targets: ['bouncer-host:2112']
```

## Available metrics

### `crowdsec_bouncer_info`

| | |
|---|---|
| **Type** | Gauge |
| **Labels** | `version`, `routeros_identity` |

Build information and RouterOS router identity. Always has value `1`.

### `crowdsec_bouncer_start_time_seconds`

| | |
|---|---|
| **Type** | Gauge |

Unix timestamp of when the bouncer started. Useful for calculating uptime.

### `crowdsec_bouncer_active_decisions`

| | |
|---|---|
| **Type** | Gauge |
| **Labels** | `protocol` (`ipv4`, `ipv6`) |

Number of currently active ban decisions, broken down by protocol.

### `crowdsec_bouncer_decisions_total`

| | |
|---|---|
| **Type** | Counter |
| **Labels** | `action` (`ban`, `unban`), `protocol` (`ipv4`, `ipv6`) |

Total number of decisions processed since startup.

### `crowdsec_bouncer_errors_total`

| | |
|---|---|
| **Type** | Counter |
| **Labels** | `type` (`api`, `routeros`, `reconcile`) |

Total number of errors by category:

- `api` — CrowdSec LAPI communication errors
- `routeros` — MikroTik API errors
- `reconcile` — Reconciliation errors

### `crowdsec_bouncer_operation_duration_seconds`

| | |
|---|---|
| **Type** | Histogram |
| **Labels** | `operation` (`add`, `remove`, `reconcile`) |
| **Buckets** | 1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s, 10s |

Latency of operations:

- `add` — time to add an IP to MikroTik address list (~1ms typical)
- `remove` — time to remove an IP from MikroTik address list
- `reconcile` — time for a full reconciliation

### `crowdsec_bouncer_routeros_connected`

| | |
|---|---|
| **Type** | Gauge |

RouterOS connection status: `1` = connected, `0` = disconnected.

### `crowdsec_bouncer_reconciliation_total`

| | |
|---|---|
| **Type** | Counter |

Total number of reconciliation events since startup.

## Example queries

### Active blocked IPs

```promql
crowdsec_bouncer_active_decisions
```

### Decision rate (per minute)

```promql
rate(crowdsec_bouncer_decisions_total[5m]) * 60
```

### Error rate

```promql
rate(crowdsec_bouncer_errors_total[5m]) * 60
```

### Operation latency (p95)

```promql
histogram_quantile(0.95, rate(crowdsec_bouncer_operation_duration_seconds_bucket[5m]))
```

### Uptime

```promql
time() - crowdsec_bouncer_start_time_seconds
```
