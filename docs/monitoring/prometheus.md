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

### `crowdsec_bouncer_active_decisions_by_origin`

| | |
|---|---|
| **Type** | Gauge |
| **Labels** | `origin` (`crowdsec`, `cscli`, `CAPI`) |

Number of currently active ban decisions, broken down by CrowdSec origin.

### `crowdsec_bouncer_decisions_total`

| | |
|---|---|
| **Type** | Counter |
| **Labels** | `action` (`ban`, `unban`), `proto` (`ipv4`, `ipv6`), `origin` (`crowdsec`, `cscli`, `CAPI`) |

Total number of decisions processed since startup.

### `crowdsec_bouncer_errors_total`

| | |
|---|---|
| **Type** | Counter |
| **Labels** | `operation` (`api`, `routeros`, `reconcile`, `add`, `find`) |

Total number of errors by category:

- `api` — CrowdSec LAPI communication errors
- `routeros` — MikroTik API errors
- `reconcile` — Reconciliation errors
- `add` — Address add/update errors
- `find` — Address lookup errors

### `crowdsec_bouncer_operation_duration_seconds`

| | |
|---|---|
| **Type** | Histogram |
| **Labels** | `operation` (`add`, `remove`, `reconcile`) |
| **Buckets** | 1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s, 10s |

Latency of operations:

- `add` — time to add an IP to MikroTik address list (~1–3 ms typical)
- `remove` — time to remove an IP from MikroTik address list
- `reconcile` — time for a full reconciliation

### `crowdsec_bouncer_routeros_connected`

| | |
|---|---|
| **Type** | Gauge |

RouterOS connection status: `1` = connected, `0` = disconnected.

### `crowdsec_bouncer_routeros_cpu_load`

| | |
|---|---|
| **Type** | Gauge |

RouterOS CPU load percentage (0–100). Polled from `/system/resource/print`.

### `crowdsec_bouncer_routeros_memory_used_bytes`

| | |
|---|---|
| **Type** | Gauge |

RouterOS used memory in bytes (total − free). Polled from `/system/resource/print`.

### `crowdsec_bouncer_routeros_memory_total_bytes`

| | |
|---|---|
| **Type** | Gauge |

RouterOS total memory in bytes. Polled from `/system/resource/print`.

### `crowdsec_bouncer_routeros_cpu_temperature_celsius`

| | |
|---|---|
| **Type** | Gauge |

RouterOS CPU temperature in degrees Celsius. Polled from `/system/health/print`. Not updated if the device does not have a temperature sensor.

### `crowdsec_bouncer_reconciliation_total`

| | |
|---|---|
| **Type** | Counter |
| **Labels** | `action` (`added`, `removed`) |

Total number of reconciliation actions performed since startup.

### `crowdsec_bouncer_dropped_bytes_total`

| | |
|---|---|
| **Type** | Gauge |

Cumulative bytes dropped by firewall rules managed by the bouncer. Read from MikroTik firewall counters across all 4 paths (filter+raw × IPv4+IPv6).

### `crowdsec_bouncer_dropped_packets_total`

| | |
|---|---|
| **Type** | Gauge |

Cumulative packets dropped by firewall rules managed by the bouncer. Read from MikroTik firewall counters across all 4 paths (filter+raw × IPv4+IPv6).

### `crowdsec_bouncer_config_info`

| | |
|---|---|
| **Type** | Gauge (info pattern, value always 1) |
| **Labels** | `group`, `param`, `value` |
| **Series** | 31 (one per configuration parameter) |

Exposes the current bouncer configuration as one time series per parameter. Each series carries three labels: `group` (category), `param` (human-readable name), and `value` (current setting). Sensitive fields (API key, password, TLS cert paths) are excluded.

**Groups and parameters (31 total):**

| Group | Parameters |
|-------|-----------|
| `CrowdSec` | API URL, Update Frequency, Origins, Scopes, Decision Types, TLS Enabled, Retry Initial Connect |
| `MikroTik` | Address, TLS Enabled, Connection Pool Size, Connection Timeout, Command Timeout |
| `Firewall` | IPv4 Enabled, IPv4 Address List, IPv6 Enabled, IPv6 Address List, Filter Enabled, Filter Chains, Raw Enabled, Raw Chains, Deny Action, Block Output, Rule Placement, Comment Prefix, Logging Enabled |
| `Logging` | Level, Format |
| `Metrics` | Enabled, Listen Address, Listen Port, RouterOS Poll Interval |

**Example output:**

```
crowdsec_bouncer_config_info{group="CrowdSec",param="API URL",value="http://localhost:8080/"} 1
crowdsec_bouncer_config_info{group="Firewall",param="Deny Action",value="drop"} 1
crowdsec_bouncer_config_info{group="MikroTik",param="Connection Pool Size",value="10"} 1
```

## CrowdSec LAPI Metrics

In addition to Prometheus metrics, the bouncer reports usage metrics directly to the CrowdSec LAPI at a configurable interval (`crowdsec.lapi_metrics_interval`, default `15m`). These are **not** Prometheus metrics — they are sent to the CrowdSec LAPI `/v1/usage-metrics` endpoint and appear in the CrowdSec Console.

### What is reported

| Metric | Unit | Labels | Description |
|--------|------|--------|-------------|
| `active_decisions` | `ip` | `origin` | Active decisions by origin (`crowdsec`, `cscli`, `CAPI`) |
| `active_decisions` | `ip` | `ip_type` | Active decisions by protocol (`ipv4`, `ipv6`) |
| `dropped` | `byte` | — | Bytes blocked by firewall rules (delta since last push) |
| `dropped` | `packet` | — | Packets blocked by firewall rules (delta since last push) |

### Bouncer metadata

Each push also includes bouncer metadata:

| Field | Example |
|-------|---------|
| Type | `cs-routeros-bouncer` |
| Version | `vX.Y.Z` |
| OS | `linux` |
| Startup timestamp | UTC epoch |
| Feature flags | `[]` (expected empty for bouncers) |

### Dropped traffic counters

The bouncer reads byte and packet counters from MikroTik firewall rules (the rules it manages) just before each LAPI push. It computes deltas between pushes and reports them as `dropped` metrics. This provides CrowdSec with visibility into how much traffic is actually being blocked.

### Configuration

```yaml
crowdsec:
  lapi_metrics_interval: "15m"  # Set to "0" to disable
```

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
