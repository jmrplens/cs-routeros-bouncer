---
title: Prometheus Metrics
description: Complete reference of all Prometheus metrics exported by the bouncer.
---

The bouncer exports Prometheus metrics when `metrics.enabled` is `true`. Metrics are available at `http://<listen_addr>:<listen_port>/metrics`.

## Bouncer Metrics

### `crowdsec_routeros_active_decisions`

| | |
|---|---|
| **Type** | Gauge |
| **Labels** | `origin`, `action`, `scope`, `ip_type` |
| **Description** | Number of currently active (banned) decisions |

This metric provides a real-time count of active decisions, broken down by their source, action, scope, and IP type:

| Label | Values | Description |
|-------|--------|-------------|
| `origin` | `crowdsec`, `cscli`, `CAPI`, `lists:*` | Source of the decision |
| `action` | `ban` | Action type (currently only `ban` is supported) |
| `scope` | `Ip`, `Range` | Whether it's a single IP or CIDR range |
| `ip_type` | `ipv4`, `ipv6` | Protocol version |

**Example PromQL queries:**

```txt
# Total active decisions
sum(crowdsec_routeros_active_decisions)

# Active decisions by origin
sum by (origin) (crowdsec_routeros_active_decisions)

# Only local decisions (non-CAPI)
sum(crowdsec_routeros_active_decisions{origin!="CAPI"})

# IPv6 decisions
sum(crowdsec_routeros_active_decisions{ip_type="ipv6"})
```

### `crowdsec_routeros_processed_total`

| | |
|---|---|
| **Type** | Counter |
| **Labels** | `action`, `origin`, `ip_type` |
| **Description** | Total number of decisions processed since startup |

Counts both bans (`action="ban"`) and unbans (`action="unban"`).

```txt
# Ban rate per minute by origin
rate(crowdsec_routeros_processed_total{action="ban"}[5m]) * 60

# Total unbans since startup
sum(crowdsec_routeros_processed_total{action="unban"})
```

### `crowdsec_routeros_lapi_calls_total`

| | |
|---|---|
| **Type** | Counter |
| **Labels** | `status` |
| **Description** | Total LAPI API calls |

Labels: `status="success"` or `status="error"`.

```txt
# LAPI error rate
rate(crowdsec_routeros_lapi_calls_total{status="error"}[5m])
```

### `crowdsec_routeros_routeros_calls_total`

| | |
|---|---|
| **Type** | Counter |
| **Labels** | `status` |
| **Description** | Total RouterOS API calls |

Labels: `status="success"` or `status="error"`.

```txt
# RouterOS error rate
rate(crowdsec_routeros_routeros_calls_total{status="error"}[5m])
```

### `crowdsec_routeros_stream_events_total`

| | |
|---|---|
| **Type** | Counter |
| **Labels** | `status` |
| **Description** | Total stream events received from LAPI |

Counts polling events (each containing 0+ decisions). Labels: `status="success"` or `status="error"`.

### `crowdsec_routeros_lapi_stream_latency_seconds`

| | |
|---|---|
| **Type** | Gauge |
| **Description** | Last recorded LAPI polling latency in seconds |

Time taken for the last LAPI poll request. Useful for detecting LAPI connectivity issues.

### `crowdsec_routeros_reconciliation_total`

| | |
|---|---|
| **Type** | Counter |
| **Labels** | `status` |
| **Description** | Total reconciliation runs |

Labels: `status="success"` or `status="error"`.

### `crowdsec_routeros_reconciliation_duration_seconds`

| | |
|---|---|
| **Type** | Gauge |
| **Description** | Duration of the last reconciliation run in seconds |

### `crowdsec_routeros_config_info`

| | |
|---|---|
| **Type** | Gauge (always 1) |
| **Labels** | All configuration parameters |
| **Description** | Exposes bouncer configuration as metric labels |

This info-style metric has value `1` and carries all configuration parameters as labels:

| Label | Example value |
|-------|---------------|
| `version` | `1.3.0` |
| `crowdsec_url` | `http://localhost:8080/` |
| `crowdsec_update_frequency` | `10s` |
| `crowdsec_include_scenarios_containing` | — |
| `crowdsec_exclude_scenarios_containing` | — |
| `crowdsec_only_include_decisions_from` | — |
| `crowdsec_origins` | `crowdsec,cscli` |
| `crowdsec_scenarios` | — |
| `mikrotik_host` | `192.168.88.1:8728` |
| `mikrotik_tls` | `false` |
| `mikrotik_pool_size` | `4` |
| `firewall_deny_action` | `drop` |
| `firewall_reject_with` | — |
| `firewall_rule_placement` | `top` |
| `firewall_filter_chains` | `input` |
| `firewall_raw_chains` | `prerouting` |
| `firewall_ipv4_enabled` | `true` |
| `firewall_ipv6_enabled` | `true` |
| `firewall_filter_enabled` | `true` |
| `firewall_raw_enabled` | `true` |
| `firewall_log` | `false` |
| `firewall_log_prefix` | `crowdsec-bouncer` |
| `firewall_comment_prefix` | `crowdsec-bouncer` |
| `firewall_block_output` | `false` |
| `firewall_input_interface` | — |
| `firewall_input_interface_list` | — |
| `firewall_input_whitelist` | — |
| `firewall_filter_connection_state` | — |
| `firewall_filter_log_prefix` | — |
| `firewall_raw_log_prefix` | — |
| `metrics_routeros_poll_interval` | `30s` |

```txt
# Check current configuration
crowdsec_routeros_config_info
```

## RouterOS System Metrics

When `metrics.routeros_poll_interval` is non-zero, the bouncer also collects MikroTik system metrics:

### `crowdsec_routeros_system_cpu_load`

| | |
|---|---|
| **Type** | Gauge |
| **Labels** | `core` |
| **Description** | CPU load percentage per core |

### `crowdsec_routeros_system_memory_total_bytes`

| | |
|---|---|
| **Type** | Gauge |
| **Description** | Total system memory in bytes |

### `crowdsec_routeros_system_memory_used_bytes`

| | |
|---|---|
| **Type** | Gauge |
| **Description** | Used system memory in bytes |

### `crowdsec_routeros_system_temperature_celsius`

| | |
|---|---|
| **Type** | Gauge |
| **Labels** | `component` |
| **Description** | System temperature in Celsius |

```txt
# Memory usage percentage
crowdsec_routeros_system_memory_used_bytes / crowdsec_routeros_system_memory_total_bytes * 100

# Average CPU load across all cores
avg(crowdsec_routeros_system_cpu_load)
```

## LAPI Metrics

The bouncer collects CrowdSec LAPI metrics via the `/metrics` endpoint. These are proxied as gauges:

### `crowdsec_routeros_lapi_*`

| Metric | Type | Description |
|--------|------|-------------|
| `crowdsec_routeros_lapi_active_decisions` | Gauge | Total active decisions in LAPI |
| `crowdsec_routeros_lapi_bouncers` | Gauge | Number of registered bouncers |
| `crowdsec_routeros_lapi_machines` | Gauge | Number of registered machines |
| `crowdsec_routeros_lapi_alerts_total` | Gauge | Total alerts in LAPI |
| `crowdsec_routeros_lapi_decisions_added_total` | Gauge | Decisions added counter from LAPI |
| `crowdsec_routeros_lapi_decisions_deleted_total` | Gauge | Decisions deleted counter from LAPI |

:::note
LAPI metrics require the CrowdSec LAPI to have its own Prometheus endpoint enabled and accessible.
:::
