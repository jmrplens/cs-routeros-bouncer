# Logging & Metrics

Settings for bouncer logging and Prometheus metrics.

## Logging

### `logging.level`

| | |
|---|---|
| **Env** | `LOG_LEVEL` |
| **Default** | `info` |

Log verbosity level:

| Level | Description |
|-------|-------------|
| `debug` | Detailed information for debugging (noisy) |
| `info` | Normal operation messages |
| `warn` | Warning conditions |
| `error` | Error conditions only |

```yaml
logging:
  level: "debug"  # Useful for troubleshooting
```

### `logging.format`

| | |
|---|---|
| **Env** | `LOG_FORMAT` |
| **Default** | `text` |

Log output format:

- `text` — human-readable, colored output (best for console/journalctl)
- `json` — structured JSON (best for log aggregation systems)

### `logging.file`

| | |
|---|---|
| **Env** | `LOG_FILE` |
| **Default** | — (stdout) |

Path to a log file. When empty, logs are written to stdout only. When set, logs are written to both stdout and the specified file.

```yaml
logging:
  file: "/var/log/cs-routeros-bouncer.log"
```

## Prometheus Metrics

### `metrics.enabled`

| | |
|---|---|
| **Env** | `METRICS_ENABLED` |
| **Default** | `false` |

Enable the Prometheus metrics endpoint. When enabled, the bouncer exposes metrics at `/metrics` and a health check at `/health`.

### `metrics.listen_addr`

| | |
|---|---|
| **Env** | `METRICS_ADDR` |
| **Default** | `0.0.0.0` |

Listen address for the metrics HTTP server.

### `metrics.listen_port`

| | |
|---|---|
| **Env** | `METRICS_PORT` |
| **Default** | `2112` |

Listen port for the metrics HTTP server.

```yaml
metrics:
  enabled: true
  listen_addr: "0.0.0.0"
  listen_port: 2112
```

### Available metrics

See [Prometheus Metrics](../monitoring/prometheus.md) for the full list of exported metrics.

!!! warning "Security"
    The metrics endpoint should not be exposed to the internet. Use firewall rules or network segmentation to restrict access.
