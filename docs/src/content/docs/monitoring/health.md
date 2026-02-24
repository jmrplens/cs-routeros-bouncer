---
title: Health Endpoint
description: HTTP health check endpoint for monitoring bouncer status.
---

The bouncer provides a health check endpoint when metrics are enabled.

## Endpoint

```
GET http://<listen_addr>:<listen_port>/health
```

Default: `http://localhost:2112/health`

## Response format

```json
{
  "status": "healthy",
  "version": "1.3.0",
  "crowdsec_connected": true,
  "routeros_connected": true,
  "active_decisions": 1483,
  "last_pull": "2024-01-15T14:30:00Z"
}
```

## HTTP status codes

| Code | Meaning |
|------|---------|
| `200` | All systems operational |
| `503` | One or more components unhealthy |

## Integration examples

### Docker healthcheck

```yaml
services:
  cs-routeros-bouncer:
    image: ghcr.io/jmrplens/cs-routeros-bouncer:latest
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:2112/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
```

### Kubernetes liveness probe

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 2112
  initialDelaySeconds: 15
  periodSeconds: 30
  timeoutSeconds: 10

readinessProbe:
  httpGet:
    path: /health
    port: 2112
  initialDelaySeconds: 5
  periodSeconds: 10
```

### Prometheus alerting

```yaml
groups:
  - name: cs-routeros-bouncer
    rules:
      - alert: BouncerUnhealthy
        expr: up{job="cs-routeros-bouncer"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "CrowdSec RouterOS bouncer is down"
```
