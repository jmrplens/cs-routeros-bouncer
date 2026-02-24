# Health Endpoint

The bouncer provides a health check endpoint for monitoring and container orchestration.

## Endpoint

```
GET /health
```

Available when metrics are enabled (`metrics.enabled: true`) at the configured address and port.

```bash
curl http://localhost:2112/health
```

## Response

```json
{
  "status": "ok",
  "routeros_connected": true,
  "version": "vX.Y.Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"ok"` when the bouncer is operational |
| `routeros_connected` | boolean | `true` if connected to MikroTik API |
| `version` | string | Bouncer version |

## HTTP status codes

| Code | Meaning |
|------|---------|
| `200` | Healthy — bouncer is running and connected |
| `503` | Unhealthy — RouterOS connection lost |

## Use cases

### Docker health check

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
```

### External monitoring

```bash
# Simple availability check
curl -sf http://bouncer-host:2112/health > /dev/null && echo "OK" || echo "FAIL"

# Check RouterOS connection
curl -s http://bouncer-host:2112/health | jq -r '.routeros_connected'
```
