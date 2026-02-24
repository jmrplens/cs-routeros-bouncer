---
title: Troubleshooting
description: Common problems and their solutions.
---

## Connection issues

### Cannot connect to MikroTik

:::danger[Error: dial tcp: connection refused]
The bouncer cannot reach the MikroTik API port.

**Solutions:**
1. Verify the API service is enabled on the router:
   ```routeros
   /ip/service/print where name=api
   ```
2. Check the port matches your configuration (default: 8728, TLS: 8729)
3. Verify firewall rules allow access from the bouncer's IP
4. If using Docker, ensure the container can reach the router network
:::

### Authentication failed

:::danger[Error: cannot log in]
Wrong username or password.

**Solutions:**
1. Verify the username and password in your configuration
2. Check the user exists and has correct group:
   ```routeros
   /user/print where name=crowdsec
   ```
3. Verify the user's group has required policies: `api`, `read`, `write`
4. Check if the user's allowed address list restricts access
:::

### TLS certificate errors

:::danger[Error: x509: certificate signed by unknown authority]
TLS verification failed.

**Solutions:**
1. If using self-signed certificates, import the CA:
   ```yaml
   crowdsec:
     ca_cert_path: "/path/to/ca.pem"
   ```
2. Verify the certificate is valid and not expired
3. Check the hostname matches the certificate's CN or SAN
:::

## CrowdSec LAPI issues

### Cannot connect to LAPI

:::danger[Error: connection to CrowdSec LAPI failed]
The bouncer cannot reach the CrowdSec Local API.

**Solutions:**
1. Verify the LAPI URL is correct:
   ```bash
   curl http://localhost:8080/v1/decisions
   ```
2. Check the bouncer API key is valid:
   ```bash
   cscli bouncers list
   ```
3. If CrowdSec runs in Docker, ensure network connectivity
:::

### No decisions received

:::caution[Bouncer starts but no IPs are banned]
The bouncer connects successfully but the address list stays empty.

**Possible causes:**
1. No active decisions in CrowdSec — check with:
   ```bash
   cscli decisions list
   ```
2. Origin filtering is too restrictive — check `crowdsec.origins` config
3. Scenario filtering excludes all scenarios — check `crowdsec.scenarios` config
4. CrowdSec engine is not detecting threats — check CrowdSec logs
:::

## Firewall rule issues

### Rules not created

:::caution[Address list has entries but no firewall rules]
IPs are added to the address list but no firewall rules exist.

**Solutions:**
1. Check filter and raw are enabled:
   ```yaml
   firewall:
     filter:
       enabled: true
     raw:
       enabled: true
   ```
2. Look for errors in bouncer logs:
   ```bash
   journalctl -u cs-routeros-bouncer -f
   ```
3. Verify the user has `write` policy for firewall operations
:::

### Rules in wrong position

:::note[Firewall rules appear at the bottom instead of top]
Rules may be placed after existing rules.

**Solutions:**
1. Verify `rule_placement: "top"` in configuration
2. Check if dynamic/built-in rules occupy position 0 (the bouncer skips these and places after)
3. Manually check rule positions:
   ```routeros
   /ip/firewall/filter print
   /ip/firewall/raw print
   ```
:::

## Performance issues

### High CPU usage on router during reconciliation

:::caution[Router CPU spikes during bouncer startup]
This is expected during initial reconciliation with large address lists.

**Performance numbers:**
| List size | Time | CPU peak |
|-----------|------|----------|
| ~1,500 IPs (local) | ~9 s | ~14% |
| ~25,000 IPs (full CAPI) | ~2 min 50 s | ~23% |

**To reduce impact:**
1. Use `origins` filtering to limit synced decisions:
   ```yaml
   crowdsec:
     origins: ["crowdsec", "cscli"]
   ```
2. Schedule bouncer restarts during low-traffic periods
3. The CPU impact is temporary and only during reconciliation
:::

### Slow LAPI polling

:::note[LAPI latency is high]
Check the `crowdsec_routeros_lapi_stream_latency_seconds` metric.

**Possible causes:**
1. Network latency between bouncer and LAPI
2. LAPI under heavy load
3. Large decision set being serialized
:::

## Logging and debugging

### Enable debug logging

```yaml
logging:
  level: "debug"
```

Or via environment variable:

```bash
LOG_LEVEL=debug cs-routeros-bouncer run -c config.yml
```

### Check bouncer health

```bash
curl http://localhost:2112/health
```

### View metrics

```bash
curl http://localhost:2112/metrics
```

### Check what's on the router

```routeros
# View address list entries
/ip/firewall/address-list print where list=crowdsec-banned

# Count entries
/ip/firewall/address-list print count-only where list=crowdsec-banned

# View firewall rules created by bouncer
/ip/firewall/filter print where comment~"crowdsec-bouncer"
/ip/firewall/raw print where comment~"crowdsec-bouncer"
```

## Docker-specific issues

### Container cannot reach router

:::caution[Connection timeout from Docker container]
Docker networking may prevent the container from reaching the router.

**Solutions:**
1. Use `network_mode: host` in Docker Compose:
   ```yaml
   services:
     cs-routeros-bouncer:
       network_mode: host
   ```
2. Or ensure the Docker network can route to the router's IP
3. Check Docker DNS resolution if using hostnames
:::

### Permission denied for config file

:::danger[Error: permission denied reading config]
The container user cannot read the mounted config file.

**Solutions:**
1. Check file permissions: `chmod 644 config.yml`
2. If using Docker secrets, ensure the secret is properly mounted
3. Use environment variables instead of a config file
:::
