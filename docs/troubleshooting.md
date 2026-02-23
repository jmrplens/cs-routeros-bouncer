# Troubleshooting

Common issues and their solutions.

## Connection issues

### Cannot connect to RouterOS API

!!! failure "Symptoms"
    ```
    error connecting to RouterOS: dial tcp 192.168.0.1:8728: connection refused
    ```

**Solutions:**

1. **Verify the API service is enabled** on the router:
    ```routeros
    /ip/service/print
    ```
    The `api` (or `api-ssl`) service should be enabled.

2. **Check the router firewall** — ensure port 8728 (or 8729 for TLS) is not blocked from the bouncer host.

3. **Verify credentials** — ensure the username and password are correct and the user has the `api` policy.

4. **For TLS connections**, ensure:
    - `mikrotik.tls: true` is set
    - The correct port (8729) is used
    - `mikrotik.tls_insecure: true` if using self-signed certificates

### Cannot connect to CrowdSec LAPI

!!! failure "Symptoms"
    ```
    error connecting to CrowdSec LAPI: connection refused
    ```

**Solutions:**

1. **Verify LAPI is running**: `sudo systemctl status crowdsec`
2. **Check the URL** — ensure `crowdsec.api_url` includes the trailing slash
3. **Check the API key** — regenerate if needed: `sudo cscli bouncers add cs-routeros-bouncer`
4. **Network access** — ensure the bouncer can reach the LAPI host and port

## Firewall rule issues

### Rules not at the top of the chain

!!! warning "Symptoms"
    Bouncer rules appear at a position other than 0.

**Explanation:** RouterOS dynamic/builtin rules (e.g., fasttrack counters) occupy the top positions and cannot be moved. The bouncer iterates through positions starting from 0 and places the rule at the first available position.

**Verification:**
```routeros
/ip/firewall/filter/print
```

If rules above the bouncer's rule are dynamic/builtin, the placement is expected and correct.

### Rules not being created

**Check:**

1. Is the bouncer running? `sudo systemctl status cs-routeros-bouncer`
2. Check logs: `sudo journalctl -u cs-routeros-bouncer -f`
3. Verify firewall configuration — ensure `filter.enabled` and/or `raw.enabled` are `true`
4. Check the health endpoint: `curl http://localhost:2112/health`

## Address list issues

### Address list not being populated

!!! warning "Symptoms"
    The address list exists but contains no entries.

**Solutions:**

1. **Check CrowdSec has active decisions:**
    ```bash
    sudo cscli decisions list
    ```

2. **Verify the API key** — check bouncer logs for authentication errors

3. **Enable debug logging:**
    ```yaml
    logging:
      level: debug
    ```

4. **Check origin filtering** — if using `crowdsec.origins`, ensure it includes the expected sources

### Duplicate IPs in address list

This should not happen with cs-routeros-bouncer. If you see duplicates:

1. They may be left over from a previous bouncer (e.g., nvtkaszpir-alt)
2. Clean up manually:
    ```routeros
    /ip/firewall/address-list/remove [find where list=crowdsec-banned]
    ```
3. Restart the bouncer to re-sync

## Performance issues

### High memory/CPU usage at startup

!!! info "Expected behavior"
    Large community blocklists (CAPI) can contain 20,000+ IPs. Initial reconciliation processes them all using script-based bulk add with a connection pool.

**Typical startup times** (benchmarked on RB5009UG+S+, ARM64, RouterOS 7.21.3):

| Scenario | IPs | Duration | Router CPU peak |
|----------|-----|----------|-----------------|
| Local decisions only | ~1,500 | ~9 s | 14% |
| Local + CAPI community | ~25,000 | ~2 min 50 s | 23% |
| Restart (IPs already present) | ~25,000 | ~10 s | 16% |

**Solutions:**

- Use `crowdsec.origins: ["crowdsec", "cscli"]` to sync only local decisions (~1,500 IPs, ~9 s startup)
- Startup is a one-time cost; runtime processing is ~1–3 ms per IP
- Increase `mikrotik.command_timeout` if you see timeout errors

### Slow reconciliation

If reconciliation takes longer than expected:

1. Reduce the number of decisions by using origin filtering
2. Increase `mikrotik.command_timeout` to avoid timeouts
3. Check router CPU — ensure the router is not overloaded by other services
4. Verify the RouterOS API connection is direct (not through NAT or VPN)

## Logging

### Enable debug logging

```yaml
logging:
  level: "debug"
  format: "text"
```

Or via environment variable:

```bash
LOG_LEVEL=debug
```

### View logs

```bash
# Systemd service
sudo journalctl -u cs-routeros-bouncer -f

# Docker
docker logs -f cs-routeros-bouncer
```

### JSON logging for log aggregation

```yaml
logging:
  format: "json"
```

Output format:

```json
{"level":"info","time":"2025-01-15T10:30:00Z","message":"ban IPv4","ip":"1.2.3.4","duration":"4h0m0s"}
```
