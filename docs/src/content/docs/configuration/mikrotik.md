---
title: MikroTik Configuration
description: RouterOS API connection, TLS, timeouts, and connection pool settings.
---

Settings for the RouterOS API connection.

## Connection

### `mikrotik.address`

| | |
|---|---|
| **Env** | `MIKROTIK_HOST` |
| **Default** | `192.168.0.1:8728` |
| **Required** | Yes |

RouterOS API address in `host:port` format.

- Port `8728` — plaintext API
- Port `8729` — TLS-encrypted API

```yaml
mikrotik:
  address: "192.168.0.1:8728"
```

### `mikrotik.username`

| | |
|---|---|
| **Env** | `MIKROTIK_USER` |
| **Default** | `crowdsec` |
| **Required** | Yes |

The RouterOS API username. Use a dedicated user with minimal permissions. See [Router Setup](/getting-started/router-setup/) for creating the user.

### `mikrotik.password`

| | |
|---|---|
| **Env** | `MIKROTIK_PASS` |
| **Default** | — |
| **Required** | Yes |

The RouterOS API password.

:::tip[Environment variables]
For sensitive values like passwords, use environment variables instead of the config file:
```bash
export MIKROTIK_PASS="your-secure-password"
```
:::

## TLS

### `mikrotik.tls`

| | |
|---|---|
| **Env** | `MIKROTIK_TLS` |
| **Default** | `false` |

Enable TLS for the RouterOS API connection. Requires the `api-ssl` service on the router (port 8729).

```yaml
mikrotik:
  address: "192.168.0.1:8729"
  tls: true
```

### `mikrotik.tls_insecure`

| | |
|---|---|
| **Env** | `MIKROTIK_TLS_INSECURE` |
| **Default** | `false` |

Skip TLS certificate verification. Required for self-signed certificates.

:::caution
If your router uses a self-signed certificate, you need to set `tls_insecure: true`. For production, consider using a CA-signed certificate.
:::

## Timeouts

### `mikrotik.connection_timeout`

| | |
|---|---|
| **Env** | `MIKROTIK_CONN_TIMEOUT` |
| **Default** | `10s` |

Maximum time to wait for the initial API connection. Uses Go duration format.

### `mikrotik.command_timeout`

| | |
|---|---|
| **Env** | `MIKROTIK_CMD_TIMEOUT` |
| **Default** | `30s` |

Maximum time to wait for a single API command to complete. Increase if you have a slow router or large address lists.

:::tip
If you see timeout errors during reconciliation with large IP lists (20,000+), increase `command_timeout` to `60s` or more. Note that with the script-based bulk add, individual API commands are small (100 IPs per script), so the default `30s` is sufficient for most setups.
:::

## Connection Pool

### `mikrotik.pool_size`

| | |
|---|---|
| **Env** | `MIKROTIK_POOL_SIZE` |
| **Default** | `4` |

Number of parallel RouterOS API connections used for bulk operations (adding, removing, and reconciling address-list entries). A higher value increases throughput during startup reconciliation and mass ban/unban events.

- **Valid range:** 1–20
- **Auto-capping:** On startup the bouncer queries the router's API service `max-sessions` limit and automatically reduces the effective pool size so it never exceeds `max-sessions − 2` (reserving connections for the main client and external tools such as WinBox).

```yaml
mikrotik:
  pool_size: 8  # Higher parallelism for faster bulk operations
```

### Checking the router limit

The RouterOS API service has a `max-sessions` setting that limits simultaneous connections. The factory default is **20**.

```routeros
# Check current limit
/ip/service/print where name=api

# Increase it (maximum supported value is 1000)
/ip/service/set api max-sessions=1000
```

:::tip[Performance tuning]
For small to medium deployments (≤ 5,000 IPs) the default `pool_size: 4` is optimal. For very large CAPI lists (20,000+ IPs) increasing to 6–8 can noticeably reduce reconciliation time. Always verify the router's `max-sessions` first:

```routeros
/ip/service/set api max-sessions=1000
```
:::

:::note
Each pool connection is a full RouterOS API session. On resource-constrained routers (e.g., hAP lite) keep `pool_size` low (1–2) to avoid memory pressure.
:::
