# MikroTik Configuration

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

The RouterOS API username. Use a dedicated user with minimal permissions. See [Router Setup](../getting-started/router-setup.md) for creating the user.

### `mikrotik.password`

| | |
|---|---|
| **Env** | `MIKROTIK_PASS` |
| **Default** | — |
| **Required** | Yes |

The RouterOS API password.

!!! tip "Environment variables"
    For sensitive values like passwords, use environment variables instead of the config file:
    ```bash
    export MIKROTIK_PASS="your-secure-password"
    ```

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

!!! warning
    If your router uses a self-signed certificate, you need to set `tls_insecure: true`. For production, consider using a CA-signed certificate.

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

!!! tip
    If you see timeout errors during reconciliation with large IP lists (20,000+), increase `command_timeout` to `60s` or more.
