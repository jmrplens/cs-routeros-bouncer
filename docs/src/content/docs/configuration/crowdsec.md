---
title: CrowdSec Configuration
description: LAPI connection, polling interval, and decision filtering settings.
---

Settings for the CrowdSec LAPI connection and decision filtering.

## Connection

### `crowdsec.api_url`

| | |
|---|---|
| **Env** | `CROWDSEC_URL` |
| **Default** | `http://localhost:8080/` |
| **Required** | Yes |

The URL of the CrowdSec Local API (LAPI). Include the trailing slash.

```yaml
crowdsec:
  api_url: "http://localhost:8080/"
```

### `crowdsec.api_key`

| | |
|---|---|
| **Env** | `CROWDSEC_BOUNCER_API_KEY` |
| **Default** | — |
| **Required** | Yes |

The bouncer API key. Generate one with:

```bash
sudo cscli bouncers add cs-routeros-bouncer
```

### `crowdsec.retry_initial_connect`

| | |
|---|---|
| **Env** | `CROWDSEC_RETRY_INITIAL_CONNECT` |
| **Default** | `true` |

When enabled, the bouncer retries connecting to LAPI on startup if the initial connection fails. Useful when the bouncer starts before CrowdSec is ready.

## Polling

### `crowdsec.update_frequency`

| | |
|---|---|
| **Env** | `CROWDSEC_UPDATE_FREQUENCY` |
| **Default** | `10s` |

How often to poll LAPI for new or expired decisions. Uses Go duration format (e.g., `10s`, `1m`, `30s`).

:::tip
Lower values provide faster response but increase LAPI load. `10s` is a good balance for most setups.
:::

### `crowdsec.lapi_metrics_interval`

| | |
|---|---|
| **Env** | `CROWDSEC_LAPI_METRICS_INTERVAL` |
| **Default** | `15m` |

How often to report usage metrics to the CrowdSec LAPI `/v1/usage-metrics` endpoint. Set to `0` to disable.

Each push includes:

- **Active decisions** — per-origin (e.g., `crowdsec`, `cscli`, `CAPI`) and per-IP-type (`ipv4`, `ipv6`)
- **Dropped traffic** — bytes and packets blocked by MikroTik firewall rules (delta since last push)
- **Bouncer metadata** — type, version, OS info, uptime

This data appears in the CrowdSec Console and helps track bouncer effectiveness.

```yaml
crowdsec:
  lapi_metrics_interval: "15m"
```

## Decision Filtering

### `crowdsec.origins`

| | |
|---|---|
| **Env** | `CROWDSEC_ORIGINS` |
| **Default** | `[]` (all origins) |

Filter decisions by their origin. Empty means all decisions are processed.

Common origins:

| Origin | Description |
|--------|-------------|
| `crowdsec` | Decisions from CrowdSec detection engine |
| `cscli` | Manual decisions via `cscli decisions add` |
| `CAPI` | Community blocklists from CrowdSec Central API |

```yaml
# Only local decisions (no community blocklists)
crowdsec:
  origins: ["crowdsec", "cscli"]
```

:::note[Local-only mode]
Setting `origins: ["crowdsec", "cscli"]` is the recommended way to exclude community blocklists (CAPI). This avoids pushing 20,000+ IPs to the router.
:::

### `crowdsec.scopes`

| | |
|---|---|
| **Env** | `CROWDSEC_SCOPES` |
| **Default** | `["ip", "range"]` |

Decision scopes to process. Supported values: `ip`, `range`.

### `crowdsec.supported_decisions_types`

| | |
|---|---|
| **Env** | `CROWDSEC_DECISIONS_TYPES` |
| **Default** | `["ban"]` |

Only decisions of these types are processed.

:::caution
This bouncer only implements the **`ban`** action, which translates to drop/reject firewall
rules on MikroTik. Other CrowdSec decision types such as `captcha` or `throttle` are not
applicable to a network firewall bouncer and will be silently ignored even if listed here.
:::

### `crowdsec.scenarios_containing`

| | |
|---|---|
| **Env** | `CROWDSEC_SCENARIOS_CONTAINING` |
| **Default** | `[]` (no filter) |

Only process decisions from scenarios whose name contains one of these strings. Empty means no filtering.

```yaml
crowdsec:
  scenarios_containing: ["ssh", "http"]
```

### `crowdsec.scenarios_not_containing`

| | |
|---|---|
| **Env** | `CROWDSEC_SCENARIOS_NOT_CONTAINING` |
| **Default** | `[]` (no filter) |

Exclude decisions from scenarios whose name contains one of these strings.

## TLS Authentication

For mutual TLS authentication with the LAPI:

### `crowdsec.cert_path`

| | |
|---|---|
| **Env** | `CROWDSEC_CERT_PATH` |
| **Default** | — |

Path to the TLS client certificate (PEM format).

### `crowdsec.key_path`

| | |
|---|---|
| **Env** | `CROWDSEC_KEY_PATH` |
| **Default** | — |

Path to the TLS client key (PEM format).

### `crowdsec.ca_cert_path`

| | |
|---|---|
| **Env** | `CROWDSEC_CA_CERT_PATH` |
| **Default** | — |

Path to the CA certificate (PEM format) for verifying the LAPI server certificate.

### `crowdsec.insecure_skip_verify`

| | |
|---|---|
| **Env** | `CROWDSEC_INSECURE_SKIP_VERIFY` |
| **Default** | `false` |

Skip TLS certificate verification for LAPI connections.

:::danger
Only use in development/testing. Never in production.
:::
