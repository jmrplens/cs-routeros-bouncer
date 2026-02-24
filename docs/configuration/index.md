# Configuration Overview

cs-routeros-bouncer can be configured via **YAML file** and/or **environment variables**. Environment variables override values from the config file.

## Config file

The default config file location is `/etc/cs-routeros-bouncer/cs-routeros-bouncer.yaml`. Override with the `-c` flag:

```bash
cs-routeros-bouncer -c /path/to/config.yaml
```

A full annotated reference is included in the repository at [`config/cs-routeros-bouncer.yaml`](https://github.com/jmrplens/cs-routeros-bouncer/blob/main/config/cs-routeros-bouncer.yaml).

## Configuration sections

The configuration is divided into five sections:

| Section | Description |
|---------|-------------|
| [CrowdSec](crowdsec.md) | LAPI connection, polling, decision filtering |
| [MikroTik](mikrotik.md) | RouterOS API connection and timeouts |
| [Firewall](firewall.md) | IPv4/IPv6, filter/raw rules, output blocking, logging |
| [Logging & Metrics](logging-metrics.md) | Log level/format, Prometheus metrics |
| [Examples](examples.md) | Complete configuration examples for common scenarios |

## Quick reference

All options at a glance. See the dedicated pages for detailed descriptions.

### Basic parameters

The essential settings to get the bouncer running. Most deployments only need these.

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `crowdsec.api_url` | `CROWDSEC_URL` | `http://localhost:8080/` | CrowdSec LAPI URL |
| `crowdsec.api_key` | `CROWDSEC_BOUNCER_API_KEY` | *(required)* | Bouncer API key |
| `mikrotik.address` | `MIKROTIK_HOST` | `192.168.0.1:8728` | RouterOS API address (`host:port`) |
| `mikrotik.username` | `MIKROTIK_USER` | `crowdsec` | API username |
| `mikrotik.password` | `MIKROTIK_PASS` | *(required)* | API password |
| `firewall.ipv4.enabled` | `FIREWALL_IPV4_ENABLED` | `true` | Enable IPv4 blocking |
| `firewall.ipv6.enabled` | `FIREWALL_IPV6_ENABLED` | `true` | Enable IPv6 blocking |
| `firewall.filter.enabled` | `FIREWALL_FILTER_ENABLED` | `true` | Create filter firewall rules |
| `firewall.raw.enabled` | `FIREWALL_RAW_ENABLED` | `true` | Create raw/prerouting rules |
| `firewall.deny_action` | `FIREWALL_DENY_ACTION` | `drop` | Action: `drop` or `reject` |
| `logging.level` | `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |

### Advanced parameters

Fine-tuning options for decision filtering, TLS, performance, firewall customization, and observability. The defaults work well for most setups.

#### [CrowdSec](crowdsec.md) — polling, filtering & TLS

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `crowdsec.update_frequency` | `CROWDSEC_UPDATE_FREQUENCY` | `10s` | Poll interval |
| `crowdsec.lapi_metrics_interval` | `CROWDSEC_LAPI_METRICS_INTERVAL` | `15m` | Usage metrics reporting interval (`0` = disabled) |
| `crowdsec.origins` | `CROWDSEC_ORIGINS` | `[]` (all) | Filter by origin |
| `crowdsec.scopes` | `CROWDSEC_SCOPES` | `["ip","range"]` | Decision scopes |
| `crowdsec.supported_decisions_types` | `CROWDSEC_DECISIONS_TYPES` | `["ban"]` | Decision types (only `ban` is implemented) |
| `crowdsec.scenarios_containing` | `CROWDSEC_SCENARIOS_CONTAINING` | `[]` | Include only matching scenarios |
| `crowdsec.scenarios_not_containing` | `CROWDSEC_SCENARIOS_NOT_CONTAINING` | `[]` | Exclude matching scenarios |
| `crowdsec.retry_initial_connect` | `CROWDSEC_RETRY_INITIAL_CONNECT` | `true` | Retry on startup |
| `crowdsec.insecure_skip_verify` | `CROWDSEC_INSECURE_SKIP_VERIFY` | `false` | Skip TLS verify |
| `crowdsec.cert_path` | `CROWDSEC_CERT_PATH` | | Client cert path |
| `crowdsec.key_path` | `CROWDSEC_KEY_PATH` | | Client key path |
| `crowdsec.ca_cert_path` | `CROWDSEC_CA_CERT_PATH` | | CA cert path |

#### [MikroTik](mikrotik.md) — TLS & performance

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `mikrotik.tls` | `MIKROTIK_TLS` | `false` | Use TLS |
| `mikrotik.tls_insecure` | `MIKROTIK_TLS_INSECURE` | `false` | Skip TLS verify |
| `mikrotik.connection_timeout` | `MIKROTIK_CONN_TIMEOUT` | `10s` | Connect timeout |
| `mikrotik.command_timeout` | `MIKROTIK_CMD_TIMEOUT` | `30s` | Command timeout |
| `mikrotik.pool_size` | `MIKROTIK_POOL_SIZE` | `4` | Parallel API connections (1–20) |

#### [Firewall](firewall.md) — rules, interfaces & logging

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `firewall.ipv4.address_list` | `FIREWALL_IPV4_ADDRESS_LIST` | `crowdsec-banned` | IPv4 list name |
| `firewall.ipv6.address_list` | `FIREWALL_IPV6_ADDRESS_LIST` | `crowdsec6-banned` | IPv6 list name |
| `firewall.filter.chains` | `FIREWALL_FILTER_CHAINS` | `["input"]` | Filter chains |
| `firewall.raw.chains` | `FIREWALL_RAW_CHAINS` | `["prerouting"]` | Raw chains |
| `firewall.rule_placement` | `FIREWALL_RULE_PLACEMENT` | `top` | Placement: `top` or `bottom` |
| `firewall.comment_prefix` | `FIREWALL_COMMENT_PREFIX` | `crowdsec-bouncer` | Comment prefix |
| `firewall.log` | `FIREWALL_LOG` | `false` | Enable rule logging |
| `firewall.log_prefix` | `FIREWALL_LOG_PREFIX` | `crowdsec-bouncer` | Global log prefix |
| `firewall.reject_with` | `FIREWALL_REJECT_WITH` | | Reject type when `deny_action=reject` |
| `firewall.filter.log_prefix` | `FIREWALL_FILTER_LOG_PREFIX` | | Override log prefix for filter rules |
| `firewall.filter.connection_state` | `FIREWALL_FILTER_CONNECTION_STATE` | | Connection-state matcher for filter rules |
| `firewall.raw.log_prefix` | `FIREWALL_RAW_LOG_PREFIX` | | Override log prefix for raw rules |
| `firewall.block_input.interface` | `FIREWALL_INPUT_INTERFACE` | | Restrict input/raw rules to interface (empty = all) |
| `firewall.block_input.interface_list` | `FIREWALL_INPUT_INTERFACE_LIST` | | Restrict input/raw rules to interface list (empty = all) |
| `firewall.block_input.whitelist` | `FIREWALL_INPUT_WHITELIST` | | Address-list for input whitelist (accept before drop) |
| `firewall.block_output.enabled` | `FIREWALL_BLOCK_OUTPUT` | `false` | Block outbound |
| `firewall.block_output.interface` | `FIREWALL_OUTPUT_INTERFACE` | | WAN interface |
| `firewall.block_output.interface_list` | `FIREWALL_OUTPUT_INTERFACE_LIST` | | WAN interface list |
| `firewall.block_output.log_prefix` | `FIREWALL_OUTPUT_LOG_PREFIX` | | Override log prefix for output rules |
| `firewall.block_output.passthrough_v4` | `FIREWALL_OUTPUT_PASSTHROUGH_V4` | | IPv4 client to bypass output blocking |
| `firewall.block_output.passthrough_v4_list` | `FIREWALL_OUTPUT_PASSTHROUGH_V4_LIST` | | IPv4 list to bypass output blocking |
| `firewall.block_output.passthrough_v6` | `FIREWALL_OUTPUT_PASSTHROUGH_V6` | | IPv6 client to bypass output blocking |
| `firewall.block_output.passthrough_v6_list` | `FIREWALL_OUTPUT_PASSTHROUGH_V6_LIST` | | IPv6 list to bypass output blocking |

#### [Logging & Metrics](logging-metrics.md) — format, file output & Prometheus

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `logging.format` | `LOG_FORMAT` | `text` | Log format: `text` or `json` |
| `logging.file` | `LOG_FILE` | | Log file path (empty = stdout only) |
| `metrics.enabled` | `METRICS_ENABLED` | `false` | Enable Prometheus `/metrics` endpoint |
| `metrics.listen_addr` | `METRICS_ADDR` | `0.0.0.0` | Listen address |
| `metrics.listen_port` | `METRICS_PORT` | `2112` | Listen port |
| `metrics.routeros_poll_interval` | `METRICS_ROUTEROS_POLL_INTERVAL` | `30s` | RouterOS system metrics poll interval (0 to disable) |
