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

All options at a glance, grouped by section. See the dedicated pages for detailed descriptions.

### [CrowdSec](crowdsec.md)

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `crowdsec.api_url` | `CROWDSEC_URL` | `http://localhost:8080/` | CrowdSec LAPI URL |
| `crowdsec.api_key` | `CROWDSEC_BOUNCER_API_KEY` | *(required)* | Bouncer API key |
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

### [MikroTik](mikrotik.md)

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `mikrotik.address` | `MIKROTIK_HOST` | `192.168.0.1:8728` | API address (`host:port`) |
| `mikrotik.username` | `MIKROTIK_USER` | `crowdsec` | API username |
| `mikrotik.password` | `MIKROTIK_PASS` | *(required)* | API password |
| `mikrotik.tls` | `MIKROTIK_TLS` | `false` | Use TLS |
| `mikrotik.tls_insecure` | `MIKROTIK_TLS_INSECURE` | `false` | Skip TLS verify |
| `mikrotik.connection_timeout` | `MIKROTIK_CONN_TIMEOUT` | `10s` | Connect timeout |
| `mikrotik.command_timeout` | `MIKROTIK_CMD_TIMEOUT` | `30s` | Command timeout |

### [Firewall](firewall.md)

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `firewall.ipv4.enabled` | `FIREWALL_IPV4_ENABLED` | `true` | Enable IPv4 |
| `firewall.ipv4.address_list` | `FIREWALL_IPV4_ADDRESS_LIST` | `crowdsec-banned` | IPv4 list name |
| `firewall.ipv6.enabled` | `FIREWALL_IPV6_ENABLED` | `true` | Enable IPv6 |
| `firewall.ipv6.address_list` | `FIREWALL_IPV6_ADDRESS_LIST` | `crowdsec6-banned` | IPv6 list name |
| `firewall.filter.enabled` | `FIREWALL_FILTER_ENABLED` | `true` | Filter rules |
| `firewall.filter.chains` | `FIREWALL_FILTER_CHAINS` | `["input"]` | Filter chains |
| `firewall.raw.enabled` | `FIREWALL_RAW_ENABLED` | `true` | Raw rules |
| `firewall.raw.chains` | `FIREWALL_RAW_CHAINS` | `["prerouting"]` | Raw chains |
| `firewall.deny_action` | `FIREWALL_DENY_ACTION` | `drop` | Action: `drop` or `reject` |
| `firewall.rule_placement` | `FIREWALL_RULE_PLACEMENT` | `top` | Placement: `top` or `bottom` |
| `firewall.comment_prefix` | `FIREWALL_COMMENT_PREFIX` | `crowdsec-bouncer` | Comment prefix |
| `firewall.log` | `FIREWALL_LOG` | `false` | Enable rule logging |
| `firewall.log_prefix` | `FIREWALL_LOG_PREFIX` | `crowdsec-bouncer` | Log prefix |
| `firewall.block_output.enabled` | `FIREWALL_BLOCK_OUTPUT` | `false` | Block outbound |
| `firewall.block_output.interface` | `FIREWALL_OUTPUT_INTERFACE` | | WAN interface |
| `firewall.block_output.interface_list` | `FIREWALL_OUTPUT_INTERFACE_LIST` | | WAN interface list |

### [Logging](logging-metrics.md#logging)

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `logging.level` | `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `logging.format` | `LOG_FORMAT` | `text` | Log format: `text` or `json` |
| `logging.file` | `LOG_FILE` | | Log file path (empty = stdout only) |

### [Metrics](logging-metrics.md#prometheus-metrics)

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `metrics.enabled` | `METRICS_ENABLED` | `false` | Enable Prometheus `/metrics` endpoint |
| `metrics.listen_addr` | `METRICS_ADDR` | `0.0.0.0` | Listen address |
| `metrics.listen_port` | `METRICS_PORT` | `2112` | Listen port |
